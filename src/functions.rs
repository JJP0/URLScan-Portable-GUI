use std::fs::{OpenOptions, File};
use std::io::{self, Write, BufRead, BufReader, Read};
use std::collections::HashMap;
use reqwest;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use mini_redis::{client, Result};
use serde_json::{json, Value};
use serde::{Serialize, Deserialize};
use reqwest::StatusCode;
use std::any::type_name;

/*
Need to refactor:
1. Create func to get headers as they are standard throughout, repeated code
2. Create single func for getting api key/uuid
3. Create single func for saving api key/uuid to file
4. Refactor whole chunks of code, repeated and not optimal
5. Test edge cases
6. Implement more error handling (particularly for invalid URLs and for when 'Fetch results' is clicked before any data has loaded)


*/


/* 				Structs used for search results, JSON			*/
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub data: Data,
    pub lists: Lists,
    pub verdicts: Verdicts,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Data {
    pub requests: Vec<Value>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lists {
    pub ips: Vec<String>,
    pub countries: Vec<String>,
    pub urls: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    #[serde(rename = "IPv6Percentage")]
    pub malicious: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdicts {
    pub overall: Overall,
    pub community: Community,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Overall {
    pub score: i64,
    pub malicious: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Community {
    pub score: i64,
    pub votes_total: i64,
    pub votes_malicious: i64,
    pub votes_benign: i64,
    pub malicious: bool,
    pub has_verdicts: bool,
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/






/* 	 Structs used to handle search API response		*/
#[derive(Debug, Deserialize)]
struct SuccessResponse {
    uuid: String,
    api: String,
    visibility: String,
    url: String,
    result: String,
    options: serde_json::Value,
    country: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    message: String,
    description: String,
    status: u16,
    errors: Vec<ErrorDetail>,
}

#[derive(Debug, Deserialize)]
struct ErrorDetail {
    title: String,
    detail: String,
    status: u16,
}

#[derive(Debug, Deserialize)]
enum ApiResponse {
    Success(SuccessResponse),
    Error(ErrorResponse),
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/





/* Struct used to handle custom JSON result */
#[derive(Debug, Deserialize, Default)]
pub struct ResultsData {
    pub community_malicious: bool,
    pub community_score: i64,
    pub countries: Vec<String>,
    pub ips: Vec<String>,
    pub overall_malicious: bool,
    pub overall_score: i64,
    pub urls: Vec<String>,
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/



/*        Used to write api key, uuid to respective file           */
pub fn write_to_file(data: &str, file_path: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)?;

    file.write_all(data.as_bytes())?;

    Ok(())
}

/*     Used to read api key, uuid from respective file    */
pub fn read_from_file(file_name: &str) -> io::Result<String> {
    let file_path = match File::open(file_name) {
        Ok(file) => file,
        Err(e) => {
            File::create(file_name).expect("Failed to create file");
            eprintln!("Error opening file: {}", e);
            return Ok(String::new());
        }
    };

    let reader = BufReader::new(file_path);
    if let Some(Ok(line)) = reader.lines().next() {
        Ok(line)
    } else {
        Ok(String::new())
    }
}


/*  Func to submit url to URLScan API and retrieve the UUID created */
#[tokio::main]
pub async fn scan_url(url: String, api_key: String) -> Result<()> {

	// Create maps for reqwest data, headers
	//let mut data = HashMap::new();
	let mut headers = HeaderMap::new();

	// Custom header required for URLScan api
	let CUSTOM_HEADER: &'static str = "api-key";

	// Add headers to map
	headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
	headers.insert(HeaderName::from_static(CUSTOM_HEADER), HeaderValue::from_str(&api_key).expect("FAILURE HERE"));

	// Add data to map
	//data.insert("url", url.to_string());
	//data.insert("visibility", "public".to_string());

	// Create data in JSON format
	let json_data = &serde_json::json!({
		"url": url,
		"visibility": "public"
	});
	
	// Create reqwest client with headers and data
	let client = reqwest::Client::new();
	let res = client.post("https://urlscan.io/api/v1/scan/")
		.headers(headers)
		.json(json_data)
		.send()
		.await?;

	// Retrieve the status result for error checking, body for parsing
	let status = res.status();
    let body = res.text().await?;

    // If 200...
    if status.is_success() {
        
        let json_result: SuccessResponse = serde_json::from_str(&body).expect("Failed to deserialize response");
        // Get uuid as required for gathering the results
        let uuid = json_result.uuid;
        // Write uuid to file
        match write_to_file(&uuid, "uuid.txt") {
            Ok(()) => println!("UUID ({}) Successfully added to file", uuid),
            Err(_) => println!("Error occurred writing UUID"),
        }
    } else {
        println!("Received non-success status code: {}", status);
        let error_response: ErrorResponse = serde_json::from_str(&body).expect("Failed to deserialize error response");
        println!("{:#?}", error_response);
    }
 
	Ok(())
}

/*      Func to get results of previous URLScan api search, parse results      */
#[tokio::main]
pub async fn fetch_results() -> std::result::Result<(), Box<dyn std::error::Error>> {

	// Read api key, uuid {api key may not be needed}
	let api_key = read_from_file("key.txt").expect("Failed to get API Key");
	let uuid = read_from_file("uuid.txt").expect("Failed to get UUID");

	let mut headers = HeaderMap::new();

	let CUSTOM_HEADER: &'static str = "api-key";

	headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
	headers.insert(HeaderName::from_static(CUSTOM_HEADER), HeaderValue::from_str(&api_key).expect("FAILURE HERE"));


	let url = format!("https://urlscan.io/api/v1/result/{}/", uuid);

	let client = reqwest::Client::new();
	let res = client.get(url)
		.headers(headers)
		.send()
		.await?;

	let status = res.status();
	let body = res.text().await?;

	// If 200, parse json and turn into custom json data
	if status.is_success() {
	        let response: Root = serde_json::from_str(&body)?;
	
			let ips = &response.lists.ips;
			let countries = &response.lists.countries;
			let urls = &response.lists.urls;
			let overall_score = response.verdicts.overall.score;
			let overall_malicious = response.verdicts.overall.malicious;
			let community_score = response.verdicts.community.score;
			let community_malicious = response.verdicts.community.malicious;

			let json_data = json!({
		        "ips": ips,
		        "urls": urls,
		        "countries": countries,
		        "overall_score": overall_score,
		        "overall_malicious": overall_malicious,
		        "community_score": community_score,
		        "community_malicious": community_malicious,
		    });

		    // Write results to results.json file
		    write_result_data(&json_data)?;

	    } else {
	        println!("Received non-success status code: {}", status);
	        return Err(format!("HTTP request failed with status code {}: {}", status, body).into());
	    }
	Ok(())
}

/*       Write results to results.json file       */
fn write_result_data(data: &Value) -> io::Result<()> {

	let file_path = "results.json";

    let mut file = File::create(file_path)?;

    // Serialize the JSON data and write it to the file
    let serialized_data = serde_json::to_string_pretty(data)?;
    file.write_all(serialized_data.as_bytes())?;

    println!("Data written to {}", file_path);

	Ok(())
}


/*   Initial func to load json data, could be refactored   */
pub fn load_data() -> ResultsData {

	// Call func to read data from file 
    let json_data = read_json_file("results.json").unwrap_or(String::new());//.expect("Failed to read JSON file");

    // Turn string from result into JSON for parsing
    serde_json::from_str(&json_data).unwrap_or_default()
}


fn read_json_file(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut json_data = String::new();
    file.read_to_string(&mut json_data)?;
    Ok(json_data)
}

/* Func to remove results.json text, for GUI purposes */
pub fn remove_all_text_from_json_file() -> io::Result<()> {
    // Open the file with write access, truncating its contents
    let mut file = OpenOptions::new().write(true).truncate(true).open("results.json")?;

    // Truncate the file, removing all text
    file.set_len(0)?;

    Ok(())
}
