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

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub data: Data,
    pub lists: Lists,
    //pub meta: Meta,
    //pub page: Page,
    //pub scanner: Scanner,
    //pub stats: Stats,
    //pub submitter: Submitter,
    //pub task: Task,
    pub verdicts: Verdicts,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Data {
    pub requests: Vec<Value>,
    pub cookies: Vec<Value>,
    pub console: Vec<Value>,
    pub links: Vec<Value>,
    pub timing: Timing,
    pub globals: Vec<Value>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Timing {
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lists {
    pub ips: Vec<String>,
    pub countries: Vec<String>,
    pub asns: Vec<Value>,
    pub domains: Vec<Value>,
    pub servers: Vec<Value>,
    pub urls: Vec<String>,
    pub link_domains: Vec<Value>,
    pub certificates: Vec<Value>,
    pub hashes: Vec<Value>,
}


#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    #[serde(rename = "IPv6Percentage")]
    pub ipv6percentage: i64,
    pub ad_blocked: i64,
    pub domain_stats: Vec<Value>,
    pub ip_stats: Vec<Value>,
    pub malicious: i64,
    pub protocol_stats: Vec<Value>,
    pub reg_domain_stats: Vec<Value>,
    pub resource_stats: Vec<Value>,
    pub secure_percentage: i64,
    pub secure_requests: i64,
    pub server_stats: Vec<Value>,
    pub tls_stats: Vec<Value>,
    pub total_links: i64,
    pub uniq_countries: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdicts {
    pub overall: Overall,
    pub urlscan: Urlscan,
    pub engines: Engines,
    pub community: Community,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Overall {
    pub score: i64,
    pub categories: Vec<Value>,
    pub brands: Vec<Value>,
    pub tags: Vec<Value>,
    pub malicious: bool,
    pub has_verdicts: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Urlscan {
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Engines {
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Community {
    pub score: i64,
    pub categories: Vec<Value>,
    pub brands: Vec<Value>,
    pub votes_total: i64,
    pub votes_malicious: i64,
    pub votes_benign: i64,
    pub malicious: bool,
    pub has_verdicts: bool,
}


// Custom struct for JSON produced from API search
// #[derive(Debug, Deserialize)]
// struct SearchResponse {
// 	api: String,
// 	//country: String,
// 	//message: String,
// 	//options: String,
// 	//result: String,
// 	//url: String,
// 	uuid: String,
// 	//visibility: String,
// }




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

pub fn save_api_key(api_key: &String) -> io::Result<()> {

	let file_path = "key.txt";

	let mut file = OpenOptions::new()
		.write(true)
		.create(true)
		.truncate(true)
		.open(file_path)?;

	file.write_all(api_key.as_bytes())?;

	Ok(())
}

pub fn get_api_key() -> io::Result<String> {

	let file_path = match File::open("key.txt") {
		Ok(file) => file,
		Err(e) => {
			File::create("key.txt").expect("Failed to create key file");
;			eprintln!("Error opening file: {}", e);
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




fn write_uuid_to_file(uuid: &String) -> io::Result<()> {
	
	let file_path = "uuid.txt";

		let mut file = OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(true)
			.open(file_path)?;

		file.write_all(uuid.as_bytes())?;

		Ok(())
}


pub fn get_uuid() -> io::Result<String> {
	let file_path = match File::open("uuid.txt") {
		Ok(file) => file,
		Err(e) => {
			File::create("uuid.txt").expect("Failed to create uuid file");
			eprintln!("Error opening file: {}", e);
			return Ok(String::new());
		}
	};

	//let

	let reader = BufReader::new(file_path);

	if let Some(Ok(line)) = reader.lines().next() {
		Ok(line)
	} else {
		Ok(String::new())
	}
}


#[tokio::main]
pub async fn scan_url(url: String, api_key: String) -> Result<()> {

	let mut data = HashMap::new();
	let mut headers = HeaderMap::new();

	let CUSTOM_HEADER: &'static str = "api-key";

	headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
	headers.insert(HeaderName::from_static(CUSTOM_HEADER), HeaderValue::from_str(&api_key).expect("FAILURE HERE"));

	let temp = api_key.to_string();

	data.insert("url", url.to_string());
	data.insert("visibility", "public".to_string());

	let json_data = &serde_json::json!({
		"url": url,
		"visibility": "public"
	});
	
	let client = reqwest::Client::new();
	let res = client.post("https://urlscan.io/api/v1/scan/")
		.headers(headers)
		.json(json_data)
		.send()
		.await?;


	let status = res.status();
    let body = res.text().await?;

    println!("{}", status);

    if status.is_success() {
        let json_result: SuccessResponse = serde_json::from_str(&body).expect("Failed to deserialize response");
        println!("{:#?}", json_result);
        let uuid = json_result.uuid;
        match write_uuid_to_file(&uuid) {
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


#[tokio::main]
pub async fn fetch_results() -> std::result::Result<(), Box<dyn std::error::Error>> {

	let api_key = get_api_key().expect("Failed to get API Key");
	let uuid = get_uuid().expect("Failed to get UUID");

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
		// .text()
		// .await?;

	let status = res.status();
	let body = res.text().await?;

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

		    write_result_data(&json_data)?;

		    // write_result_data(&json_data)?;

	    } else {
	        println!("Received non-success status code: {}", status);
	        return Err(format!("HTTP request failed with status code {}: {}", status, body).into());
	        //let error_response: ErrorResponse = serde_json::from_str(&body).expect("Failed to deserialize error response");
	       // println!("{:#?}", error_response);
	    }

	Ok(())
}

fn write_result_data(data: &Value) -> io::Result<()> {
	let file_path = "results.json";

    let mut file = File::create(file_path)?;

    // Serialize the JSON data and write it to the file
    let serialized_data = serde_json::to_string_pretty(data)?;
    file.write_all(serialized_data.as_bytes())?;

    println!("Data written to {}", file_path);

	Ok(())
}


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


pub fn load_data() -> ResultsData {

    let json_data = read_json_file("results.json").unwrap_or(String::new());//.expect("Failed to read JSON file");
    serde_json::from_str(&json_data).unwrap_or_default()
}


fn read_json_file(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut json_data = String::new();
    file.read_to_string(&mut json_data)?;
    Ok(json_data)
}

pub fn remove_all_text_from_json_file() -> io::Result<()> {
    // Open the file with write access, truncating its contents
    let mut file = OpenOptions::new().write(true).truncate(true).open("results.json")?;

    // Truncate the file, removing all text
    file.set_len(0)?;

    Ok(())
}
/*

fetch reuslts when not yet finished - "{\n  \"message\": \"Scan is not finished yet\",\n  \"status\": 404,\n  \"errors\": [\n    {\n      \"title\": \"Scan is not finished yet\",\n      \"detail\": \"Scan is not finished yet\",\n      \"status\": 404\n    }\n  ]\n}"


*/