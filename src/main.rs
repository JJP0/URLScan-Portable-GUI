#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use eframe::egui;
use eframe::egui::{menu, Color32, widgets::Separator, widgets::Spinner};
use reqwest;
use serde_json::{json, Value};
use serde::{Serialize, Deserialize};

mod functions; 
use functions::ResultsData;

/*
Need to refactor:
1. Create func to get headers as they are standard throughout, repeated code
2. Create single func for getting api key/uuid
3. Create single func for saving api key/uuid to file
4. Refactor whole chunks of code, repeated and not optimal
5. Test edge cases
6. Implement more error handling (particularly for invalid URLs and for when 'Fetch results' is clicked before any data has loaded)


*/


#[derive(Debug, Deserialize)]
struct SearchResponse {
    api: String,
    country: String,
    message: String,
    //options: String,
    result: String,
    url: String,
    uuid: String,
    visibility: String,
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        min_window_size: Some(egui::vec2(520.0, 600.0)),
        initial_window_size: Some(egui::vec2(520.0, 600.0)),
        ..Default::default()
    };
    eframe::run_native(
        "Portable URLScan GUI",
        options,
        Box::new(|_cc| Box::new(MyApp::default())),
    )
}


struct MyApp {

    remaining_public_scans: i8,
    remaining_private_scans: i8,
    settings_open: bool,
    api_key: String,
    url_to_scan: String,
    url_search_uuid: String,
    results: ResultsData,
    current_url_name: String,

}

impl Default for MyApp {
    fn default() -> Self {

        Self {

            remaining_public_scans: 0,
            remaining_private_scans: 0,

            api_key: functions::read_from_file("key.txt").expect(""),

            settings_open: false,
            url_to_scan: "".to_string(),
            url_search_uuid: "".to_string(),
            results: ResultsData {
                community_malicious: Default::default(),
                community_score: Default::default(),
                countries: Default::default(),
                ips: Default::default(),
                overall_malicious: Default::default(),
                overall_score: Default::default(),
                urls: Default::default(),
            },
            current_url_name: "".to_string(),
        }
    }
}

impl eframe::App for MyApp {
    
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {

            
            menu::bar(ui, |ui| {
                ui.menu_button("Settings", |ui| {
                    if ui.button("API Key").clicked() {
                        self.settings_open = true;
                    }
                });
            });

            if self.settings_open {
                egui::Window::new("API Key").show(&ctx, |ui: &mut egui::Ui| {
                    // Add content to the window here
                    ui.horizontal(|ui| {
                        ui.label("API Key");
                        ui.text_edit_singleline(&mut self.api_key);
                    });

                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                           // functions::create_json_file(self.api_key.to_string(), self.web_chat_path.to_string());
                            println!("Saving API Key - {}", self.api_key.to_string());
                            functions::write_to_file(&self.api_key, "key.txt").expect("Failed to save API key");
                            println!("UUID = {}", self.url_search_uuid);
                        }
                        if ui.button("Close").clicked() {
                            self.settings_open = false;
                        }
                    });
                    
                });
            }

            ui.separator();

            ui.vertical_centered(|ui| {
                ui.heading("Portable URLScan GUI");
            });

            ui.separator();
            ui.add_space(5.0);

            // Check for API Key
            if self.api_key == "" {
                if functions::read_from_file("key.txt").expect("").is_empty() {
                    ui.add_space(5.0);
                    ui.colored_label(egui::Color32::RED, "API KEY MISSING - ADD API KEY TO SETTINGS");
                    ui.separator();
                } else {
                    self.api_key = functions::read_from_file("key.txt").expect("Weird Failure")
                }
                
            }

            ui.horizontal(|ui| {
                ui.label("URL to scan:");
                ui.text_edit_singleline(&mut self.url_to_scan);
                if ui.button("Scan URL").clicked() {

                    if self.results.ips != Vec::<String>::default() {
                        self.results = ResultsData {
                            community_malicious: Default::default(),
                            community_score: Default::default(),
                            countries: Default::default(),
                            ips: Default::default(),
                            overall_malicious: Default::default(),
                            overall_score: Default::default(),
                            urls: Default::default(),
                        };
                    }
                    functions::remove_all_text_from_json_file();

                    let blank = &self.url_to_scan;
                    self.current_url_name = blank.to_string();
                    // self.current_url_name = &self.url_to_scan;
                    println!("WOOOO");
                    println!("{} {}", self.url_to_scan.to_string(), self.api_key.to_string());
                    self.url_search_uuid = String::new();

                    functions::scan_url(self.url_to_scan.to_string(), self.api_key.to_string());//.expect("Failed to scan url"); 

                    self.url_search_uuid = functions::read_from_file("uuid.txt").expect("Couldn't retrieve UUID");


                    }
            });

            if !self.url_search_uuid.is_empty() {
                ui.add_space(10.0);
                ui.colored_label(egui::Color32::GREEN, "URL search created, please wait roughly 15secs before gathering results.");
                ui.colored_label(egui::Color32::LIGHT_YELLOW, format!("UUID = {}", self.url_search_uuid));
                ui.colored_label(egui::Color32::LIGHT_YELLOW, format!("Current URL = {}", self.current_url_name));

                ui.add_space(10.0);
                ui.vertical_centered(|ui| {
                    if ui.button("Fetch results").clicked() {

                        match functions::fetch_results() {
                            Ok(()) => {
                                println!("Fetched results successfully");
                                //functions::fetch_results();
                            }
                            Err(err) => {
                                println!("Failed to fetch results: {}", err);
                                ui.label("Tried to access results too soon. Hang on.");
                            }
                        }
                        


                        self.results = functions::load_data();

                        println!("{:?}", self.results.ips);

                    }
                });
                
            }
            ui.add_space(20.0);

            if self.results.ips != Vec::<String>::default() {
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::GREEN, "IPs: ");
                    ui.vertical_centered(|ui| {
                        // ui.text_edit_multiline(&mut self.results.ips.join("\n "));
                        egui::ScrollArea::vertical().id_source("ips_scroll_area").show(ui, |ui| {
                        ui.add(egui::TextEdit::multiline(&mut self.results.ips.join("\n")).desired_rows(5));
                    });
                        });
                    
                });
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::GREEN, "URLs: ");
                   // ui.add(egui::TextEdit::multiline(&mut self.results.urls.join("\n\n")).desired_rows(5);
                    ui.vertical_centered(|ui| {
                        egui::ScrollArea::vertical().id_source("urls_scroll_area").show(ui, |ui| {
                        ui.add(egui::TextEdit::multiline(&mut self.results.urls.join("\n\n")).desired_rows(5));
                    });
                    });
                    
                });
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::GREEN, "Countries: ");
                    ui.vertical_centered(|ui| {
                        // ui.text_edit_multiline(&mut self.results.countries.join("\n "));
                        egui::ScrollArea::vertical().id_source("countries_scroll_area").show(ui, |ui| {
                        ui.add(egui::TextEdit::multiline(&mut self.results.countries.join("\n")).desired_rows(5));
                    });
                        });
                    
                });
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::GREEN, "Overall score: ");
                    ui.colored_label(egui::Color32::RED, self.results.overall_score.to_string());
                });
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::GREEN, "Overall malicious? ");
                    ui.colored_label(egui::Color32::RED, self.results.overall_malicious.to_string());
                });
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::GREEN, "Community score: ");
                    ui.colored_label(egui::Color32::RED, self.results.community_score.to_string());
                });
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::GREEN, "Community malicious?: ");
                    ui.colored_label(egui::Color32::RED, self.results.community_malicious.to_string());
                });
            }
        });
    }
}