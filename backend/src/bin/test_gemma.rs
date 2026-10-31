#[path = "../services/mod.rs"]
mod services;

use serde_json::json;
use services::gemma::GemmaClient;

#[tokio::main]
async fn main() {
    let gemma = match GemmaClient::from_env() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("Configuration error: {}", error);
            return;
        }
    };

    let alert = json!({
        "event_type": "potential_port_scan",
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.1",
        "distinct_ports": 15,
        "time_window_seconds": 10,
        "severity": "Medium"
    });

    println!("Sending alert to Gemma for analysis...\n");

    match gemma.analyze_alert(&alert).await {
        Ok(assessment) => {
            println!("========== SENTINELAI AI ASSESSMENT ==========");
            println!("{}", serde_json::to_string_pretty(&assessment).unwrap());
            println!("==============================================");
        }
        Err(error) => {
            eprintln!("Gemma analysis failed: {}", error);
        }
    }
}
