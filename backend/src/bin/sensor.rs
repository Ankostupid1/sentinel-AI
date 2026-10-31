use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Error};

use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const PORT_THRESHOLD: usize = 10;
const TIME_WINDOW: Duration = Duration::from_secs(10);
const ALERT_COOLDOWN: Duration = Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

const API_URL: &str = "http://127.0.0.1:3000/api/v1/alerts";
const HEARTBEAT_URL: &str = "http://127.0.0.1:3000/api/v1/sensor/heartbeat";

#[derive(Serialize)]
struct NewAlert {
    event_type: String,
    source_ip: String,
    destination_ip: String,
    distinct_ports: usize,
    time_window_seconds: u64,
    severity: String,
}

#[derive(Serialize)]
struct SensorHeartbeat {
    interface: String,
    packets_captured: u64,
    alerts_generated: u64,
}

fn send_alert(runtime: &tokio::runtime::Runtime, client: &reqwest::Client, alert: &NewAlert) {
    let result = runtime.block_on(async { client.post(API_URL).json(alert).send().await });

    match result {
        Ok(response) => {
            let status = response.status();

            if status.is_success() {
                println!("[API] Alert successfully delivered: {}", status);
            } else {
                let body = runtime.block_on(response.text()).unwrap_or_default();

                eprintln!("[API] Server rejected alert: {} - {}", status, body);
            }
        }
        Err(error) => {
            eprintln!("[API] Failed to send alert: {}", error);
        }
    }
}

fn send_heartbeat(
    runtime: &tokio::runtime::Runtime,
    client: &reqwest::Client,
    interface: &str,
    packets_captured: u64,
    alerts_generated: u64,
) {
    let heartbeat = SensorHeartbeat {
        interface: interface.to_string(),
        packets_captured,
        alerts_generated,
    };

    let result =
        runtime.block_on(async { client.post(HEARTBEAT_URL).json(&heartbeat).send().await });

    match result {
        Ok(response) if response.status().is_success() => {
            println!(
                "[HEARTBEAT] Sensor online | Interface: {} | Packets: {} | Alerts: {}",
                interface, packets_captured, alerts_generated
            );
        }
        Ok(response) => {
            eprintln!("[HEARTBEAT] API returned an error: {}", response.status());
        }
        Err(error) => {
            eprintln!("[HEARTBEAT] Could not contact API: {}", error);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let interface = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "wlan0".to_string());

    println!("========================================");
    println!("       SENTINELAI NETWORK SENSOR");
    println!("========================================");
    println!("Interface: {}", interface);
    println!("Detection: {} ports / 10 seconds", PORT_THRESHOLD);
    println!("API: {}", API_URL);
    println!("Heartbeat interval: 5 seconds");
    println!("Starting packet capture...\n");

    let runtime = tokio::runtime::Runtime::new()?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let mut capture = Capture::from_device(interface.as_str())?
        .promisc(false)
        .snaplen(65535)
        .timeout(1000)
        .open()?;

    let mut traffic: HashMap<(Ipv4Addr, Ipv4Addr), VecDeque<(Instant, u16)>> = HashMap::new();

    let mut last_alert: HashMap<(Ipv4Addr, Ipv4Addr), Instant> = HashMap::new();

    let mut packets_captured: u64 = 0;
    let mut alerts_generated: u64 = 0;
    let mut last_heartbeat = Instant::now();

    // Send initial heartbeat immediately
    send_heartbeat(
        &runtime,
        &client,
        &interface,
        packets_captured,
        alerts_generated,
    );

    loop {
        // Send heartbeat every five seconds
        if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
            send_heartbeat(
                &runtime,
                &client,
                &interface,
                packets_captured,
                alerts_generated,
            );

            last_heartbeat = Instant::now();
        }

        match capture.next_packet() {
            Ok(packet) => {
                packets_captured += 1;

                let parsed = match SlicedPacket::from_ethernet(&packet.data) {
                    Ok(parsed) => parsed,
                    Err(_) => continue,
                };

                let ip = match parsed.net {
                    Some(NetSlice::Ipv4(ip)) => ip,
                    _ => continue,
                };

                let source_ip = Ipv4Addr::from(ip.header().source());
                let destination_ip = Ipv4Addr::from(ip.header().destination());

                let tcp = match parsed.transport {
                    Some(TransportSlice::Tcp(tcp)) => tcp,
                    _ => continue,
                };

                // Only count TCP SYN initiation packets
                if !tcp.syn() || tcp.ack() {
                    continue;
                }

                let destination_port = tcp.destination_port();
                let key = (source_ip, destination_ip);
                let now = Instant::now();

                let distinct_ports = {
                    let events = traffic.entry(key).or_default();

                    events.retain(|(timestamp, _)| now.duration_since(*timestamp) <= TIME_WINDOW);

                    events.push_back((now, destination_port));

                    events
                        .iter()
                        .map(|(_, port)| *port)
                        .collect::<HashSet<u16>>()
                        .len()
                };

                println!(
                    "[TCP SYN] {} -> {}:{} | Distinct ports: {}",
                    source_ip, destination_ip, destination_port, distinct_ports
                );

                if distinct_ports >= PORT_THRESHOLD {
                    let cooling_down = last_alert
                        .get(&key)
                        .map(|last| last.elapsed() < ALERT_COOLDOWN)
                        .unwrap_or(false);

                    if !cooling_down {
                        println!("\n");
                        println!("========================================");
                        println!("       POTENTIAL PORT SCAN");
                        println!("========================================");
                        println!("Source IP:      {}", source_ip);
                        println!("Destination IP: {}", destination_ip);
                        println!("Distinct ports: {}", distinct_ports);
                        println!("Time window:    10 seconds");
                        println!("Severity:       Medium");
                        println!("Assessment:     Potential reconnaissance");
                        println!("========================================\n");

                        let alert = NewAlert {
                            event_type: "potential_port_scan".to_string(),
                            source_ip: source_ip.to_string(),
                            destination_ip: destination_ip.to_string(),
                            distinct_ports,
                            time_window_seconds: 10,
                            severity: "Medium".to_string(),
                        };

                        last_alert.insert(key, Instant::now());
                        alerts_generated += 1;

                        send_alert(&runtime, &client, &alert);
                    }
                }
            }

            Err(Error::TimeoutExpired) => {
                // Normal capture timeout; the next loop checks heartbeat.
            }

            Err(error) => {
                eprintln!("[SENSOR] Capture error: {}", error);
                break;
            }
        }
    }

    Ok(())
}
