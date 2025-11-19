use std::{net::{IpAddr, SocketAddr}, time::Duration};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

pub struct Config {
    pub timeout: Duration,
    pub batch_size: usize,
    pub join_scan: bool,
    pub rescan_mode: bool,
    pub rescan_every: Option<Duration>,
    pub full_scan_every: Option<Duration>,
    pub masscan: bool,
}

pub struct ServerInfo {
    pub ip: IpAddr,
    pub port: i32,
    pub version_name: String,
    pub protocol: i32,
    pub players_max: i32,
    pub players_online: i32,
    pub player_sample: Option<Vec<Player>>,
    pub motd: Option<String>,
    pub favicon: Option<String>,
    pub timestamp: i64
}

pub struct Player {
    pub name: String,
    pub uuid: String,
    pub timestamp: i64,
}

pub struct ServerJoinInfo {
    pub cracked: Option<bool>,
    pub whitelist: Option<bool>,
    pub forge: Option<bool>
}

pub fn form_handshake(intent: u8, protocol: i32, addr: SocketAddr) -> Vec<u8> {
    let ip = addr.ip().to_string();
    let port = addr.port();

    [
        &[0x00],
        write_varint(protocol).as_slice(),
        write_varint(ip.len().try_into().unwrap()).as_slice(),
        ip.as_bytes(),
        &port.to_be_bytes(),
        &[intent]
    ].concat()
}

pub fn prefix_len(bytes: &[u8]) -> Vec<u8> {
    [
        &write_varint(bytes.len().try_into().unwrap()),
        bytes
    ].concat()
}

pub fn write_varint(num: i32) -> Vec<u8> {
    let mut num = num as u32;
    let mut output = Vec::new();

    loop {
        if num & !0x7F == 0 {
            output.push(num as u8);
            return output
        }

        output.push((num as u8) | 0x80);
        num >>= 7;
    }
}

pub async fn read_varint<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Option<i32> {
    let mut output: u32 = 0;
    let mut position = 0;

    loop {
        let mut byte = [0; 1];
        reader.read_exact(&mut byte).await.ok()?;
        let byte = byte[0];

        output |= (byte as u32 & 0x7F) << position;

        if byte & 0x80 == 0 {
            break
        }

        position += 7;

        if position >= 32 {
            return None
        }
    }
    
    Some(output as i32)
}

pub fn parse_motd(component: &Value) -> Option<String> {
    match component {
        Value::Object(obj) => {
            let mut output = String::new();

            if let Some(text) = obj.get("text")
                && let Some(str) = parse_motd(text) {
                    output.push_str(&str);
                }

            if let Some(extra) = obj.get("extra")
                && let Some(extra) = parse_motd(extra) {
                    output.push_str(&extra);
                }

            if !output.is_empty() {
                return Some(output)
            }

            None
        },
        Value::Array(arr) => {
            let mut output = String::new();
            for value in arr {
                if let Some(str) = parse_motd(value) {
                    output.push_str(&str);
                }
            }

            if !output.is_empty() {
                return Some(output)
            }

            None
        }
        Value::String(str) => {
            let mut output = String::new();

            let mut ignore_next = false;
            for char in str.chars() {
                if char == '§' {
                    ignore_next = true;
                } else if ignore_next {
                    ignore_next = false;
                } else {
                    output.push(char);
                }
            }

            if !output.is_empty() {
                return Some(output)
            }

            None
        },
        _ => None,
    }
}