use std::process::Command;
use std::{env, io};
use std::sync::{Arc};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex};
use tokio::sync::{mpsc};
use tokio::net::{TcpSocket};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::{timeout};
use tokio::fs::File;
use tokio_postgres::NoTls;
use serde_json::Value;
use std::io::Write;
use futures::future::join_all;

const BATCH_SIZE: usize = 2000;
const TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-m" | "--masscan" => {
                println!("scanning for open ports with masscan");
                Command::new("masscan")
                    .args(["-c", "masscan/masscan.conf"])
                    .status().expect("failed to run masscan");
            },
            _ => ()
        }
    }

    let masscan_output = File::open("masscan/masscan-output.txt").await.expect("file masscan-output.txt was not found, run with --masscan first");
    let mut line_iter = BufReader::new(masscan_output).lines();

    let mut server_count = 0;
    let mut servers: Vec<SocketAddr> = Vec::new();

    while let Some(line) = line_iter.next_line().await.unwrap() {
        if line.starts_with('#') {
            continue
        }

        let mut split = line.split(' ');
        split.next();
        split.next();

        let port: u16 = split.next().expect("wrongly formatted file").parse().expect("wrongly formatted file");
        let ip: &str = split.next().expect("wrongly formatted file");

        let addr = SocketAddr::new(ip.parse().expect("failed to parse into ipv4 address"), port);

        servers.push(addr);
        server_count += 1;
    }

    println!("scanning {server_count} servers");
    
    let (tx, mut rx) = mpsc::channel(5000);
    let scanned = Arc::new(Mutex::new(0));
    let scanned_clone = scanned.clone();

    tokio::spawn(async move {
        let mut futures: Vec<_> = Vec::new();
    
        for addr in servers {
            let tx = tx.clone();
            let scanned_clone = scanned_clone.clone();

            let future = async move {
                let server_info = timeout(TIMEOUT, ping_server(addr)).await;
                if let Ok(Some(server_info)) = server_info {
                    tx.send(server_info).await.unwrap();
                }
                *scanned_clone.lock().await += 1;
            };

            futures.push(future);

            if futures.len() >= BATCH_SIZE {
                join_all(futures).await;
                futures = Vec::new();
            }
        }
    });

    let (client, connection) = tokio_postgres::connect("host=localhost user=postgres dbname=scanner", NoTls).await.unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {e}");
        }
    });

    let insert_server = client.prepare(r"
        INSERT INTO servers (ip, port, version_name, protocol, players_max, players_online, motd, favicon, first_seen, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (ip, port)
        DO UPDATE SET
            version_name = EXCLUDED.version_name,
            protocol = EXCLUDED.protocol,
            players_max = EXCLUDED.players_max,
            players_online = EXCLUDED.players_online,
            motd = EXCLUDED.motd,
            favicon = EXCLUDED.favicon,
            last_seen = EXCLUDED.last_seen
    ").await.unwrap();

    let insert_player = client.prepare(r"
        INSERT INTO players (ip, port, name, uuid, first_seen, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (ip, port, name)
        DO UPDATE SET
            last_seen = EXCLUDED.last_seen
    ").await.unwrap();
    
    let mut resp_count = 0;
    let mut stdout_lock = io::stdout().lock();

    while let Some(server) = rx.recv().await {
        resp_count += 1;
        client.execute(&insert_server, &[&server.ip, &server.port, &server.version_name, &server.protocol, &server.players_max, &server.players_online, &server.motd, &server.favicon, &server.timestamp, &server.timestamp]).await.unwrap();

        if let Some(sample) = server.player_sample {
            for player in sample {
                client.execute(&insert_player, &[&server.ip, &server.port, &player.name, &player.uuid, &player.timestamp, &player.timestamp]).await.unwrap();
            }
        }

        let scanned_lock = scanned.lock().await;

        if resp_count % 10 == 0 {
            writeln!(stdout_lock, "{}/{} scanned, {} servers have responded", *scanned_lock, server_count, resp_count).unwrap();
        }
    }

    println!("done, {resp_count}/{server_count} servers responded");
}

#[derive(Debug)]
struct ServerInfo {
    ip: IpAddr,
    port: i32,
    version_name: String,
    protocol: i32,
    players_max: i32,
    players_online: i32,
    player_sample: Option<Vec<Player>>,
    motd: String,
    favicon: Option<String>,
    timestamp: i64
}

#[derive(Debug)]
struct Player {
    name: String,
    uuid: String,
    timestamp: i64,
}

async fn ping_server(addr: SocketAddr) -> Option<ServerInfo> {
    let socket = TcpSocket::new_v4().ok()?;
    let mut stream = socket.connect(addr).await.ok()?;
    
    let ip = addr.ip().to_string();
    let port = addr.port();

    let handshake: Vec<u8> = [
        &[0x00],
        write_varint(47).as_slice(),
        write_varint(ip.len().try_into().ok()?).as_slice(),
        ip.as_bytes(),
        &port.to_be_bytes(),
        &[0x01]
    ].concat();

    stream.write_all(&[write_varint(handshake.len().try_into().ok()?), handshake].concat()).await.ok()?;
    stream.write_all(&[0x01, 0x00]).await.ok()?;

    let mut reader = BufReader::new(stream);
    read_varint(&mut reader).await?;

    let packet_id = read_varint(&mut reader).await?;

    if packet_id != 0x00 {
        return None
    }
    let json_len = read_varint(&mut reader).await?;

    if json_len > 8192 {
        return None
    }

    let mut json_buf = vec![0u8; json_len as usize];
    reader.read_exact(&mut json_buf).await.ok()?;
    
    let json: Value = serde_json::from_slice(&json_buf).ok()?;
    let timestamp: i64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis().try_into().unwrap();

    Some(ServerInfo {
        ip: addr.ip(),
        port: port.into(),
        version_name: match &json["version"]["name"] {
            Value::String(str) => str.to_string(),
            _ => return None
        },
        protocol: match &json["version"]["protocol"] {
            Value::Number(num) => num.as_i64()?.try_into().ok()?,
            _ => return None
        },
        players_max: match &json["players"]["max"] {
            Value::Number(num) => num.as_i64()?.try_into().ok()?,
            _ => return None
        },
        players_online: match &json["players"]["online"] {
            Value::Number(num) => num.as_i64()?.try_into().ok()?,
            _ => return None
        },
        player_sample: match &json["players"]["sample"] {
            Value::Array(arr) => {
                let mut sample: Vec<Player> = Vec::new();

                for player in arr {
                    sample.push(Player {
                        name: match &player["name"] {
                            Value::String(str) => str.to_string(),
                            _ => continue
                        },
                        uuid: match &player["id"] {
                            Value::String(str) => str.to_string(),
                            _ => continue
                        },
                        timestamp
                    });
                }

                Some(sample)
            },
            _ => None
        },
        motd: parse_motd(&json["description"])?,
        favicon: match &json["favicon"] {
            Value::String(str) => Some(str.to_string()),
            _ => None,
        },
        timestamp
    })
}

fn write_varint(num: i32) -> Vec<u8> {
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

async fn read_varint<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Option<i32> {
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

fn parse_motd(component: &Value) -> Option<String> {
    match component {
        Value::Object(obj) => {
            let mut string = String::new();

            if let Some(text) = obj.get("text") {
                if let Some(str) = parse_motd(text) {
                    string.push_str(&str);
                }
            }

            if let Some(extra) = obj.get("extra") {
                if let Some(extra) = parse_motd(extra) {
                    string.push_str(&extra);
                }
            }

            if !string.is_empty() {
                return Some(string)
            }
            None
        },
        Value::Array(arr) => {
            let mut string = String::new();
            for value in arr {
                if let Some(str) = parse_motd(value) {
                    string.push_str(&str);
                }
            }
            Some(string)
        }
        Value::String(str) => Some(str.to_string()),
        _ => None,
    }
}