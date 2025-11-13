use std::process::Command;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use tokio::sync::{mpsc, mpsc::Sender};
use tokio::net::TcpSocket;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;
use tokio::fs::File;
use tokio_postgres::NoTls;
use serde_json::Value;

struct Config {
    timeout: Duration,
    batch_size: usize,
    join_scan: bool,
    rescan_mode: bool,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let config = parse_args(args);

    let (client, connection) = tokio_postgres::connect("host=localhost user=postgres dbname=scanner", NoTls).await.unwrap();
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {e}");
        }
    });

    let mut servers: Vec<SocketAddr> = Vec::new();
    if config.rescan_mode {
        let server_rows = client.query("SELECT ip, port FROM servers", &[]).await.unwrap();
        for row in server_rows {
            let ip: IpAddr = row.get("ip");
            let port: i32 = row.get("port");

            servers.push(SocketAddr::new(ip, port.try_into().unwrap()))
        }
    } else {
        let masscan_output = File::open("masscan/masscan-output.txt").await.expect("file masscan-output.txt was not found, run with --masscan first");
        let mut line_iter = BufReader::new(masscan_output).lines();

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
        }
    }

    let (tx, mut rx) = mpsc::channel(100);

    tokio::spawn(batch_server_list(servers, tx, config));

    let insert_server = client.prepare(r"
        INSERT INTO servers (ip, port, version_name, protocol, players_max, players_online, online, motd, favicon, first_seen, last_seen, cracked, whitelist, forge)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        ON CONFLICT (ip, port)
        DO UPDATE SET
            version_name = EXCLUDED.version_name,
            protocol = EXCLUDED.protocol,
            players_max = EXCLUDED.players_max,
            players_online = EXCLUDED.players_online,
            online = EXCLUDED.online,
            motd = EXCLUDED.motd,
            favicon = EXCLUDED.favicon,
            last_seen = EXCLUDED.last_seen,
            cracked = EXCLUDED.cracked,
            whitelist = EXCLUDED.whitelist,
            forge = EXCLUDED.forge
    ").await.unwrap();

    let insert_player = client.prepare(r"
        INSERT INTO players (ip, port, name, uuid, first_seen, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (ip, port, name)
        DO UPDATE SET
            last_seen = EXCLUDED.last_seen
    ").await.unwrap();

    let set_offline = client.prepare(r"
        UPDATE servers
        SET
            online = false
        WHERE
            ip = $1 AND port = $2 
    ").await.unwrap();

    while let Some(servers) = rx.recv().await {
        for server in servers {
            let (addr, server_info, server_join_info) = server;

            let Some(server_info) = server_info else {
                client.execute(&set_offline, &[&addr.ip(), &(addr.port() as i32)]).await.unwrap();
                continue
            };

            let (mut cracked, mut whitelist, mut forge) = (None, None, None);
            if let Some(server_join_info) = server_join_info {
                cracked = server_join_info.cracked;
                whitelist = server_join_info.whitelist;
                forge = server_join_info.forge;
            }

            if let Err(e) = client.execute(&insert_server, &[
                &server_info.ip,
                &server_info.port,
                &server_info.version_name,
                &server_info.protocol,
                &server_info.players_max,
                &server_info.players_online,
                &true,
                &server_info.motd,
                &server_info.favicon,
                &server_info.timestamp,
                &server_info.timestamp,
                &cracked,
                &whitelist,
                &forge,
            ]).await {
                eprintln!("error adding server to db: {e}");
            }

            if let Some(sample) = server_info.player_sample {
                for player in sample {
                    if player.name != "Anonymous Player" {
                        if let Err(e) = client.execute(&insert_player, &[&server_info.ip, &server_info.port, &player.name, &player.uuid, &player.timestamp, &player.timestamp]).await {
                            eprintln!("error adding player to db: {e}");
                        }
                    }
                }
            }
        }
    }
}

fn parse_args(args: Vec<String>) -> Config {
    let mut config = Config {
        timeout: Duration::from_secs(5),
        batch_size: 1000,
        join_scan: false,
        rescan_mode: false,
    };

    let mut args_iter = args.iter().skip(1);

    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "-m" | "--masscan" => {
                println!("scanning for open ports with masscan");
                Command::new("masscan")
                    .args(["-c", "masscan/masscan.conf"])
                    .status().expect("failed to run masscan");
            },
            "-j" | "--join" => {
                config.join_scan = true;
            },
            "-r" | "--rescan" => {
                println!("rescanning servers in db");
                config.rescan_mode = true;
            },
            "-b" | "--batch-size" => {
                let size = args_iter.next();

                let Some(size) = size else {
                    panic!("batch size is not specified")
                };

                config.batch_size = size.parse().expect("batch size is not a number");
            },
            "-t" | "--timeout" => {
                let timeout = args_iter.next();

                let Some(timeout) = timeout else {
                    panic!("timeout is not specified")
                };

                config.timeout = timeout.parse::<humantime::Duration>().expect("timeout is not a valid time").into()
            },
            arg => {
                panic!("unknown argument: {arg}")
            }
        }
    }

    config
}

struct ServerInfo {
    ip: IpAddr,
    port: i32,
    version_name: String,
    protocol: i32,
    players_max: i32,
    players_online: i32,
    player_sample: Option<Vec<Player>>,
    motd: Option<String>,
    favicon: Option<String>,
    timestamp: i64
}

struct Player {
    name: String,
    uuid: String,
    timestamp: i64,
}

struct ServerJoinInfo {
    cracked: Option<bool>,
    whitelist: Option<bool>,
    forge: Option<bool>
}

async fn batch_server_list(server_list: Vec<SocketAddr>, tx: Sender<Vec<(SocketAddr, Option<ServerInfo>, Option<ServerJoinInfo>)>>, config: Config) {
    let server_list_len = server_list.len();
    println!("scanning {server_list_len} servers");

    let mut i: usize = 0;

    while i + config.batch_size < server_list_len {
        tx.send(scan_server_list(&server_list[i..i + config.batch_size], &config).await).await.unwrap();
        i += config.batch_size;
        println!("{i}/{server_list_len}");
    }
    
    if i != server_list_len {
        tx.send(scan_server_list(&server_list[i..i + (server_list_len - i)], &config).await).await.unwrap();
        i += server_list_len - i;
        println!("{i}/{server_list_len}");
    }
}

async fn scan_server_list(server_list: &[SocketAddr], config: &Config) -> Vec<(SocketAddr, Option<ServerInfo>, Option<ServerJoinInfo>)> {
    let futures = FuturesUnordered::new();
    
    for addr in server_list {
        futures.push(async {
            match timeout(config.timeout, scan_server(*addr, config.join_scan)).await {
                Ok(result) => result,
                Err(_) => (*addr, None, None)
            }
        });
    }

    return futures.collect().await
}

async fn scan_server(addr: SocketAddr, do_join_scan: bool) -> (SocketAddr, Option<ServerInfo>, Option<ServerJoinInfo>) {
    let Some(server_info) = ping_scan(addr).await else {
        return (addr, None, None)
    };

    if do_join_scan {
        let server_join_info = join_scan(addr, if server_info.protocol <= 0 { 754 } else { server_info.protocol }).await;
        return (addr, Some(server_info), server_join_info)
    }

    return (addr, Some(server_info), None)
}

async fn ping_scan(addr: SocketAddr) -> Option<ServerInfo> {
    let socket = TcpSocket::new_v4().ok()?;
    let mut stream = socket.connect(addr).await.ok()?;

    stream.write_all(&prefix_len(&form_handshake(1, 754, addr))).await.ok()?;
    stream.write_all(&[0x01, 0x00]).await.ok()?;

    let mut reader = BufReader::new(stream);
    read_varint(&mut reader).await?;

    let packet_id = read_varint(&mut reader).await?;
    if packet_id != 0x00 {
        return None
    }

    let json_len = read_varint(&mut reader).await?;
    if json_len > 100000 {
        return None
    }

    let mut json_buf = vec![0u8; json_len as usize];
    reader.read_exact(&mut json_buf).await.ok()?;
    
    let json: Value = serde_json::from_slice(&json_buf).ok()?;
    let timestamp: i64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis().try_into().unwrap();
    let port = addr.port();

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
        motd: parse_motd(&json["description"]),
        favicon: match &json["favicon"] {
            Value::String(str) => Some(str.to_string()),
            _ => None,
        },
        timestamp
    })
}

async fn join_scan(addr: SocketAddr, protocol: i32) -> Option<ServerJoinInfo> {
    let socket = TcpSocket::new_v4().ok()?;
    let mut stream = socket.connect(addr).await.ok()?;

    stream.write_all(&prefix_len(&form_handshake(2, protocol, addr))).await.ok()?;
    
    let username = b"scanner";
    
    let login_start_fields = match protocol {
        protocol if protocol <= 758 => {
            &prefix_len(username)
        },
        759 => {
            &[
                &prefix_len(username)[..],
                &[0x00]
            ].concat()
        },
        760 => {
            &[
                &prefix_len(username)[..],
                &[0x00, 0x00]
            ].concat()
        },
        protocol if protocol <= 763 => {
            &[
                &prefix_len(username)[..],
                &[0x00]
            ].concat()
        },
        _ => {
            &[
                &prefix_len(username)[..],
                &0xe0ce739bab603be2b9dfd45dcee616a2_u128.to_be_bytes()
            ].concat()
        }
    };

    stream.write_all(&prefix_len(&[&[0x00], &login_start_fields[..]].concat())).await.ok()?;

    let mut reader = BufReader::new(stream);

    read_varint(&mut reader).await?;
    let packet_id = read_varint(&mut reader).await?;

    match packet_id {
        0x00 => {
            let reason_len = read_varint(&mut reader).await?;

            let mut buf = vec![0u8; reason_len.try_into().unwrap()];
            reader.read_exact(&mut buf).await.ok()?;

            let str = str::from_utf8(&buf).ok()?;

            match str {
                str if str.to_lowercase().contains("whitelist") || str.to_lowercase().contains("white-list") => {
                    Some(ServerJoinInfo {
                        cracked: Some(true),
                        whitelist: Some(true),
                        forge: Some(false)
                    })
                },
                str if str.to_lowercase().contains("forge") => {
                    Some(ServerJoinInfo {
                        cracked: Some(true),
                        whitelist: None,
                        forge: Some(true)
                    })
                },
                _ => {
                    Some(ServerJoinInfo {
                        cracked: Some(true),
                        whitelist: None,
                        forge: None
                    })
                }
            }
        },
        0x01 => {
            Some(ServerJoinInfo {
                cracked: Some(false),
                whitelist: None,
                forge: None
            })
            
        },
        0x02 | 0x03 => {
            Some(ServerJoinInfo {
                cracked: Some(true),
                whitelist: Some(false),
                forge: Some(false)
            })
        },
        _ => None
    }
}

fn form_handshake(intent: u8, protocol: i32, addr: SocketAddr) -> Vec<u8> {
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

fn prefix_len(bytes: &[u8]) -> Vec<u8> {
    [
        &write_varint(bytes.len().try_into().unwrap()),
        bytes
    ].concat()
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