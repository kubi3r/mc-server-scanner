use std::process::Command;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use tokio::select;
use tokio::sync::{mpsc, mpsc::Sender};
use tokio::net::TcpSocket;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::{sleep, timeout};
use tokio::fs::File;
use tokio_postgres::NoTls;
use serde_json::{Value};

use util::{Config, Player, ServerInfo, ServerJoinInfo};

mod db;
mod util;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let mut config = parse_args(args);

    let (client, connection) = tokio_postgres::connect("host=localhost user=postgres dbname=scanner", NoTls).await.unwrap();
    let client = Arc::new(client);

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {e}");
        }
    });

    let (tx, rx) = mpsc::channel(100);

    tokio::spawn(db::collect_servers_to_db(client.clone(), rx));

    if config.full_scan_every.is_none() || config.rescan_every.is_none() {
        if config.masscan {
            println!("scanning for open ports with masscan");
            Command::new("masscan")
                .args(["-c", "masscan/masscan.conf"])
                .status().expect("failed to run masscan");
        }

        let servers = if config.rescan_mode {
            config.join_scan = false;
            db::get_servers(&client).await
        } else {
            config.join_scan = true;
            read_masscan_output("masscan/masscan-output.txt").await
        };

        batch_server_list(servers, &tx, &config).await;
        db::update_stats(&client).await;
    } else {
        let mut last_full_scan = SystemTime::now();
        let mut last_rescan = SystemTime::now();

        let full_scan_every = match config.full_scan_every {
            Some(dur) => {
                println!("scanning for new servers every {} hours", dur.as_secs() / 3600);
                dur
            },
            None => Duration::MAX
        };

        let rescan_every = match config.rescan_every {
            Some(dur) => {
                println!("rescanning every {} hours", dur.as_secs() / 3600);
                dur
            },
            None => Duration::MAX
        };

        loop {
            let servers = select! {
                _ = sleep(rescan_every - last_rescan.elapsed().unwrap()) => {
                    println!("rescanning now");
                    last_rescan = SystemTime::now();
                    
                    config.join_scan = false;
                    db::get_servers(&client).await
                },
                _ = sleep(full_scan_every - last_full_scan.elapsed().unwrap()) => {
                    println!("scanning for new servers now");
                    last_full_scan = SystemTime::now();

                    if config.masscan {
                        println!("scanning for open ports with masscan");
                        Command::new("masscan")
                            .args(["-c", "masscan/masscan.conf"])
                            .status().expect("failed to run masscan");
                    }

                    config.join_scan = true;
                    read_masscan_output("masscan/masscan-output.txt").await
                },
            };

            batch_server_list(servers, &tx, &config).await;
            db::update_stats(&client).await;
        }
    }
}

fn parse_args(args: Vec<String>) -> Config {
    let mut config = Config {
        timeout: Duration::from_secs(5),
        batch_size: 1000,
        join_scan: false,
        rescan_mode: false,
        rescan_every: None,
        full_scan_every: None,
        masscan: false,
    };

    let mut args_iter = args.iter().skip(1);

    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "-m" | "--masscan" => {
                config.masscan = true;
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
            "--rescan-every" => {
                let time = args_iter.next();

                let Some(time) = time else {
                    panic!("time for '--rescan-every' is not specified")
                };

                config.rescan_every = Some(time.parse::<humantime::Duration>().expect("time for '--rescan-every' is not a valid time").into())
            },
            "--full-scan-every" => {
                let time = args_iter.next();

                let Some(time) = time else {
                    panic!("time for '--full-scan-every' is not specified")
                };

                config.full_scan_every = Some(time.parse::<humantime::Duration>().expect("time for '--full-scan-every' is not a valid time").into())
            },
            arg => {
                panic!("unknown argument: {arg}")
            }
        }
    }

    config
}

async fn read_masscan_output(file_path: &str) -> Vec<SocketAddr> {
    let mut servers: Vec<SocketAddr> = Vec::new();

    let masscan_output = File::open(file_path).await.expect("file in masscan/masscan-output.txt was not found, run with --masscan first");
    let mut line_iter = BufReader::new(masscan_output).lines();

    while let Some(line) = line_iter.next_line().await.unwrap() {
        if line.starts_with('#') {
            continue
        }

        let mut split = line.split(' ');
        split.next();
        split.next();

        let port: u16 = split.next().expect("wrongly formatted masscan output").parse().expect("wrongly formatted masscan output");
        let ip: &str = split.next().expect("wrongly formatted masscan output");

        let addr = SocketAddr::new(ip.parse().expect("failed to parse into ipv4 address"), port);

        servers.push(addr);
    }

    servers
}

async fn batch_server_list(server_list: Vec<SocketAddr>, tx: &Sender<Vec<(SocketAddr, Option<ServerInfo>, Option<ServerJoinInfo>)>>, config: &Config) {
    let server_list_len = server_list.len();
    println!("scanning {server_list_len} servers");

    let mut i: usize = 0;

    while i + config.batch_size < server_list_len {
        tx.send(scan_batch(&server_list[i..i + config.batch_size], &config).await).await.unwrap();
        i += config.batch_size;
        println!("{i}/{server_list_len}");
    }
    
    if i != server_list_len {
        tx.send(scan_batch(&server_list[i..i + (server_list_len - i)], &config).await).await.unwrap();
        i += server_list_len - i;
        println!("{i}/{server_list_len}");
    }
}

async fn scan_batch(batch: &[SocketAddr], config: &Config) -> Vec<(SocketAddr, Option<ServerInfo>, Option<ServerJoinInfo>)> {
    let futures = FuturesUnordered::new();
    
    for addr in batch {
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

    stream.write_all(&util::prefix_len(&util::form_handshake(1, 754, addr))).await.ok()?;
    stream.write_all(&[0x01, 0x00]).await.ok()?;

    let mut reader = BufReader::new(stream);
    util::read_varint(&mut reader).await?;

    let packet_id = util::read_varint(&mut reader).await?;
    if packet_id != 0x00 {
        return None
    }

    let json_len = util::read_varint(&mut reader).await?;
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
        motd: util::parse_motd(&json["description"]),
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

    stream.write_all(&util::prefix_len(&util::form_handshake(2, protocol, addr))).await.ok()?;
    
    let username = b"scanner";
    
    let login_start_fields = match protocol {
        protocol if protocol <= 758 => {
            &util::prefix_len(username)
        },
        759 => {
            &[
                &util::prefix_len(username)[..],
                &[0x00]
            ].concat()
        },
        760 => {
            &[
                &util::prefix_len(username)[..],
                &[0x00, 0x00]
            ].concat()
        },
        protocol if protocol <= 763 => {
            &[
                &util::prefix_len(username)[..],
                &[0x00]
            ].concat()
        },
        _ => {
            &[
                &util::prefix_len(username)[..],
                &0xe0ce739bab603be2b9dfd45dcee616a2_u128.to_be_bytes()
            ].concat()
        }
    };

    stream.write_all(&util::prefix_len(&[&[0x00], &login_start_fields[..]].concat())).await.ok()?;

    let mut reader = BufReader::new(stream);

    util::read_varint(&mut reader).await?;
    let packet_id = util::read_varint(&mut reader).await?;

    match packet_id {
        0x00 => {
            let reason_len = util::read_varint(&mut reader).await?;

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