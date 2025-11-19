use tokio_postgres::Client;
use std::{net::{IpAddr, SocketAddr}, sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use tokio::sync::mpsc::Receiver;

use crate::util::{ServerInfo, ServerJoinInfo};

pub async fn get_servers(client: &Client) -> Vec<SocketAddr> {
    let mut servers = Vec::new();

    let server_rows = client.query("SELECT ip, port FROM servers", &[]).await.unwrap();
    for row in server_rows {
        let ip: IpAddr = row.get("ip");
        let port: i32 = row.get("port");

        servers.push(SocketAddr::new(ip, port.try_into().unwrap()))
    }

    servers
}

pub async fn collect_servers_to_db(client: Arc<Client>, mut rx: Receiver<Vec<(SocketAddr, Option<ServerInfo>, Option<ServerJoinInfo>)>>) {
    let insert_server = client.prepare(r"
        INSERT INTO servers (ip, port, version_name, protocol, players_max, players_online, online, motd, favicon, first_seen, last_seen, cracked, whitelist, forge, country)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
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
            forge = EXCLUDED.forge,
            country = EXCLUDED.country
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

    let maxmind_reader = maxminddb::Reader::open_readfile("GeoLite2-Country.mmdb").unwrap();

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

            let country_code = match maxmind_reader.lookup::<maxminddb::geoip2::Country>(addr.ip()).unwrap() {
                Some(country) => match country.country {
                    Some(country) => {
                        country.iso_code
                    },
                    None => None
                },
                None => None
            };

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
                &country_code
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

pub async fn update_stats(client: &Client) {
    let stats = client.prepare(r"
        INSERT INTO stats (timestamp, server_count, online_count, cracked_count, total_player_count, whitelist_count, forge_count)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    ").await.unwrap();

    let timestamp = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap();
    let server_count: i64 = client.query_one("SELECT COUNT(ip) FROM servers", &[]).await.unwrap().get(0);
    let online_count: i64 = client.query_one("SELECT COUNT(ip) FROM servers WHERE online", &[]).await.unwrap().get(0);
    let cracked_count: i64 = client.query_one("SELECT COUNT(ip) FROM servers WHERE cracked", &[]).await.unwrap().get(0);
    let total_player_count: i64 = client.query_one("SELECT COUNT(name) FROM players", &[]).await.unwrap().get(0);
    let whitelist_count: i64 = client.query_one("SELECT COUNT(ip) FROM servers WHERE whitelist", &[]).await.unwrap().get(0);
    let forge_count: i64 = client.query_one("SELECT COUNT(ip) FROM servers WHERE forge", &[]).await.unwrap().get(0);

    client.execute(&stats, &[
        &timestamp,
        &server_count,
        &online_count,
        &cracked_count,
        &total_player_count,
        &whitelist_count,
        &forge_count,
    ]).await.unwrap();
}