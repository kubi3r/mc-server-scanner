CREATE TABLE servers (
    ip inet NOT NULL,
    port integer NOT NULL,
    version_name text,
    protocol integer,
    players_max integer,
    players_online integer,
    cracked boolean,
    whitelist boolean,
    forge boolean,
    motd text,
    favicon text,
    first_seen bigint NOT NULL,
    last_seen bigint NOT NULL,
    PRIMARY KEY (ip, port)
);

CREATE TABLE players (
    ip inet NOT NULL,
    port integer NOT NULL,
    name text NOT NULL,
    uuid text NOT NULL,
    first_seen bigint NOT NULL,
    last_seen bigint NOT NULL,
    PRIMARY KEY (ip, port, name),
    FOREIGN KEY (ip, port)
        REFERENCES servers(ip, port)
        ON DELETE CASCADE
);