ALTER TABLE workspace_agents
    ADD COLUMN ipv6 inet NOT NULL DEFAULT '::/128',
    ADD COLUMN wireguard_public_key varchar(128) NOT NULL DEFAULT 'mkey:0000000000000000000000000000000000000000000000000000000000000000',
    ADD COLUMN disco_public_key varchar(128) NOT NULL DEFAULT 'discokey:0000000000000000000000000000000000000000000000000000000000000000';

CREATE TABLE cli_wireguard_peers (
    id uuid NOT NULL,
    owner uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    wireguard_public_key varchar(128),
    disco_public_key varchar(128),
    ipv6 inet NOT NULL UNIQUE,
    PRIMARY KEY (id)
);
