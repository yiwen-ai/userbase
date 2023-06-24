CREATE TABLE IF NOT EXISTS user_index (
    cn         TEXT,   -- user common name, globally unique
    id         BLOB,   -- user id, 12 bytes XID, https://docs.rs/xid/latest/xid/
    created_at BIGINT, -- login name created at, unix time, ms
    expire_at  BIGINT, -- login name expire at, unix time, ms
    PRIMARY KEY (cn)
) WITH caching = {'enabled': 'true'}
    AND comment = 'user index'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE TABLE IF NOT EXISTS user (
    id         BLOB,    -- user id, 12 bytes XID, https://docs.rs/xid/latest/xid/
    cn         TEXT,    -- user common name, globally unique
    gid        BLOB,    -- optional, group id who create the user. The group owners has full control over these users.
    status     TINYINT, -- int8, -2: Disabled -1: Suspended, 0: Normal, 1: Verified, 2: Protected
    rating     TINYINT, -- int8, rating of content that user can view.
    kind       TINYINT, -- int8, -1: Robot, 0: Human, 1: Organization, 2: Corporation, 3: Education, 4: Government
    name       TEXT,    -- display name
    language   TEXT,    -- language user preferred, ISO 639-3
    created_at BIGINT,  -- create at
    updated_at BIGINT,  -- update at
    avatar     TEXT,
    location   TEXT,
    email      TEXT,
    phone      TEXT,
    bio        BLOB,    -- biography in CBOR format
    PRIMARY KEY (id)
) WITH caching = {'enabled': 'true'}
    AND comment = 'users'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE INDEX user_gid ON user (gid);

CREATE TABLE IF NOT EXISTS group_index (
    cn         TEXT,   -- group common name, globally unique
    id         BLOB,   -- group id, 12 bytes XID, https://docs.rs/xid/latest/xid/
    created_at BIGINT, -- group name created at, unix time, ms
    expire_at  BIGINT, -- group name expire at, unix time, ms
    PRIMARY KEY (cn)
) WITH caching = {'enabled': 'true'}
    AND comment = 'group index'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE TABLE IF NOT EXISTS group (
    id          BLOB,       -- group id, 12 bytes XID, https://docs.rs/xid/latest/xid/
    cn          TEXT,       -- group common name, globally unique
    status      TINYINT,    -- int8, -2: Disabled -1: Suspended, 0: Normal, 1: Verified, 2: Published
    kind        TINYINT,    -- int8, 0: Normal, 1: Organization, 2: Corporation, 3: Education, 4: Government
    uid         BLOB,       -- user id who create the group.
    created_at  BIGINT,     -- create at
    updated_at  BIGINT,     -- update at
    name        TEXT,       -- group display name
    logo        TEXT,
    keywords    LIST<TEXT>, -- keywords
    email       TEXT,
    description BLOB,       -- description in CBOR format
    PRIMARY KEY (id)
) WITH caching = {'enabled': 'true'}
    AND comment = 'users'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE TABLE IF NOT EXISTS member (
    gid        BLOB,    -- group id, 12 bytes XID
    uid        BLOB,    -- user id, 12 bytes XID
    role       TINYINT, -- int8, -2: Suspended -1: Subscriber, 0: Member, 1: Admin, 2: Owner
    priority   TINYINT, -- int8, priority that user marked on the group, -1: Ignored, 0: Normal, 1: Preferred, 2: Pinned
    created_at BIGINT,  -- create at
    updated_at BIGINT,  -- update at
    PRIMARY KEY (gid, uid)
) WITH CLUSTERING ORDER BY (uid ASC)
    AND caching = {'enabled': 'true'}
    AND comment = 'group users'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE INDEX member_uid ON member (uid);
CREATE INDEX member_gid_role ON member ((gid), role);

CREATE TABLE IF NOT EXISTS authn (
    idp        TEXT,      -- identity provider, such as github, webchat, phone, email...
    aid        TEXT,      -- app id (or client id) from provider
    oid        TEXT,      -- user open id from provider
    uid        BLOB,      -- user id
    created_at BIGINT,    -- create at, unix time, ms
    updated_at BIGINT,    -- update at
    expire_at  BIGINT,    -- expire at, unix time, ms
    scope      SET<TEXT>, -- optional, Oauth2 scope
    ip         TEXT,      -- optional, last access ip
    payload    BLOB,      -- payload in CBOR format, struct defined by provider
    PRIMARY KEY ((idp, aid, oid))
) WITH caching = {'enabled': 'true'}
    AND comment = 'authentications'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE INDEX authn_uid ON authn (uid);

CREATE TABLE IF NOT EXISTS authz (
    oid        TEXT,      -- user open id: BASE64URL(HMAC_256_256(uid + gid)[..16])
    aid        BLOB,      -- app id is a robot user id who created by a group
    uid        BLOB,      -- user id
    created_at BIGINT,    -- create at, unix time, ms
    updated_at BIGINT,    -- update at
    expire_at  BIGINT,    -- expire at, unix time, ms
    scope      SET<TEXT>, -- optional, Oauth2 scope
    ip         TEXT,      -- optional, last access ip
    PRIMARY KEY (oid, aid)
) WITH caching = {'enabled': 'true'}
    AND comment = 'authorizations'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE INDEX authz_uid ON authz (uid);

CREATE TABLE IF NOT EXISTS session (
    id          BLOB,   -- session id, 12 bytes XID
    uid         BLOB,   -- user id
    ip          TEXT,   -- last access ip
    created_at  BIGINT, -- updated at, unix time, ms
    updated_at  BIGINT, -- updated at, unix time, ms
    device_id   TEXT,
    device_desc TEXT,
    idp         TEXT,   -- provider for authn or group id for authz
    aid         TEXT,   -- app id from provider
    oid         TEXT,   -- user open id from provider
    PRIMARY KEY (id)
) WITH caching = {'enabled': 'true'}
    AND comment = 'user''s tokens index'
    AND compaction = {'class': 'TimeWindowCompactionStrategy', 'compaction_window_size': 3}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 604800; -- 60*60*24*7, 604800，可以续期，id 不变 token 变

CREATE INDEX session_uid ON session (uid);
