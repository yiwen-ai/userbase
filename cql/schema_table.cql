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

-- https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
CREATE TABLE IF NOT EXISTS user (
    id         BLOB,    -- user id, 12 bytes XID, https://docs.rs/xid/latest/xid/
    cn         TEXT,    -- user common name, globally unique
    gid        BLOB,    -- optional, group id who create the user. The group owners has full control over these users.
    status     TINYINT, -- int8, -2: Disabled -1: Suspended, 0: Normal, 1: Verified, 2: Protected
    kind       TINYINT, -- int8, -1: Robot, 0: Human, 1: Organization, 2: Corporation, 3: Education, 4: Government
    rating     TINYINT, -- int8, rating of content that user can view.
    created_at BIGINT,  -- create at
    updated_at BIGINT,  -- update at
    email      TEXT,
    phone      TEXT,
    name       TEXT,    -- display name
    birthdate  INT,    -- day’s number in the proleptic Gregorian calendar, with January 1, 1 being day 1.
    locale     TEXT,    -- language user preferred, ISO 639-3
    picture    TEXT,
    address    TEXT,
    website    TEXT,
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

-- https://schema.org/Organization
CREATE TABLE IF NOT EXISTS group (
    id          BLOB,       -- group id, 12 bytes XID, https://docs.rs/xid/latest/xid/
    cn          TEXT,       -- group common name, globally unique
    uid         BLOB,       -- user id who create the group.
    status      TINYINT,    -- int8, -2: Disabled -1: Suspended, 0: Normal, 1: Verified, 2: Published
    kind        TINYINT,    -- int8, 0: Normal, 1: Organization, 2: Corporation, 3: Education, 4: Government
    created_at  BIGINT,     -- create at
    updated_at  BIGINT,     -- update at
    email       TEXT,
    legal_name  TEXT,       -- The official name of the organization, e.g. the registered company name.
    name        TEXT,       -- group display name
    keywords    LIST<TEXT>, -- keywords
    logo        TEXT,
    slogan      TEXT,       -- A slogan or motto associated with the item.
    address     TEXT,
    website     TEXT,
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

CREATE TABLE IF NOT EXISTS follow (
    uid        BLOB,    -- user id, 12 bytes XID
    gid        BLOB,    -- group id, 12 bytes XID
    created_at BIGINT,  -- create at
    PRIMARY KEY (uid, gid)
) WITH CLUSTERING ORDER BY (gid ASC)
    AND caching = {'enabled': 'true'}
    AND comment = 'user followed groups'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE INDEX follow_gid ON follow (gid);

CREATE TABLE IF NOT EXISTS authn (
    idp        TEXT,      -- identity provider, such as github, webchat, phone, email...
    aud        TEXT,      -- audience - app id (or client id) from provider
    sub        TEXT,      -- subject - user unique id from provider
    uid        BLOB,      -- user id
    created_at BIGINT,    -- create at, unix time, ms
    updated_at BIGINT,    -- update at
    expire_at  BIGINT,    -- expire at, unix time, ms
    scope      SET<TEXT>, -- optional, Oauth2 scope
    ip         TEXT,      -- optional, last access ip
    payload    BLOB,      -- payload in CBOR format, struct defined by provider
    PRIMARY KEY ((idp, aud, sub))
) WITH caching = {'enabled': 'true'}
    AND comment = 'authentications'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE INDEX authn_uid ON authn (uid);

CREATE TABLE IF NOT EXISTS authz (
    aud        BLOB,      -- audience - app id, a robot user who created by a group
    sub        UUID,      -- subject - user unique id from provider, crate::crypto::MacId
    uid        BLOB,      -- user id
    created_at BIGINT,    -- create at, unix time, ms
    updated_at BIGINT,    -- update at
    expire_at  BIGINT,    -- expire at, unix time, ms
    scope      SET<TEXT>, -- optional, Oauth2 scope
    ip         TEXT,      -- optional, last access ip
    PRIMARY KEY ((aud, sub))
) WITH caching = {'enabled': 'true'}
    AND comment = 'authorizations'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE INDEX authz_uid ON authz (uid);

CREATE TABLE IF NOT EXISTS session (
    id          BLOB,   -- session id, 12 bytes XID
    uid         BLOB,   -- user id
    created_at  BIGINT, -- updated at, unix time, ms
    updated_at  BIGINT, -- updated at, unix time, ms
    ttl         INT,    -- ttl, seconds
    device_id   TEXT,
    device_desc TEXT,
    idp         TEXT,   -- provider for authn or group id for authz
    aud         TEXT,   -- audience - app id
    sub         TEXT,   -- subject - user unique id from provider
    PRIMARY KEY (id)
) WITH caching = {'enabled': 'true'}
    AND comment = 'user''s tokens index'
    AND compaction = {'class': 'TimeWindowCompactionStrategy', 'compaction_window_size': 7}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 2592000; -- 60*60*24*30，可以续期

CREATE INDEX session_uid ON session (uid);
