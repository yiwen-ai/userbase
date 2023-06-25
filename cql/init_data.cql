INSERT INTO user_index (cn,id,created_at,expire_at)
VALUES ('jarvis',0x00000000000000004d5bfcb8,toUnixTimestamp(currentTimestamp()),0)
IF NOT EXISTS;

INSERT INTO user (id,cn,gid,status,rating,kind,name,language,created_at,updated_at,avatar,location,email,phone)
VALUES (
  0x00000000000000004d5bfcb8,
  'jarvis',
  0x00000000000000004d5bfcb8,
  2,
  127,
  -1,
  'Jarvis',
  'eng',
  toUnixTimestamp(currentTimestamp()),
  toUnixTimestamp(currentTimestamp()),
  '',
  '',
  '',
  ''
) IF NOT EXISTS;

INSERT INTO group_index (cn,id,created_at,expire_at)
VALUES ('jarvis',0x00000000000000004d5bfcb8,toUnixTimestamp(currentTimestamp()),0)
IF NOT EXISTS;

INSERT INTO group (id,cn,status,kind,uid,created_at,updated_at,name,logo,email)
VALUES (
  0x00000000000000004d5bfcb8,
  'jarvis',
  1,
  2,
  0x00000000000000004d5bfcb8,
  toUnixTimestamp(currentTimestamp()),
  toUnixTimestamp(currentTimestamp()),
  'Jarvis',
  '',
  ''
) IF NOT EXISTS;
