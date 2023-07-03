INSERT INTO user_index (cn,id,created_at,expire_at)
VALUES ('jarvis',0x00000000000000004d5bfcb8,toUnixTimestamp(currentTimestamp()),0)
IF NOT EXISTS;

INSERT INTO user (id,cn,gid,status,rating,kind,created_at,updated_at,email,phone,name,birthdate,locale,picture,address,website)
VALUES (
  0x00000000000000004d5bfcb8,
  'jarvis',
  0x00000000000000004d5bfcb8,
  2,
  127,
  -1,
  toUnixTimestamp(currentTimestamp()),
  toUnixTimestamp(currentTimestamp()),
  '',
  '',
  'Jarvis',
  738651,
  'eng',
  '',
  '',
  'https://www.yiwen.ai'
) IF NOT EXISTS;

INSERT INTO group_index (cn,id,created_at,expire_at)
VALUES ('jarvis',0x00000000000000004d5bfcb8,toUnixTimestamp(currentTimestamp()),0)
IF NOT EXISTS;

INSERT INTO group (id,cn,uid,status,kind,created_at,updated_at,name,keywords,logo,slogan,address,website)
VALUES (
  0x00000000000000004d5bfcb8,
  'jarvis',
  0x00000000000000004d5bfcb8,
  1,
  2,
  toUnixTimestamp(currentTimestamp()),
  toUnixTimestamp(currentTimestamp()),
  'Jarvis',
  [],
  '',
  '',
  '',
  'https://www.yiwen.ai'
) IF NOT EXISTS;
