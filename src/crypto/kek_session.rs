// use hex_literal::hex;
use aes_kw::KekAes256;
use base64ct::{Base64UrlUnpadded, Encoding};

pub struct Session {
    kek: KekAes256,
}

impl Session {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            kek: KekAes256::from(key),
        }
    }

    pub fn session(&self, sid: &xid::Id, uid: &xid::Id, oid: Option<&uuid::Uuid>) -> String {
        let data = if oid.is_some() {
            let mut buf: Vec<u8> = Vec::with_capacity(40);
            buf.extend_from_slice(sid.as_bytes());
            buf.extend_from_slice(uid.as_bytes());
            buf.extend_from_slice(oid.unwrap().as_bytes());
            buf
        } else {
            let mut buf: Vec<u8> = Vec::with_capacity(24);
            buf.extend_from_slice(sid.as_bytes());
            buf.extend_from_slice(uid.as_bytes());
            buf
        };

        let wrapped_data = self.kek.wrap_with_padding_vec(&data).unwrap();
        println!("KEK: {} -> {}", data.len(), wrapped_data.len());
        Base64UrlUnpadded::encode_string(&wrapped_data)
    }

    pub fn from(&self, sess: &str) -> anyhow::Result<(xid::Id, xid::Id, Option<uuid::Uuid>)> {
        let wrapped_data = Base64UrlUnpadded::decode_vec(sess).map_err(anyhow::Error::msg)?;
        let data = self
            .kek
            .unwrap_with_padding_vec(&wrapped_data)
            .map_err(anyhow::Error::msg)?;
        match data.len() {
            24 => {
                let mut sid = [0u8; 12];
                sid.copy_from_slice(&data[..12]);
                let mut uid = [0u8; 12];
                uid.copy_from_slice(&data[12..]);
                Ok((xid::Id(sid), xid::Id(uid), None))
            }
            40 => {
                let mut sid = [0u8; 12];
                sid.copy_from_slice(&data[..12]);
                let mut uid = [0u8; 12];
                uid.copy_from_slice(&data[12..24]);
                let mut oid = [0u8; 16];
                oid.copy_from_slice(&data[24..]);
                Ok((
                    xid::Id(sid),
                    xid::Id(uid),
                    Some(uuid::Uuid::from_bytes(oid)),
                ))
            }
            _ => Err(anyhow::Error::msg("invalid session")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    #[test]
    fn aes_session_works() {
        let aes_session = Session::new(hex!(
            "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"
        ));

        let sid = xid::new();
        let uid = xid::new();
        let oid = uuid::Uuid::new_v4();

        let s1 = aes_session.session(&sid, &uid, Some(&oid));

        assert!(aes_session.from(&s1[1..]).is_err());
        let (a, b, c) = aes_session.from(&s1).unwrap();
        assert_eq!(a, sid);
        assert_eq!(b, uid);
        assert_eq!(c, Some(oid));

        let s2 = aes_session.session(&sid, &uid, None);
        assert_ne!(s1, s2);

        assert!(aes_session.from(&s2[2..]).is_err());
        let (a, b, c) = aes_session.from(&s2).unwrap();
        assert_eq!(a, sid);
        assert_eq!(b, uid);
        assert_eq!(c, None);

        let aes_session = Session::new(hex!(
            "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0E"
        ));
        assert!(aes_session.from(&s1).is_err());
        assert!(aes_session.from(&s2).is_err());

        let s3 = aes_session.session(&sid, &uid, Some(&oid));

        assert!(aes_session.from(&s3[3..]).is_err());
        let (a, b, c) = aes_session.from(&s3).unwrap();
        assert_eq!(a, sid);
        assert_eq!(b, uid);
        assert_eq!(c, Some(oid));

        let s4 = aes_session.session(&sid, &uid, None);
        assert_ne!(s4, s3);
        assert_ne!(s4, s2);
        assert_ne!(s4, s1);

        assert!(aes_session.from(&s4[4..]).is_err());
        let (a, b, c) = aes_session.from(&s4).unwrap();
        assert_eq!(a, sid);
        assert_eq!(b, uid);
        assert_eq!(c, None);
    }
}
