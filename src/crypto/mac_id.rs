use hmac::{Hmac, Mac};
use sha3::Sha3_256;
use subtle::ConstantTimeEq;

pub struct MacId {
    hmac: Hmac<Sha3_256>,
}

impl MacId {
    pub fn new(key: [u8; 32]) -> Self {
        let hmac: Hmac<Sha3_256> = Hmac::new_from_slice(&key).unwrap();
        MacId { hmac }
    }

    pub fn uuid(&self, gid: &xid::Id, uid: &xid::Id) -> uuid::Uuid {
        let digest = self
            .hmac
            .clone()
            .chain_update(gid.as_bytes())
            .chain_update(uid.as_bytes())
            .finalize()
            .into_bytes();
        let mut code = [0u8; 16];
        code.copy_from_slice(&digest[..16]);
        uuid::Uuid::from_bytes(code)
    }

    pub fn verify(&self, gid: &xid::Id, uid: &xid::Id, id: &uuid::Uuid) -> bool {
        let digest = self
            .hmac
            .clone()
            .chain_update(gid.as_bytes())
            .chain_update(uid.as_bytes())
            .finalize()
            .into_bytes();
        let id: &[u8; 16] = id.as_bytes();
        id.ct_eq(&digest[..16]).unwrap_u8() == 1u8
    }

    pub fn user_key_seed(&self, uid: &xid::Id) -> [u8; 32] {
        let mut key = [0u8; 32];
        key.copy_from_slice(
            &self
                .hmac
                .clone()
                .chain_update(b"user key seed")
                .chain_update(uid.as_bytes())
                .finalize()
                .into_bytes()[..32],
        );
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    #[test]
    fn mac_id_works() {
        let mac_id = MacId::new(hex!(
            "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"
        ));
        let gid = xid::new();
        let uid = xid::new();
        let id = mac_id.uuid(&gid, &uid);
        println!("id: {}", id);
        assert!(mac_id.verify(&gid, &uid, &id));
        assert_eq!(mac_id.uuid(&gid, &uid), id);
        assert_eq!(mac_id.uuid(&gid, &uid), id);
        assert_eq!(mac_id.uuid(&gid, &uid), id);

        let uid = xid::new();
        let id2 = mac_id.uuid(&gid, &uid);
        assert!(mac_id.verify(&gid, &uid, &id2));
        assert_eq!(mac_id.uuid(&gid, &uid), id2);
        assert_ne!(id2, id);

        let gid = xid::new();
        let id3 = mac_id.uuid(&gid, &uid);
        assert!(mac_id.verify(&gid, &uid, &id3));
        assert_eq!(mac_id.uuid(&gid, &uid), id3);
        assert_ne!(id3, id2);
        assert_ne!(id3, id);

        let mac_id = MacId::new(hex!(
            "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E1F"
        ));
        let id4 = mac_id.uuid(&gid, &uid);
        assert!(mac_id.verify(&gid, &uid, &id4));
        assert_eq!(mac_id.uuid(&gid, &uid), id4);
        assert_ne!(id4, id3);
        assert_ne!(id4, id2);
        assert_ne!(id4, id);
    }
}
