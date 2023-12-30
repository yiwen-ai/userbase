use coset::{CborSerializable, CoseMac0, CoseMac0Builder, HeaderBuilder, TaggedCborSerializable};
use hmac::{Hmac, Mac};
use sha3::Sha3_256;

pub use coset::cwt::{ClaimsSet, Timestamp};

pub struct MacState {
    macer: Hmac<Sha3_256>,
}

impl MacState {
    pub fn new(key: [u8; 32]) -> Self {
        let macer: Hmac<Sha3_256> = Hmac::new_from_slice(&key).unwrap();
        Self { macer }
    }

    pub fn create_state(&self, state: ClaimsSet, aad: &[u8]) -> anyhow::Result<Vec<u8>> {
        let protected = HeaderBuilder::new().build();
        let unprotected = HeaderBuilder::new().build();
        let payload = state.to_vec().map_err(anyhow::Error::msg)?;

        let m0 = CoseMac0Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload)
            .create_tag(aad, |tbm| {
                self.macer.clone().chain_update(tbm).finalize().into_bytes()[0..8].to_vec()
            })
            .build();
        m0.to_tagged_vec().map_err(anyhow::Error::msg)
    }

    pub fn verify_state(&self, mac0_data: &[u8], aad: &[u8]) -> anyhow::Result<ClaimsSet> {
        let m0 = CoseMac0::from_tagged_slice(mac0_data).map_err(anyhow::Error::msg)?;
        m0.verify_tag(aad, |tag, tbm| {
            let t = &self.macer.clone().chain_update(tbm).finalize().into_bytes()[0..8];
            if t != tag {
                return Err(anyhow::Error::msg("verify tag failed"));
            }
            Ok(())
        })?;
        let state =
            ClaimsSet::from_slice(&m0.payload.unwrap_or_default()).map_err(anyhow::Error::msg)?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand_core::{OsRng, RngCore};

    #[test]
    fn encrypt0_works() {
        let mut key = [0u8; 32];
        let mut id = [0u8; 16];

        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut id);

        let ms = MacState::new(key);
        let state = ClaimsSet {
            expiration_time: Some(Timestamp::WholeSeconds(12345)),
            cwt_id: Some(id.to_vec()),
            ..Default::default()
        };

        let data = ms.create_state(state, b"yiwen.ai").unwrap();
        let res = ms.verify_state(&data, b"yiwen.ai").unwrap();
        assert_eq!(Some(id.to_vec()), res.cwt_id);
        assert_eq!(Some(Timestamp::WholeSeconds(12345)), res.expiration_time);
        assert!(ms.verify_state(&data, b"yiwen").is_err());
    }
}
