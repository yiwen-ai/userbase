use ciborium::Value;
use coset::{iana, CborSerializable, CoseKey, CoseKeyBuilder, KeyType, Label};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};

const ZERO_256: [u8; 32] = [0u8; 32];
const KEY_PARAM_K: Label = Label::Int(iana::SymmetricKeyParameter::K as i64);
const KEY_PARAM_D: Label = Label::Int(iana::OkpKeyParameter::D as i64);
const KEY_PARAM_X: Label = Label::Int(iana::OkpKeyParameter::X as i64);

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Key(pub CoseKey);

impl Key {
    pub fn new_sym(alg: iana::Algorithm, kid: &[u8]) -> anyhow::Result<Self> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        assert_ne!(key, ZERO_256);

        let mut key = CoseKeyBuilder::new_symmetric_key(key.to_vec()).algorithm(alg);
        if !kid.is_empty() {
            key = key.key_id(kid.to_vec());
        }
        Ok(Self(key.build()))
    }

    pub fn new_ed25519(kid: &[u8]) -> anyhow::Result<Self> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        assert_ne!(key, ZERO_256);

        let mut key = CoseKeyBuilder::new_okp_key()
            .algorithm(iana::Algorithm::EdDSA)
            .param(
                iana::OkpKeyParameter::Crv as i64,
                Value::from(iana::EllipticCurve::Ed25519 as i64),
            )
            .param(iana::OkpKeyParameter::D as i64, Value::Bytes(key.to_vec()));

        if !kid.is_empty() {
            key = key.key_id(kid.to_vec());
        }
        Ok(Self(key.build()))
    }

    pub fn ed25519_public(&self) -> anyhow::Result<Self> {
        if self.0.kty != KeyType::Assigned(iana::KeyType::OKP) {
            return Err(anyhow::Error::msg("Unsupport key type"));
        };
        let verifying_key = SigningKey::from_bytes(&self.get_private()?).verifying_key();
        let mut key = CoseKeyBuilder::new_okp_key()
            .algorithm(iana::Algorithm::EdDSA)
            .param(
                iana::OkpKeyParameter::Crv as i64,
                Value::from(iana::EllipticCurve::Ed25519 as i64),
            )
            .param(
                iana::OkpKeyParameter::X as i64,
                Value::Bytes(verifying_key.as_bytes().to_vec()),
            )
            .build();
        key.key_id = self.0.key_id.clone();
        Ok(Self(key))
    }

    pub fn key_id(&self) -> Vec<u8> {
        self.0.key_id.clone()
    }

    pub fn to_vec(self) -> anyhow::Result<Vec<u8>> {
        self.0.to_vec().map_err(anyhow::Error::msg)
    }

    pub fn from_slice(data: &[u8]) -> anyhow::Result<Self> {
        let key = CoseKey::from_slice(data).map_err(anyhow::Error::msg)?;
        Ok(Self(key))
    }

    pub fn get_private(&self) -> anyhow::Result<[u8; 32]> {
        let key_param = match self.0.kty {
            KeyType::Assigned(iana::KeyType::Symmetric) => &KEY_PARAM_K,
            KeyType::Assigned(iana::KeyType::OKP) => &KEY_PARAM_D,
            _ => {
                return Err(anyhow::Error::msg("Unsupport key type"));
            }
        };

        for (label, value) in &self.0.params {
            if label == key_param {
                match value {
                    Value::Bytes(val) => {
                        if val.len() != 32 {
                            return Err(anyhow::Error::msg("Invalid key length, expected 32"));
                        }
                        let mut key = [0u8; 32];
                        key.copy_from_slice(val);
                        return Ok(key);
                    }
                    _ => {
                        return Err(anyhow::Error::msg("Invalid key type"));
                    }
                }
            }
        }
        Err(anyhow::Error::msg("Invalid key"))
    }

    pub fn get_public(&self) -> anyhow::Result<[u8; 32]> {
        let key_param = match self.0.kty {
            KeyType::Assigned(iana::KeyType::OKP) => &KEY_PARAM_X,
            _ => {
                return Err(anyhow::Error::msg("Unsupport key type"));
            }
        };

        for (label, value) in &self.0.params {
            if label == key_param {
                match value {
                    Value::Bytes(val) => {
                        if val.len() != 32 {
                            return Err(anyhow::Error::msg("Invalid key length, expected 32"));
                        }
                        let mut key = [0u8; 32];
                        key.copy_from_slice(val);
                        return Ok(key);
                    }
                    _ => {
                        return Err(anyhow::Error::msg("Invalid key type"));
                    }
                }
            }
        }
        Err(anyhow::Error::msg("Invalid key"))
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn aes_session_works() {
        // let mut key = [0u8; 32];
        // let mut target = [0u8; 32];

        // OsRng.fill_bytes(&mut key);
        // OsRng.fill_bytes(&mut target);
        // assert_ne!(key, target);

        // assert!(wrap_key_256(base64url_encode(&key[1..]).as_str(), target).is_err());
        // assert!(unwrap_key_256(
        //     base64url_encode(&key[1..]).as_str(),
        //     base64url_encode(&target).as_str()
        // )
        // .is_err());
        // assert!(unwrap_key_256(
        //     base64url_encode(&key).as_str(),
        //     base64url_encode(&target[1..]).as_str()
        // )
        // .is_err());

        // let key = base64url_encode(&key);
        // let wrapped_key = wrap_key_256(&key, target).unwrap();
        // let unwrapped_key = unwrap_key_256(&key, &wrapped_key).unwrap();
        // assert_eq!(unwrapped_key, target);
    }
}
