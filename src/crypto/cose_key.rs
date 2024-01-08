use ciborium::Value;
use coset::{
    iana, CborSerializable, CoseKey, CoseKeyBuilder, KeyType, Label, RegisteredLabelWithPrivate,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};

const KEY_PARAM_K: Label = Label::Int(iana::SymmetricKeyParameter::K as i64);
const KEY_PARAM_D: Label = Label::Int(iana::OkpKeyParameter::D as i64);
const KEY_PARAM_X: Label = Label::Int(iana::OkpKeyParameter::X as i64);

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Key(pub CoseKey);

impl Key {
    pub fn new_sym(alg: iana::Algorithm, kid: &[u8]) -> anyhow::Result<Self> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let mut key = CoseKeyBuilder::new_symmetric_key(key.to_vec()).algorithm(alg);
        if !kid.is_empty() {
            key = key.key_id(kid.to_vec());
        }
        Ok(Self(key.build()))
    }

    pub fn new_ed25519(kid: &[u8]) -> anyhow::Result<Self> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Key::ed25519(key, kid)
    }

    pub fn ed25519(priv_key: [u8; 32], kid: &[u8]) -> anyhow::Result<Self> {
        let mut key = CoseKeyBuilder::new_okp_key()
            .algorithm(iana::Algorithm::EdDSA)
            .param(
                iana::OkpKeyParameter::Crv as i64,
                Value::from(iana::EllipticCurve::Ed25519 as i64),
            )
            .param(
                iana::OkpKeyParameter::D as i64,
                Value::Bytes(priv_key.to_vec()),
            );

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
        let key_label = match self.0.kty {
            KeyType::Assigned(iana::KeyType::Symmetric) => &KEY_PARAM_K,
            KeyType::Assigned(iana::KeyType::OKP) => &KEY_PARAM_D,
            _ => {
                return Err(anyhow::Error::msg("Unsupport key type"));
            }
        };

        let data = self.get_bytes(key_label)?;
        if data.len() != 32 {
            return Err(anyhow::Error::msg("Invalid key length, expected 32"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(data);
        Ok(key)
    }

    pub fn get_public(&self) -> anyhow::Result<[u8; 32]> {
        let key_label = match self.0.kty {
            KeyType::Assigned(iana::KeyType::OKP) => &KEY_PARAM_X,
            _ => {
                return Err(anyhow::Error::msg("Unsupport key type"));
            }
        };
        let data = self.get_bytes(key_label)?;
        if data.len() != 32 {
            return Err(anyhow::Error::msg("Invalid key length, expected 32"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(data);
        Ok(key)
    }

    fn get_bytes(&self, key_label: &Label) -> anyhow::Result<&Vec<u8>> {
        for (label, value) in &self.0.params {
            if label == key_label {
                match value {
                    Value::Bytes(val) => {
                        return Ok(val);
                    }
                    _ => {
                        return Err(anyhow::Error::msg("value is not bytes"));
                    }
                }
            }
        }
        Err(anyhow::Error::msg("not found"))
    }

    fn get_bool(&self, key_label: &Label) -> anyhow::Result<bool> {
        for (label, value) in &self.0.params {
            if label == key_label {
                match value {
                    Value::Bool(val) => {
                        return Ok(*val);
                    }
                    _ => {
                        return Err(anyhow::Error::msg("value is not bool"));
                    }
                }
            }
        }
        Err(anyhow::anyhow!("key {:?} not found", key_label))
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        match self.0.alg.clone().unwrap_or_default() {
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::EdDSA) => {
                let sig = ed25519_dalek::Signature::from_slice(signature)?;
                let verifying_key = VerifyingKey::from_bytes(&self.get_public()?)?;
                verifying_key.verify_strict(message, &sig)?;
            }
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256) => {
                use p256::{
                    ecdsa::{signature::Verifier, Signature, VerifyingKey},
                    elliptic_curve::generic_array::GenericArray,
                    EncodedPoint,
                };
                let x = self.get_bytes(&Label::Int(iana::Ec2KeyParameter::X as i64))?;
                let mut y = Vec::new();
                match self.get_bytes(&Label::Int(iana::Ec2KeyParameter::Y as i64)) {
                    Ok(v) => y.extend_from_slice(v),
                    Err(_) => {
                        let y_sign = self.get_bool(&Label::Int(iana::Ec2KeyParameter::Y as i64))?;
                        if y_sign {
                            y.push(3);
                        } else {
                            y.push(2);
                        }
                    }
                };
                let point = EncodedPoint::from_affine_coordinates(
                    GenericArray::from_slice(x),
                    GenericArray::from_slice(&y),
                    y.len() == 1,
                );
                let verifying_key = VerifyingKey::from_encoded_point(&point)?;
                // ES256 der signature in passkey
                let sig = match Signature::from_der(signature) {
                    Ok(sig) => sig,
                    Err(_) => Signature::from_slice(signature)?,
                };
                verifying_key.verify(message, &sig)?;
            }
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::RS256) => {
                use rsa::{
                    pkcs1v15::{Signature, VerifyingKey},
                    sha2::Sha256,
                    signature::Verifier,
                    BigUint, RsaPublicKey,
                };

                let sig = Signature::try_from(signature)?;

                let n = self.get_bytes(&Label::Int(iana::RsaKeyParameter::N as i64))?;
                let e = self.get_bytes(&Label::Int(iana::RsaKeyParameter::E as i64))?;
                let verifying_key = VerifyingKey::<Sha256>::new(RsaPublicKey::new(
                    BigUint::from_bytes_be(n),
                    BigUint::from_bytes_be(e),
                )?);
                verifying_key.verify(message, &sig)?;
            }
            alg => {
                return Err(anyhow::anyhow!(
                    "invalid cose key: unsupport algorithm {:?}",
                    alg
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn key_works() {}
}
