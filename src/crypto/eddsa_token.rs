use aes_kw::KekAes256;
use coset::{
    cwt::{ClaimName, ClaimsSet, Timestamp},
    iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder,
};
use ed25519_dalek::{Signature, Signer, SigningKey};
use std::{ops::FnOnce, str::FromStr};

use axum_web::context::unix_ms;

const CLOCK_SKEW: i64 = 5 * 60; // 5 minutes
const CTX_KEY: i64 = iana::HEADER_PARAMETER_PRIVATE_USE_MAX - 1;

pub struct Cwt {
    iss: String,
    kid: Vec<u8>,
    aad: Vec<u8>,
    kek: KekAes256,
    signing: SigningKey,
}

impl Cwt {
    pub fn new(secret_key: [u8; 32], iss: &str, kid: &[u8], aad: &[u8]) -> Self {
        Self {
            iss: iss.to_string(),
            kid: kid.to_vec(),
            aad: aad.to_vec(),
            kek: KekAes256::from(secret_key),
            signing: SigningKey::from_bytes(&secret_key),
        }
    }

    pub fn sign(&self, token: Token) -> anyhow::Result<Vec<u8>> {
        let payload = token
            .to(|se| self.encrypt_user(&se.uid, se.status, se.rating, se.kind))
            .to_vec()
            .map_err(anyhow::Error::msg)?;
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(self.kid.clone())
            .build();

        CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(&self.aad, |data| self.sign_data(data))
            .build()
            .to_vec()
            .map_err(anyhow::Error::msg)
    }

    pub fn verify(&self, sign1_token: &[u8]) -> anyhow::Result<Token> {
        let cs1 = CoseSign1::from_slice(sign1_token).map_err(anyhow::Error::msg)?;
        cs1.verify_signature(&self.aad, |sig, data| self.verify_data(sig, data))?;
        let cs =
            ClaimsSet::from_slice(&cs1.payload.unwrap_or_default()).map_err(anyhow::Error::msg)?;
        Token::from(cs, |data| self.decrypt_user(data))
    }

    fn sign_data(&self, data: &[u8]) -> Vec<u8> {
        self.signing.sign(data).to_bytes().to_vec()
    }

    fn verify_data(&self, sig: &[u8], data: &[u8]) -> Result<(), anyhow::Error> {
        let sig = Signature::from_slice(sig)?;
        self.signing
            .verify_strict(data, &sig)
            .map_err(anyhow::Error::msg)
    }

    fn encrypt_user(&self, uid: &xid::Id, status: i8, rating: i8, kind: i8) -> Vec<u8> {
        let mut buf = [0u8; 16];
        buf[..12].copy_from_slice(uid.as_bytes());
        buf[12] = status.to_be_bytes()[0];
        buf[13] = rating.to_be_bytes()[0];
        buf[14] = kind.to_be_bytes()[0];
        self.kek.wrap_vec(&buf).unwrap()
    }

    fn decrypt_user(&self, data: &[u8]) -> anyhow::Result<(xid::Id, i8, i8, i8)> {
        let buf = self.kek.unwrap_vec(data).map_err(anyhow::Error::msg)?;
        if buf.len() != 16 {
            return Err(anyhow::Error::msg("invalid user data"));
        }
        let mut uid = [0u8; 12];
        uid.copy_from_slice(&buf[..12]);
        let status = i8::from_be_bytes([buf[12]]);
        let rating = i8::from_be_bytes([buf[13]]);
        let kind = i8::from_be_bytes([buf[14]]);
        Ok((xid::Id(uid), status, rating, kind))
    }
}

// https://www.iana.org/assignments/cwt/cwt.xhtml
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub iss: String,
    pub sub: uuid::Uuid, // sub (Subject) Claim, user
    pub aud: xid::Id,    // aud (Audience) Claim, app
    pub exp: i64,        // exp (Expiration Time) Claim
    pub nbf: i64,        // nbf (Not Before) Claim
    pub iat: i64,        // iat (Issued At) Claim
    pub sid: xid::Id,    // cti (CWT ID) Claim
    pub scope: String,   // scope Claim, ignored for now
    pub uid: xid::Id,    // key: "ctx", 24 bytes, Encrypted(uid, status, rating, kind)
    pub status: i8,
    pub rating: i8,
    pub kind: i8,
}

impl Token {
    pub fn from<F>(cwt: ClaimsSet, cipher: F) -> anyhow::Result<Self>
    where
        F: FnOnce(&[u8]) -> anyhow::Result<(xid::Id, i8, i8, i8)>,
    {
        let rt = cwt
            .rest
            .last()
            .ok_or_else(|| anyhow::Error::msg("missing ctx"))?;
        let rt = cipher(
            rt.1.as_bytes()
                .ok_or_else(|| anyhow::Error::msg("invalid ctx value"))?,
        )?;
        Ok(Self {
            iss: cwt.issuer.unwrap_or_default(),
            sub: uuid::Uuid::parse_str(cwt.subject.unwrap_or_default().as_str())?,
            aud: xid::Id::from_str(cwt.audience.unwrap_or_default().as_str())?,
            exp: cwt.expiration_time.map_or(0, unwrap_timestamp),
            nbf: cwt.not_before.map_or(0, unwrap_timestamp),
            iat: cwt.issued_at.map_or(0, unwrap_timestamp),
            sid: unwrap_bytes(cwt.cwt_id.unwrap_or_default())?,
            scope: "".to_string(),
            uid: rt.0,
            status: rt.1,
            rating: rt.2,
            kind: rt.3,
        })
    }

    pub fn to<F>(&self, cipher: F) -> ClaimsSet
    where
        F: FnOnce(&Token) -> Vec<u8>,
    {
        let rt = cipher(self);

        ClaimsSet {
            issuer: Some(self.iss.clone()),
            subject: Some(self.sub.to_string()),
            audience: Some(self.aud.to_string()),
            expiration_time: Some(Timestamp::WholeSeconds(self.exp)),
            not_before: if self.nbf > 0 {
                Some(Timestamp::WholeSeconds(self.nbf))
            } else {
                None
            },
            issued_at: Some(Timestamp::WholeSeconds(self.iat)),
            cwt_id: Some(self.sid.as_bytes().to_vec()),
            // 11: Context information of an access token ("ctx": bstr), unassigned.
            rest: vec![(
                ClaimName::PrivateUse(CTX_KEY),
                ciborium::value::Value::Bytes(rt),
            )],
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let now = (unix_ms() / 1000) as i64;
        if self.exp < now - CLOCK_SKEW {
            return Err(anyhow::Error::msg("token expired"));
        }

        if self.nbf > 0 && self.nbf > now + CLOCK_SKEW {
            return Err(anyhow::Error::msg("token not yet valid"));
        }
        Ok(())
    }
}

// TODO https://openid.net/specs/openid-connect-core-1_0.html#IDToken
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct IDToken {
    pub iss: String,
    pub sub: uuid::Uuid, // sub (Subject) Claim, user
    pub aud: xid::Id,    // aud (Audience) Claim, app
    pub exp: i64,        // exp (Expiration Time) Claim
    pub iat: i64,        // iat (Issued At) Claim
    pub auth_time: i64,
    pub nonce: String,
}

fn unwrap_timestamp(ts: Timestamp) -> i64 {
    match ts {
        Timestamp::WholeSeconds(ts) => ts,
        Timestamp::FractionalSeconds(_) => 0,
    }
}

fn unwrap_bytes(id: Vec<u8>) -> anyhow::Result<xid::Id> {
    match id.len() {
        12 => Ok(xid::Id(id.try_into().unwrap())),
        n => Err(anyhow::Error::msg(format!("invalid id length: {}", n))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use faster_hex::hex_string;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn cwt_works() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let cwt = Cwt::new(key, "https://auth.yiwen.ai", b"yw01", b"yiwen.ai");
        let now = unix_ms() as i64;
        let token = Token {
            sub: uuid::Uuid::new_v4(),
            aud: xid::new(),
            exp: now + 3600 * 2,
            iat: now,
            sid: xid::new(),
            uid: xid::new(),
            ..Default::default()
        };

        let signed = cwt.sign(token.clone()).unwrap();
        println!("signed: {}, {}", signed.len(), hex_string(&signed));

        let token2 = cwt.verify(&signed).unwrap();
        assert_eq!(token, token2);
    }
}
