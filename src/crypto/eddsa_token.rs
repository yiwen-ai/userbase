use coset::{
    cwt::{ClaimsSet, Timestamp},
    iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder,
};
use ed25519_dalek::{Signature, Signer, SigningKey};
use std::str::FromStr;

use axum_web::context::unix_ms;

const CLOCK_SKEW: i64 = 5 * 60; // 5 minutes

pub struct Cwt {
    kid: Vec<u8>,
    signing: SigningKey,
}

impl Cwt {
    pub fn new(secret_key: [u8; 32], kid: &[u8]) -> Self {
        Self {
            kid: kid.to_vec(),
            signing: SigningKey::from_bytes(&secret_key),
        }
    }

    pub fn sign(&self, token: Token, aad: &[u8]) -> anyhow::Result<Vec<u8>> {
        let payload = token.to().to_vec().map_err(anyhow::Error::msg)?;
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(self.kid.clone())
            .build();

        CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(aad, |data| self.sign_data(data))
            .build()
            .to_vec()
            .map_err(anyhow::Error::msg)
    }

    pub fn verify(&self, sign1_token: &[u8], aad: &[u8]) -> anyhow::Result<Token> {
        let cs1 = CoseSign1::from_slice(sign1_token).map_err(anyhow::Error::msg)?;
        cs1.verify_signature(aad, |sig, data| self.verify_data(sig, data))?;
        let cs =
            ClaimsSet::from_slice(&cs1.payload.unwrap_or_default()).map_err(anyhow::Error::msg)?;
        Token::from(cs)
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
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub iss: String,
    pub user: xid::Id, // sub (Subject) Claim
    pub app: xid::Id,  // aud (Audience) Claim
    pub exp: i64,      // exp (Expiration Time) Claim
    pub nbf: i64,      // nbf (Not Before) Claim
    pub iat: i64,      // iat (Issued At) Claim
    pub sid: xid::Id,  // cti (CWT ID) Claim
}

impl Token {
    pub fn from(cwt: ClaimsSet) -> anyhow::Result<Self> {
        Ok(Self {
            iss: cwt.issuer.unwrap_or_default(),
            user: xid::Id::from_str(cwt.subject.unwrap_or_default().as_str())?,
            app: xid::Id::from_str(cwt.audience.unwrap_or_default().as_str())?,
            exp: cwt.expiration_time.map_or(0, unwrap_timestamp),
            nbf: cwt.not_before.map_or(0, unwrap_timestamp),
            iat: cwt.issued_at.map_or(0, unwrap_timestamp),
            sid: unwrap_bytes(cwt.cwt_id.unwrap_or_default())?,
        })
    }

    pub fn to(&self) -> ClaimsSet {
        ClaimsSet {
            issuer: Some(self.iss.clone()),
            subject: Some(self.user.to_string()),
            audience: Some(self.app.to_string()),
            expiration_time: Some(Timestamp::WholeSeconds(self.exp)),
            not_before: if self.nbf > 0 {
                Some(Timestamp::WholeSeconds(self.nbf))
            } else {
                None
            },
            issued_at: Some(Timestamp::WholeSeconds(self.iat)),
            cwt_id: Some(self.sid.as_bytes().to_vec()),
            rest: Vec::new(),
        }
    }

    pub fn validate(&self, expected_iss: String, expected_aud: xid::Id) -> anyhow::Result<()> {
        if self.iss != expected_iss {
            return Err(anyhow::Error::msg(format!(
                "invalid issuer, expected {}, got {}",
                expected_iss, self.iss
            )));
        }

        if self.app != expected_aud {
            return Err(anyhow::Error::msg(format!(
                "invalid audience, expected {}, got {}",
                expected_aud, self.app
            )));
        }

        let now = unix_ms() as i64;
        if self.exp < now - CLOCK_SKEW {
            return Err(anyhow::Error::msg("token expired"));
        }

        if self.nbf > 0 && self.nbf > now + CLOCK_SKEW {
            return Err(anyhow::Error::msg("token not yet valid"));
        }
        Ok(())
    }
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

        let cwt = Cwt::new(key, b"yw01");
        let now = unix_ms() as i64;
        let token = Token {
            iss: "yiwen.ai".to_string(),
            user: xid::new(),
            app: xid::new(),
            exp: now + 3600 * 2,
            nbf: 0,
            iat: now,
            sid: xid::new(),
        };

        let signed = cwt.sign(token.clone(), b"yiwen.ai").unwrap();
        println!("signed: {}, {}", signed.len(), hex_string(&signed));

        let token2 = cwt.verify(&signed, b"yiwen.ai").unwrap();
        assert_eq!(token, token2);
    }
}
