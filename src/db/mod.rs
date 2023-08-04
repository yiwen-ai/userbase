mod model_authn;
mod model_authz;
mod model_follow;
mod model_group;
mod model_member;
mod model_session;
mod model_user;

pub mod scylladb;

pub use model_authn::AuthN;
pub use model_authz::AuthZ;
pub use model_follow::Follow;
pub use model_group::{Group, GroupIndex};
pub use model_member::Member;
pub use model_session::Session;
pub use model_user::{User, UserIndex};

pub static USER_JARVIS: &str = "0000000000000jarvis0"; // system user
pub static USER_ANON: &str = "000000000000000anon0"; // anonymous user

static BASE_36: &str = "abcdefghijklmnopqrstuvwxyz0123456789";

// length ~= 11, example: oiy5nx77xci
pub fn xid_to_cn(id: &xid::Id, delta: u8) -> String {
    let id = id.as_bytes();
    let mut data = [id[11], id[10], id[9], id[0], id[1], id[2], id[3]];
    if delta > 0 {
        let x: u16 = data[2] as u16 + delta as u16;
        data[2] = if x < 256 { x as u8 } else { (x - 256) as u8 };
    }
    base_x::encode(BASE_36, &data)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    #[ignore]
    fn xid_to_cn_works() {
        assert_eq!(
            xid_to_cn(&xid::Id::from_str(USER_JARVIS).unwrap(), 0).as_str(),
            "oiy5nx77xci"
        );
        assert_eq!(
            xid_to_cn(&xid::Id::from_str(USER_ANON).unwrap(), 0).as_str(),
            "dvtzccgkw3m"
        );
        let id = xid::new();
        assert_ne!(xid_to_cn(&id, 0), xid_to_cn(&id, 1));
        assert_ne!(xid_to_cn(&id, 0), xid_to_cn(&xid::new(), 0));
    }
}
