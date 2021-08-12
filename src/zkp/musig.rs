//! # MuSig
//! Support for MuSig multisignature protocol

use ffi::{self, CPtr};
use {PublicKey, Secp256k1, SecretKey};
use {Error};
use {Message, Signing};

#[derive(Debug, PartialEq, Eq)]
pub struct MusigPreSession(ffi::MusigPreSession);

impl CPtr for MusigPreSession {
    type Target = ffi::MusigPreSession;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigPreSession {
    pub fn new() -> Self {
        Self(ffi::MusigPreSession::new())
    }

    pub fn as_ptr(&self) -> *const ffi::MusigPreSession {
        &self.0
    }

    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigPreSession {
        &mut self.0
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct MusigSession(ffi::MusigSession);

impl CPtr for MusigSession {
    type Target = ffi::MusigSession;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigSession {
    pub fn new<C: Signing>(
        secp: &Secp256k1<C>,
        signers: &mut [MusigSessionSignerData],
        nonce_commitment: &mut [u8; 32],
        session_id: &[u8; 32],
        msg: &Message,
        combined_pk: &PublicKey,
        pre_session: &MusigPreSession,
        seckey: &SecretKey,
    ) -> Result<Self, Error> {
        unsafe {
            let mut s = ffi::MusigSession::new();
            let (xonly, _) = ffi::xonly_from_pubkey(*secp.ctx(), combined_pk.as_ptr());

            if ffi::secp256k1_musig_session_init(
                *secp.ctx(),
                &mut s as *mut _,
                signers.as_mut_ptr() as *mut _,
                nonce_commitment.as_mut_ptr(),
                session_id.as_ptr(),
                msg.as_c_ptr(),
                &xonly,
                pre_session.as_ptr(),
                signers.len(),
                seckey.as_ptr(),
            ) == 0 {
                Err(Error::InvalidMusigSession)
            } else {
                Ok(Self(s))
            }
        }
    }

    pub fn as_ptr(&self) -> *const ffi::MusigSession {
        &self.0
    }

    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigSession {
        &mut self.0
    }
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct MusigSessionSignerData(ffi::MusigSessionSignerData);

impl MusigSessionSignerData {
    pub fn new() -> Self {
        unsafe { Self(ffi::MusigSessionSignerData::new()) }
    }
}

impl From<&PublicKey> for MusigSessionSignerData {
    fn from(k: &PublicKey) -> Self {
        let secp = Secp256k1::new();
        let (xonly, _) = ffi::xonly_from_pubkey(*secp.ctx(), k.as_ptr());
        Self(ffi::MusigSessionSignerData::from(xonly))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_musig_session() {
        let mut rng = thread_rng();
        let secp = Secp256k1::new();
        let mut secbytes = [0u8; 32];
        rng.fill_bytes(&mut secbytes);
        let seckey = SecretKey::from_slice(&secbytes).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &seckey);
        let msg = Message::from_slice(&[2u8; 32]).unwrap();
        let mut signers = [MusigSessionSignerData::from(&pubkey)];
        let mut nonce_commitment = [0u8; 32];
        let session_id = [0u8; 32];
        let pre_session = MusigPreSession::new();
        let _session = MusigSession::new(
            &secp,
            &mut signers,
            &mut nonce_commitment,
            &session_id,
            &msg,
            &pubkey,
            &pre_session,  
            &seckey,
        ).unwrap();
    }
}
