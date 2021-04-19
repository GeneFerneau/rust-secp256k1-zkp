use zeroize::Zeroize;

use crate::{ffi, Error, Secp256k1, Signature};
use crate::key::{PublicKey, SecretKey};

#[derive(Debug, Eq, PartialEq)]
pub struct FischlinProof(*mut ffi::FischlinProof);

impl FischlinProof {
    pub fn new() -> Result<Self, Error> {
        let ptr = unsafe { ffi::secp256k1_fischlin_proof_create() };
        if ptr == core::ptr::null_mut() {
            Err(Error::InvalidFischlinProof)
        } else {
            Ok(Self(ptr))
        }
    }

    pub fn as_ptr(&self) -> *const ffi::FischlinProof {
        self.0
    }

    pub fn as_mut_ptr(&mut self) -> *mut ffi::FischlinProof {
        self.0
    }

    pub fn prove(&mut self, secp: &Secp256k1, seckey: &SecretKey, vs: &[[u8; 32]; ffi::SECP256K1_FISCHLIN_ROUNDS]) -> Result<(), Error> {
        let r = unsafe { ffi::secp256k1_fischlin_prove(secp.ctx, self.as_mut_ptr(), seckey.as_ptr(), vs as *const _) };
        if r == 0 {
            Err(Error::InvalidFischlinProof)
        } else {
            Ok(())
        }
    }

    pub fn verify(&mut self, secp: &Secp256k1, pubkey: &PublicKey) -> Result<bool, Error> {
        let mut ret = 0;
        let r = unsafe { ffi::secp256k1_fischlin_verify(secp.ctx, &mut ret as *mut _, pubkey.as_ptr(), self.as_ptr()) };
        if r == 0 {
            Err(Error::InvalidFischlinProof)
        } else {
            Ok(ret == 1)
        }
    }
}

impl Drop for FischlinProof {
    fn drop(&mut self) {
        let _ret = unsafe { ffi::secp256k1_fischlin_proof_destroy(self.as_mut_ptr()) };
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcdsaPreSignature(*mut ffi::EcdsaPreSignature);

impl EcdsaPreSignature {
    pub fn new() -> Self {
        Self(unsafe { ffi::secp256k1_ecdsa_pre_signature_create() })
    }

    pub fn as_ptr(&self) -> *const ffi::EcdsaPreSignature {
        self.0
    }

    pub fn as_mut_ptr(&mut self) -> *mut ffi::EcdsaPreSignature {
        self.0
    }

    /// Create an ECDSA adaptor signature by pre-signing a message
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1zkp::{Secp256k1, ecdsa_adaptor::{EcdsaPreSignature, FischlinProof}};
    /// # use rand::{thread_rng, Rng};
    ///
    /// let mut rng = thread_rng();
    ///
    /// let s = Secp256k1::new();
    /// let (ysk, ypk) = s.generate_keypair(&mut rng).unwrap();
    /// let (xsk, xpk) = s.generate_keypair(&mut rng).unwrap();
    /// let (ksk, _) = s.generate_keypair(&mut rng).unwrap();
    /// let (rand, _) = s.generate_keypair(&mut rng).unwrap();
    ///
    /// let mut vs = [[0; 32]; ffi::SECP256K1_FISCHLIN_ROUNDS];
    /// for v in vs.iter_mut() {
    ///     rng.fill(&mut v[2..]);
    /// }
    ///
    /// let mut proof = FischlinProof::new().unwrap();
    /// proof.prove(&s, &ysk, &vs).unwrap();
    /// assert!(proof.verify(&s, &ypk).unwrap());
    ///
    /// let msg = b"SOME_BTC_SCRIPT";
    ///
    /// let mut pre_sig = EcdsaPreSignature::new();
    /// pre_sig.sign(&s, msg.as_ref(), &ypk, &proof, &xsk, &ksk, &rand).unwrap();
    /// ```
    pub fn sign(
        &mut self,
        secp: &Secp256k1,
        msg: &[u8],
        ypk: &PublicKey,
        y_proof: &FischlinProof,
        xsk: &SecretKey,
        ksk: &SecretKey,
        rand: &SecretKey,
    ) -> Result<(), Error> {
        let ret = unsafe {
            ffi::secp256k1_ecdsa_pre_sign(
                secp.ctx,
                self.as_mut_ptr(),
                msg.as_ptr(),
                msg.len(),
                ypk.as_ptr(), 
                y_proof.as_ptr(),
                xsk.as_ptr(),
                ksk.as_ptr(),
                rand.as_ptr()
            )
        };
        if ret == 0 {
            Err(Error::InvalidSignature)
        } else {
            Ok(())
        }
    }

    /// Verify an ECDSA adaptor signature over a message
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1zkp::{Secp256k1, ecdsa_adaptor::{EcdsaPreSignature, FischlinProof}};
    /// # use rand::{thread_rng, Rng};
    ///
    /// let mut rng = thread_rng();
    ///
    /// let s = Secp256k1::new();
    /// let (ysk, ypk) = s.generate_keypair(&mut rng).unwrap();
    /// let (xsk, xpk) = s.generate_keypair(&mut rng).unwrap();
    /// let (ksk, _) = s.generate_keypair(&mut rng).unwrap();
    /// let (rand, _) = s.generate_keypair(&mut rng).unwrap();
    ///
    /// let mut vs = [[0; 32]; ffi::SECP256K1_FISCHLIN_ROUNDS];
    /// for v in vs.iter_mut() {
    ///     rng.fill(&mut v[2..]);
    /// }
    ///
    /// let mut proof = FischlinProof::new().unwrap();
    /// proof.prove(&s, &ysk, &vs).unwrap();
    /// assert!(proof.verify(&s, &ypk).unwrap());
    ///
    /// let msg = b"SOME_BTC_SCRIPT";
    ///
    /// let mut pre_sig = EcdsaPreSignature::new();
    /// pre_sig.sign(&s, msg.as_ref(), &ypk, &proof, &xsk, &ksk, &rand).unwrap();
    /// assert!(pre_sig.verify(&s, msg.as_ref(), &ypk, &proof, &xpk).unwrap());
    /// ```
    pub fn verify(
        &self,
        secp: &Secp256k1,
        msg: &[u8],
        ypk: &PublicKey,
        y_proof: &FischlinProof,
        xpk: &PublicKey,
    ) -> Result<bool, Error> {
        let mut valid = 0;
        let ret = unsafe {
            ffi::secp256k1_ecdsa_pre_verify(
                secp.ctx,
                &mut valid as *mut _,
                msg.as_ptr(),
                msg.len(),
                ypk.as_ptr(),
                y_proof.as_ptr(),
                xpk.as_ptr(),
                self.as_ptr()
            )
        };
        if ret == 0 {
            Err(Error::InvalidSignature)
        } else {
            Ok(valid == 1)
        }
    }

    /// Adapt an ECDSA adaptor signature into a full ECDSA signature
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1zkp::{Secp256k1, ecdsa_adaptor::{EcdsaPreSignature, FischlinProof}};
    /// # use rand::{thread_rng, Rng};
    ///
    /// let mut rng = thread_rng();
    ///
    /// let s = Secp256k1::new();
    /// let (ysk, ypk) = s.generate_keypair(&mut rng).unwrap();
    /// let (xsk, xpk) = s.generate_keypair(&mut rng).unwrap();
    /// let (ksk, _) = s.generate_keypair(&mut rng).unwrap();
    /// let (rand, _) = s.generate_keypair(&mut rng).unwrap();
    ///
    /// let mut vs = [[0; 32]; ffi::SECP256K1_FISCHLIN_ROUNDS];
    /// for v in vs.iter_mut() {
    ///     rng.fill(&mut v[2..]);
    /// }
    ///
    /// let mut proof = FischlinProof::new().unwrap();
    /// proof.prove(&s, &ysk, &vs).unwrap();
    /// assert!(proof.verify(&s, &ypk).unwrap());
    ///
    /// let msg = b"SOME_BTC_SCRIPT";
    ///
    /// let mut pre_sig = EcdsaPreSignature::new();
    /// pre_sig.sign(&s, msg.as_ref(), &ypk, &proof, &xsk, &ksk, &rand).unwrap();
    /// assert!(pre_sig.verify(&s, msg.as_ref(), &ypk, &proof, &xpk).unwrap());
    /// let sig = pre_sig.adapt(&ysk).unwrap();
    /// ```
    pub fn adapt(
        &self,
        ysk: &SecretKey,
    ) -> Result<Signature, Error> {
        let mut sig = ffi::Signature::new();
        let ret = unsafe { ffi::secp256k1_ecdsa_adapt(&mut sig as *mut _, self.as_ptr(), ysk.as_ptr()) };
        if ret == 0 {
            Err(Error::InvalidSignature)
        } else {
            Ok(Signature(sig))
        }
    }

    /// Extract a witness from an ECDSA adaptor signature and a full ECDSA signature
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1zkp::{Secp256k1, ecdsa_adaptor::{EcdsaPreSignature, FischlinProof}};
    /// # use rand::{thread_rng, Rng};
    ///
    /// let mut rng = thread_rng();
    ///
    /// let s = Secp256k1::new();
    /// let (ysk, ypk) = s.generate_keypair(&mut rng).unwrap();
    /// let (xsk, xpk) = s.generate_keypair(&mut rng).unwrap();
    /// let (ksk, _) = s.generate_keypair(&mut rng).unwrap();
    /// let (rand, _) = s.generate_keypair(&mut rng).unwrap();
    ///
    /// let mut vs = [[0; 32]; ffi::SECP256K1_FISCHLIN_ROUNDS];
    /// for v in vs.iter_mut() {
    ///     rng.fill(&mut v[2..]);
    /// }
    ///
    /// let mut proof = FischlinProof::new().unwrap();
    /// proof.prove(&s, &ysk, &vs).unwrap();
    /// assert!(proof.verify(&s, &ypk).unwrap());
    ///
    /// let msg = b"SOME_BTC_SCRIPT";
    ///
    /// let mut pre_sig = EcdsaPreSignature::new();
    /// pre_sig.sign(&s, msg.as_ref(), &ypk, &proof, &xsk, &ksk, &rand).unwrap();
    /// assert!(pre_sig.verify(&s, msg.as_ref(), &ypk, &proof, &xpk).unwrap());
    /// let sig = pre_sig.adapt(&ysk).unwrap();
    /// let ext_y = pre_sig.extract(&s, &sig, &proof).unwrap();
    /// assert_eq!(ysk, ext_y);
    /// ```
    pub fn extract(
        &self,
        secp: &Secp256k1,
        sig: &Signature,
        y_proof: &FischlinProof,
    ) -> Result<SecretKey, Error> {
        let mut ysk = [0; 32];
        let ret = unsafe {
            ffi::secp256k1_ecdsa_extract(
                secp.ctx,
                ysk.as_mut_ptr(),
                sig.as_ptr(),
                self.as_ptr(),
                y_proof.as_ptr()
            )
        };

        if ret == 0 {
            ysk.zeroize();
            Err(Error::InvalidSignature)
        } else if let Ok(y) = SecretKey::from_slice(secp, &ysk) {
            ysk.zeroize();
            Ok(y)
        } else {
            ysk.zeroize();
            Err(Error::InvalidSignature)
        }
    }
}

impl Drop for EcdsaPreSignature {
    fn drop(&mut self) {
        unsafe { ffi::secp256k1_ecdsa_pre_signature_destroy(self.as_mut_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use crate::Secp256k1;

    #[test]
    fn test_fischlin_prove_and_verify() {
        let mut rng = thread_rng();

        let s = Secp256k1::new();
        let (sk, pk) = s.generate_keypair(&mut rng).unwrap();
        let mut vs = [[0; 32]; ffi::SECP256K1_FISCHLIN_ROUNDS];
        for v in vs.iter_mut() {
            rng.fill(&mut v[2..]);
        }
        let mut proof = FischlinProof::new().unwrap();

        proof.prove(&s, &sk, &vs).unwrap();
        assert!(proof.verify(&s, &pk).unwrap());
    }

    #[test]
    fn test_ecdsa_pre_sign_and_verify() {
        let mut rng = thread_rng();

        let s = Secp256k1::new();
        let (ysk, ypk) = s.generate_keypair(&mut rng).unwrap();
        let (xsk, xpk) = s.generate_keypair(&mut rng).unwrap();
        let (ksk, _) = s.generate_keypair(&mut rng).unwrap();
        let (rand, _) = s.generate_keypair(&mut rng).unwrap();

        let mut vs = [[0; 32]; ffi::SECP256K1_FISCHLIN_ROUNDS];
        for v in vs.iter_mut() {
            rng.fill(&mut v[2..]);
        }
        let mut proof = FischlinProof::new().unwrap();

        proof.prove(&s, &ysk, &vs).unwrap();
        assert!(proof.verify(&s, &ypk).unwrap());

        let msg = b"SOME_BTC_SCRIPT";

        let mut pre_sig = EcdsaPreSignature::new();
        pre_sig.sign(&s, msg.as_ref(), &ypk, &proof, &xsk, &ksk, &rand).unwrap();
        assert!(pre_sig.verify(&s, msg.as_ref(), &ypk, &proof, &xpk).unwrap());
    }

    #[test]
    fn test_ecdsa_adapt_and_extract() {
        let mut rng = thread_rng();

        let s = Secp256k1::new();
        let (ysk, ypk) = s.generate_keypair(&mut rng).unwrap();
        let (xsk, xpk) = s.generate_keypair(&mut rng).unwrap();
        let (ksk, _) = s.generate_keypair(&mut rng).unwrap();
        let (rand, _) = s.generate_keypair(&mut rng).unwrap();

        let mut vs = [[0; 32]; ffi::SECP256K1_FISCHLIN_ROUNDS];
        for v in vs.iter_mut() {
            rng.fill(&mut v[2..]);
        }
        let mut proof = FischlinProof::new().unwrap();

        proof.prove(&s, &ysk, &vs).unwrap();
        assert!(proof.verify(&s, &ypk).unwrap());

        let msg = b"SOME_BTC_SCRIPT";

        let mut pre_sig = EcdsaPreSignature::new();
        pre_sig.sign(&s, msg.as_ref(), &ypk, &proof, &xsk, &ksk, &rand).unwrap();
        assert!(pre_sig.verify(&s, msg.as_ref(), &ypk, &proof, &xpk).unwrap());

        let sig = pre_sig.adapt(&ysk).unwrap();
        let ext_y = pre_sig.extract(&s, &sig, &proof).unwrap();
        assert_eq!(ysk, ext_y);
    }
}
