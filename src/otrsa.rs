/// an abstraction over the RSA crate
use rsa::{traits::PaddingScheme, Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;

pub mod interlude {
    pub use super::{Bytes, HexDigest, PrivKey, PubKey};
}

pub trait PubKey {
    fn rsa_encrypt(&self, message: String) -> Vec<u8>;
    fn rsa_verify(&self, original_message: &[u8], signature: &[u8]) -> bool;
}

pub trait PrivKey {
    fn rsa_decrypt(&self, encrypted_message: &[u8]) -> Vec<u8>;
    fn rsa_sign(&self, message: &[u8]) -> Vec<u8>;
}

pub trait HexDigest {
    fn hex(&self) -> String;
}

pub trait Bytes {
    fn bytes(&self) -> Vec<u8>;
}

impl PubKey for RsaPublicKey {
    fn rsa_encrypt(&self, message: String) -> Vec<u8> {
        let mut rng = OsRng;
        self.encrypt(&mut rng, Pkcs1v15Encrypt, message.as_bytes()).unwrap()
    }

    fn rsa_verify(&self, original_message: &[u8], signature: &[u8]) -> bool {
        self.verify(Pkcs1v15Sign::new_unprefixed(), original_message, signature).is_ok()
    }
}

impl PrivKey for RsaPrivateKey {
    fn rsa_decrypt(&self, encrypted_message: &[u8]) -> Vec<u8> {
        self.decrypt(Pkcs1v15Encrypt, encrypted_message).unwrap()
    }

    fn rsa_sign(&self, message: &[u8]) -> Vec<u8> {
        self.sign(Pkcs1v15Sign::new_unprefixed(), message).unwrap()
    }
}

impl HexDigest for Vec<u8> {
    fn hex(&self) -> String {
        hex::encode(self)
    }
}

impl Bytes for String {
    fn bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

pub fn generate_keypair(rng: &mut rand::rngs::ThreadRng, bits: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let private_key = RsaPrivateKey::new(rng, bits).unwrap();
    let public_key = private_key.to_public_key();
    (private_key, public_key)
}