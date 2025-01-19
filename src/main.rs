use rand::thread_rng;

pub mod chain;
pub mod otrsa;
pub mod net;

use otrsa::interlude::*;

fn main() {
   
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let rng = &mut thread_rng();

        let (private, public) = otrsa::generate_keypair(rng, 2048);

        let message = "Hello, World!".to_string();

        let encrypted = public.rsa_encrypt(message.clone());

        let decrypted = private.rsa_decrypt(&encrypted);

        assert_eq!(message, String::from_utf8(decrypted).unwrap());
    }

    #[test]
    fn test_signing_verification() {
        let rng = &mut thread_rng();

        let (private, public) = otrsa::generate_keypair(rng, 2048);

        let message = "Hello, World!".to_string();

        let signature = private.rsa_sign(&message.bytes());

        assert!(public.rsa_verify(&message.bytes(), &signature));
    }
}