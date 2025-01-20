use openssl::symm::{Cipher, Crypter, Mode};
use openssl::rand::rand_bytes;

pub trait AesKey {
    /// Encrypt the message and return both the encrypted message and the IV in the form (encrypted_message, iv)
    fn aes_encrypt(&self, message: String) -> (Vec<u8>, Vec<u8>);

    /// Decrypt the message using the provided encrypted message and IV
    fn aes_decrypt(&self, encrypted_message: &[u8], iv: &[u8]) -> Vec<u8>;
}

impl AesKey for [u8; 16] {
    fn aes_encrypt(&self, message: String) -> (Vec<u8>, Vec<u8>) {
        // Generate a random IV (16 bytes for AES-128)
        let mut iv = vec![0u8; 16];
        rand_bytes(&mut iv).unwrap();

        // Set up the cipher for AES-128 CBC mode
        let cipher = Cipher::aes_128_cbc();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, self, Some(&iv)).unwrap();
        let mut encrypted_message = vec![0; message.len() + cipher.block_size()];
        
        // Encrypt the message
        let count = crypter.update(message.as_bytes(), &mut encrypted_message).unwrap();
        let rest = crypter.finalize(&mut encrypted_message[count..]).unwrap();
        
        // Truncate the buffer to the correct size
        encrypted_message.truncate(count + rest);

        // Return both the encrypted message and the IV
        (encrypted_message, iv)
    }

    fn aes_decrypt(&self, encrypted_message: &[u8], iv: &[u8]) -> Vec<u8> {
        // Set up the cipher for AES-128 CBC mode
        let cipher = Cipher::aes_128_cbc();
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, self, Some(iv)).unwrap();
        let mut decrypted_message = vec![0; encrypted_message.len() + cipher.block_size()];
        
        // Decrypt the message
        let count = crypter.update(encrypted_message, &mut decrypted_message).unwrap();
        let rest = crypter.finalize(&mut decrypted_message[count..]).unwrap();
        
        // Truncate the buffer to the correct size
        decrypted_message.truncate(count + rest);

        decrypted_message
    }
}
