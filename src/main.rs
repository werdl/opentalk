use rand::thread_rng;

pub mod chain;
pub mod otrsa;
pub mod otaes;
pub mod net;

use otrsa::interlude::*;
use net::interlude::*;

use tokio::runtime::Runtime;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

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

    #[cfg(test)]
    mod net {
        use super::*;
        use tokio::runtime::Runtime;
        use tokio::net::TcpListener;
        use tokio::net::TcpStream;
        use tokio::io::{AsyncWriteExt, AsyncReadExt};

        #[test]
        fn server() {
            // wait for connections, then handshake
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let listener = TcpListener::bind("localhost:8080").await.unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                let (key, _) = net::server_handshake(stream).await;

                assert_eq!(key.len(), 16);
            });
        }

        #[test]
        fn client() {
            // connect to server, then handshake
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let stream = TcpStream::connect("localhost:8080").await.unwrap();
                let (key, _) = net::client_handshake(stream).await;

                assert_eq!(key.len(), 16);
            });
        }
    }
}