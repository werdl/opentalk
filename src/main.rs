use rand::thread_rng;

pub mod chain;
pub mod otrsa;
pub mod otaes;
pub mod net;

use otrsa::*;
use net::interlude::*;

use tokio::runtime::Runtime;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

fn main() {
    // if the first argument is "server", run the server
    if std::env::args().nth(1).unwrap() == "server" {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let listener = TcpListener::bind("localhost:8080").await.unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (key, _) = net::server_handshake(stream).await;

            println!("{:?}", key);
        });
    } else {
        // if the first argument is "client", run the client
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let stream = TcpStream::connect("localhost:8080").await.unwrap();
            let (key, _) = net::client_handshake(stream).await;

            println!("{:?}", key);
        });
    }
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

        let signature = private.rsa_sign(&message.get_bytes());

        assert!(public.rsa_verify(&message.get_bytes(), &signature));
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

                println!("{:?}", key);

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

                println!("{:?}", key);

                assert_eq!(key.len(), 16);
            });
        }
    }

    mod keys {
        use crate::chain::{BasicData, Block};

        use super::*;
        use otrsa::generate_keypair;
        #[test]
        fn new_pubkey() {
            let rng = &mut thread_rng();
            let (private, public) = generate_keypair(rng, 2048);

            let basic_data = BasicData::new("round".to_string(), "handle".to_string(), &private);

            let block = Block::new_pubkey(public, basic_data);

            assert!(block.verify(vec![]));
        }
    }

    #[cfg(test)]
    mod chain {
        use crate::chain::{BasicData, Block, ValidChain};

        use super::*;
        use otrsa::generate_keypair;

        #[test]
        fn basic_data() {
            let rng = &mut thread_rng();
            let (private, public) = generate_keypair(rng, 2048);

            let basic_data = BasicData::new("round".to_string(), "handle".to_string(), &private);

            assert!(basic_data.verify(&public));
        }

        #[test]
        fn chain_continuation() {
            let rng = &mut thread_rng();

            let (private, public) = generate_keypair(rng, 2048);

            let (private2, public2) = generate_keypair(rng, 2048);

            let basic_data = BasicData::new("round".to_string(), "handle".to_string(), &private);

            let block = Block::new_pubkey(public.clone(), basic_data.clone());

            let block2 = Block::new_message("hello".to_string(), private, basic_data.clone());

            let block3 = Block::new_ack(basic_data.clone());

            let block4 = Block::new_pubkey(public2, basic_data.clone());


            assert!(vec![block.clone()].check_validity(vec![block, block2, block3, block4]))
        }
    }
}