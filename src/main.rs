pub mod chain;
pub mod otrsa;
pub mod otaes;
pub mod net;

use std::io::BufRead;
use std::io::Read;
use std::net::TcpListener;
use std::net::TcpStream;

use chain::BasicData;
use chain::Block;
// used in test submodules
#[allow(unused_imports)]
use rand::thread_rng;
#[allow(unused_imports)]
use otrsa::*;
#[allow(unused_imports)]
use net::*;

fn main() {
    // our keys
    let rng = &mut thread_rng();
    let (private, public) = otrsa::generate_keypair(rng, 2048);

    let (tx, rx) = std::sync::mpsc::channel();

    let private_clone = private.clone();
    std::thread::spawn(move || {
        listen("localhost:8080".to_string(), (public, private_clone), "test_server".to_string(), "ot_test.json", rx);
    });

    // now lets talk to the others
    std::thread::spawn(move || {
        let stream = TcpStream::connect("localhost:8080").unwrap();
        let (key, stream) = client_handshake(stream);
        loop {}
    }

    );

    println!("Listening on localhost:8080");



    // everytime the user prints a newline, send a Message block
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        println!("{}", line);
        
        let message = Block::new_message(line, private.clone(), BasicData::new("round".to_string(), "test_server".to_string(), &private));

        tx.send(message.to_json().unwrap()).unwrap();
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

        let signature = private.rsa_sign(message.as_bytes());

        assert!(public.rsa_verify(&message.as_bytes(), &signature));
    }

    #[cfg(test)]
    mod net {
        use super::*;
        use tokio::runtime::Runtime;
        use std::net::TcpListener;
        use std::net::TcpStream;

        #[test]
        fn handshake() {
            // wait for connections, then handshake
            let rt = Runtime::new().unwrap();

            rt.spawn(async {
                let stream = TcpStream::connect("localhost:8080").unwrap();
                let (key, _) = net::client_handshake(stream);

                println!("{:?}", key);

                assert_eq!(key.len(), 16);
            });

            rt.block_on(async {
                let listener = TcpListener::bind("localhost:8080").unwrap();
                let (stream, _) = listener.accept().unwrap();
                let (key, _) = net::server_handshake(stream);

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

            let (_private2, public2) = generate_keypair(rng, 2048);

            let basic_data = BasicData::new("round".to_string(), "handle".to_string(), &private);

            let block = Block::new_pubkey(public.clone(), basic_data.clone());

            let block2 = Block::new_message("hello".to_string(), private, basic_data.clone());

            let block3 = Block::new_ack(basic_data.clone());

            let block4 = Block::new_pubkey(public2, basic_data.clone());


            assert!(!vec![block.clone()].check_validity(vec![block, block2, block3, block4]))
        }
    }
}