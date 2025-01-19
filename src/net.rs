use std::any::Any;

use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task;

use crate::chain::Block;

use openssl::dh::{Dh};
use sha2::{Sha256, Digest};
use rand::Rng;

/// Perform the client's handshake and return an AES128 key
pub async fn client_handshake(mut stream: tokio::net::TcpStream) -> [u8; 16] {
    let dh_params = Dh::get_2048_224().unwrap();  // 2048 bit
    let dh_private_key = dh_params.generate_key().unwrap();
    let dh_public_key = dh_private_key.public_key().to_vec();

    stream.write_all(&dh_public_key).await.unwrap();
    println!("Client sent public key");

    let mut server_public_key = vec![0; 2048];
    stream.read_exact(&mut server_public_key).await.unwrap();
    println!("Client received server's public key");

    let server_public_key_bn = openssl::bn::BigNum::from_slice(&server_public_key).unwrap();
    let shared_secret = dh_private_key.compute_key(&server_public_key_bn).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    let hash = hasher.finalize();
    let aes_key: [u8; 16] = hash[0..16].try_into().expect("Hash length is less than 16 bytes");

    aes_key
}

/// Perform the server's handshake and return an AES128 key
pub async fn server_handshake(mut stream: tokio::net::TcpStream) -> [u8; 16] {
    // Generate Diffie-Hellman parameters and private/public keys for the server
    let dh_params = Dh::get_2048_224().unwrap();  // Use default parameters (2048-bit)
    let dh_private_key = dh_params.generate_key().unwrap();
    let dh_public_key = dh_private_key.public_key().to_vec();

    // Receive the client's public key
    let mut client_public_key = vec![0; 2048];
    stream.read_exact(&mut client_public_key).await.unwrap();
    println!("Server received client's public key");

    // Send the server's public key to the client
    stream.write_all(&dh_public_key).await.unwrap();
    println!("Server sent public key");

    // Compute the shared secret using the server's private key and client's public key
    let client_public_key_bn = openssl::bn::BigNum::from_slice(&client_public_key).unwrap();
    let shared_secret = dh_private_key.compute_key(&client_public_key_bn).unwrap();

    // Derive AES-128 key from the shared secret using SHA-256 and truncating to 16 bytes
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    let hash = hasher.finalize();
    let aes_key: [u8; 16] = hash[0..16].try_into().expect("Hash length is less than 16 bytes");

    // Return the AES-128 key derived from the shared secret
    aes_key
}


pub async fn listen(host: String) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(host).await.unwrap();

    loop {
        // Accept an incoming connection
        let (mut socket, _) = listener.accept().await?;

        // Spawn a task to handle the connection
        task::spawn(async move {
            let mut buf = [0; 1024];

            loop {
                // Read data from the socket
                match socket.read(&mut buf).await {
                    Ok(0) => {
                        // Connection was closed
                        println!("Connection closed");
                        break;
                    }
                    Ok(n) => {
                        // Print the received message
                        let msg = String::from_utf8_lossy(&buf[..n]);
                        println!("Received message: {}", msg);

                        // parse the message into a block
                        let block: Result<Block, serde_json::Error> = serde_json::from_str(&msg);

                        let result = match block {
                            Ok(block) => handle(block),
                            Err(e) => {
                                eprintln!("Failed to parse block: {}", e);
                                Some(Block::new_ping())
                            }
                        };

                        if result.is_none() {
                            break;
                        }

                        socket.write_all(result.unwrap().to_json().unwrap().as_bytes()).await.unwrap();
                    }
                    Err(e) => {
                        eprintln!("Failed to read from socket: {}", e);
                        break;
                    }
                }
            }
        });
    }
}

fn handle(block: Block) -> Option<Block> {
    match block {
        Block::PubKey(pubkey) => {
            println!("Received pubkey: {:?}", pubkey);
            None
        }
        Block::Message(message) => {
            println!("Received message: {:?}", message);
            None
        }
        Block::Ping(_) => {
            println!("Received ping");
            None
        }
        Block::Blocks(blocks) => {
            println!("Received blocks: {:?}", blocks);
            None
        }
        Block::Ack(_) => {
            println!("Received ack");
            None
        }
    }
}