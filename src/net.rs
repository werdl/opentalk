use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use base64ct::{Base64, Encoding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::chain::{BasicData, Block, BlockPersist, BlockTypes};
use crate::otaes::AesKey;

use openssl::dh::Dh;

/// Perform the client's handshake and return an AES128 key
pub fn client_handshake(mut stream: TcpStream) -> ([u8; 16], TcpStream) {
    let dh_params = Dh::get_2048_224().unwrap(); // 2048 bit
    let dh_private_key = dh_params.generate_key().unwrap();
    let dh_public_key = dh_private_key.public_key().to_vec();

    stream.write_all(&dh_public_key).unwrap();
    println!("Client sent public key");

    let mut server_public_key = vec![0; 2048];
    let n = stream.read(&mut server_public_key).unwrap();
    server_public_key.truncate(n);
    println!("Client received server's public key");

    let server_public_key_bn = openssl::bn::BigNum::from_slice(&server_public_key).unwrap();
    let shared_secret = dh_private_key.compute_key(&server_public_key_bn).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    let hash = hasher.finalize();
    let aes_key: [u8; 16] = hash[0..16]
        .try_into()
        .expect("Hash length is less than 16 bytes");

    (aes_key, stream)
}

/// Perform the server's handshake and return an AES128 key
pub fn server_handshake(mut stream: TcpStream) -> ([u8; 16], TcpStream) {
    // Generate Diffie-Hellman parameters and private/public keys for the server
    let dh_params = Dh::get_2048_224().unwrap(); // Use default parameters (2048-bit)
    let dh_private_key = dh_params.generate_key().unwrap();
    let dh_public_key = dh_private_key.public_key().to_vec();

    // Receive the client's public key
    let mut client_public_key = vec![0; 2048];
    let n = stream.read(&mut client_public_key).unwrap();
    client_public_key.truncate(n);
    println!("Server received client's public key");

    // Send the server's public key to the client
    stream.write_all(&dh_public_key).unwrap();
    println!("Server sent public key");

    // Compute the shared secret using the server's private key and client's public key
    let client_public_key_bn = openssl::bn::BigNum::from_slice(&client_public_key).unwrap();
    let shared_secret = dh_private_key.compute_key(&client_public_key_bn).unwrap();

    // Derive AES-128 key from the shared secret using SHA-256 and truncating to 16 bytes
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    let hash = hasher.finalize();
    let aes_key: [u8; 16] = hash[0..16]
        .try_into()
        .expect("Hash length is less than 16 bytes");

    // Return the AES-128 key derived from the shared secret
    (aes_key, stream)
}

/// Decrypt a message using AES-128 CBC with the provided key
pub fn decrypt_message(message: &[u8], key: &[u8; 16]) -> String {
    /*
        message is a json like so:
        {
            "iv": "iv",
            "ciphertext": "ciphertext"
        }
    */

    let json: serde_json::Value = serde_json::from_slice(message).unwrap();
    let iv = hex::decode(json["iv"].as_str().unwrap()).unwrap();
    let ciphertext = hex::decode(json["ciphertext"].as_str().unwrap()).unwrap();

    // now call otaes::AesKey::aes_decrypt
    let decrypted = key.aes_decrypt(&ciphertext, &iv);

    String::from_utf8(decrypted).unwrap()
}

/// Encrypt a message using AES-128 CBC with the provided key
pub fn encrypt_message(message: String, key: &[u8; 16]) -> Vec<u8> {
    let (encrypted, iv) = key.aes_encrypt(message);

    let json = json!({
        "iv": hex::encode(iv),
        "ciphertext": hex::encode(encrypted)
    });

    json.to_string().as_bytes().to_vec()
}

/// Listen for incoming connections and handle them
pub fn listen(
    host: String,
    keypair: (RsaPublicKey, RsaPrivateKey),
    sender: String,
    chain_path: &str,
    rx: std::sync::mpsc::Receiver<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(host)?;
    let chain = Arc::new(Mutex::new(
        <Vec<Block>>::load(chain_path).unwrap_or(Vec::new()),
    ));
    let rejected_users = Arc::new(Mutex::new(Vec::new()));
    let rx = Arc::new(Mutex::new(rx));

    for stream in listener.incoming() {
        let stream = stream?;
        let sender_clone = sender.clone();
        let keypair_clone = keypair.clone();
        let chain_clone = Arc::clone(&chain);
        let rejected_users_clone = Arc::clone(&rejected_users);
        // let rx_clone = Arc::clone(&rx_mutex);
        let rx_clone = Arc::clone(&rx);

        let (key, mut stream) = server_handshake(stream);

        thread::spawn(move || {
            looper(
                stream,
                key,
                sender_clone,
                keypair_clone,
                chain_clone,
                &mut rejected_users_clone.lock().unwrap(),
                rx_clone,
            );
        });
    }

    Ok(())
}

/// Handle the main loop of a connection. This function will listen for incoming messages, decrypt them, handle them, and send a response. It will also listen for messages on the rx channel and send them to the peer. This function will be ran by the server and client
fn looper(
    mut stream: TcpStream,
    key: [u8; 16],
    sender: String,
    keypair: (RsaPublicKey, RsaPrivateKey),
    chain: Arc<Mutex<Vec<Block>>>,
    rejected_users: &mut Vec<String>,
    rx: Arc<Mutex<std::sync::mpsc::Receiver<String>>>,
) {
    let mut buf = [0; 1024];
    let mut message = Vec::new();

    let mut to_send_queue = Arc::new(Mutex::new(Vec::new()));

    // listen for message on the rx channel
    let rx_clone = Arc::clone(&rx);
    let to_send_queue_clone = Arc::clone(&to_send_queue);

    thread::spawn(move || loop {
        let message = rx_clone.lock().unwrap().recv().unwrap();
        println!("Sending message: {}", message);
        // we get here but the message is not sent
        to_send_queue_clone.lock().unwrap().push(message);
    });

    loop {
        // check if there are any messages to send
        let to_send = to_send_queue.lock().unwrap();
        for message in to_send.iter() {
            stream.write_all(&encrypt_message(message.clone(), &key)).unwrap();
        }

        // clear the queue
        to_send_queue.lock().unwrap().clear();

        let result: Result<usize, std::io::Error> = stream.read(&mut buf);

        match result {
            Ok(0) => {
                // Connection was closed
                println!("Connection closed");
                break;
            }
            Ok(1024) => {
                // Buffer is full
                message.extend_from_slice(&buf);
                buf = [0; 1024];
            }
            Ok(n) => {
                // Print the received message
                message.extend_from_slice(&buf[..n]);

                let msg = String::from_utf8_lossy(&message);
                println!("Received message: {}", msg);

                // now, decrypt the message using openssl aes-128-cbc
                let decrypted = decrypt_message(&message, &key);

                // parse the message into a block
                let block = serde_json::from_str(&decrypted);

                let result = match block {
                    Ok(block) => handle(
                        block,
                        sender.clone(),
                        keypair.clone(),
                        &mut chain.lock().unwrap(),
                        rejected_users,
                    ),
                    Err(e) => {
                        eprintln!("Failed to parse block: {}", e);
                        Some(Block::new_ping(BasicData::new(
                            "0".to_string(),
                            sender.clone(),
                            &keypair.1.clone(),
                        )))
                    }
                };

                if result.is_none() {
                    break;
                }

                // now, encrypt the result and send it back
                let result = result.unwrap();
                let result = encrypt_message(result.to_json().unwrap(), &key);

                stream.write_all(&result as &[u8]).unwrap();
            }
            Err(e) => {
                eprintln!("Failed to read from socket: {}", e);
                break;
            }
        }
    }
}

/// manage a connection to a peer where they are the 'server' and we are the 'client'
pub fn client(
    stream: TcpStream,
    keypair: (RsaPublicKey, RsaPrivateKey),
    sender: String,
    chain_path: &str,
    rx: std::sync::mpsc::Receiver<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let chain = Arc::new(Mutex::new(
        <Vec<Block>>::load(chain_path).unwrap_or(Vec::new()),
    ));
    let rejected_users = Arc::new(Mutex::new(Vec::new()));
    let rx = Arc::new(Mutex::new(rx));

    let (key, stream) = client_handshake(stream);

    looper(
        stream,
        key,
        sender,
        keypair,
        chain,
        &mut rejected_users.lock().unwrap(),
        rx,
    );

    Ok(())
}



/// Handle a block and return a response block
fn handle(
    block: Block,
    sender: String,
    keypair: (RsaPublicKey, RsaPrivateKey),
    chain: &mut Vec<Block>,
    rejected: &mut Vec<String>,
) -> Option<Block> {
    let metadata = BasicData::new("0".to_string(), sender.clone(), &keypair.1.clone());

    // first, check if the block is valid. if so, save it to the chain
    if block.verify(chain.clone()) {
        chain.push(block.clone());
    } else {
        return Some(Block::new_ping(metadata));
    }

    // if the block's sender is in the rejected list, prompt the user if they want to accept the blocks, showing the user's handle, and total number of sent messages
    if rejected.contains(&block.metadata.handle) {
        // prompt the user
        print!(
            "User {} ({} messages) has sent you a message, would you like to accept it (y/N)? ",
            chain
                .iter()
                .filter(|b| b.metadata.handle == block.metadata.handle)
                .count(),
            block.metadata.handle
        );

        // now, wait for the user to respond
        let mut response = String::new();
        std::io::stdin().read_line(&mut response).unwrap();

        if response.trim().to_lowercase() == "y" {
            rejected.retain(|h| h != &block.metadata.handle);
        } else {
            return None;
        }
    }

    match block.inner {
        BlockTypes::Ping(_) => {
            // respond with our list of blocks
            Some(Block::new_blocks(chain.clone(), metadata))
        }
        BlockTypes::PubKey(pubkey) => {
            println!(
                "Received public key (hash {}) from {}",
                Base64::encode_string(&Sha256::digest(&pubkey.pubkey)),
                block.metadata.handle
            );
            Some(Block::new_ack(metadata))
        }
        BlockTypes::Message(message) => {
            println!(
                "Received message: {}",
                String::from_utf8_lossy(&message.message)
            );
            Some(Block::new_ack(metadata))
        }
        BlockTypes::Blocks(blocks) => {
            println!("Received blocks");
            for block in blocks {
                println!("Block: {}", block.to_json().unwrap());
            }
            Some(Block::new_ack(metadata))
        }
        BlockTypes::FailedBlocks(data) => {
            println!("Received failed blocks");

            // add the failed blocks to the rejected users list
            rejected.push(data.handle.clone());

            Some(Block::new_ack(metadata))
        }
        BlockTypes::Ack(_) => {
            // received an ack, nothing to do here
            println!("Received ack");
            None
        }
    }
}

pub mod interlude {
    pub use super::{client_handshake, listen, server_handshake};
}
