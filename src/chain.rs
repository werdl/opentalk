use rsa::{pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey}, RsaPrivateKey, RsaPublicKey};
use serde::{Serialize, Deserialize};

use crate::otrsa::{PrivKeyMethods, PubKeyMethods};

/// Basic data that is included in every block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BasicData {
    /// Unix timestamp
    pub timestamp: u64,

    /// the round that the message is associated with (short hash, e.g. "abc123")
    pub round: String,

    /// the handle of the sender
    pub handle: String,

    /// `timestamp` signed with the sender's private key
    pub signed_timestamp: Vec<u8>,
}

/// Block specifying the public key of a user. If one of these is recieved, it should be accepted only if 
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PubKey {
    pub handle: String,

    /// hex-encoded RSA public key
    pub pubkey: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    pub message: Vec<u8>,

    pub signed_message: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Ping {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Ack {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BlockTypes {
    PubKey(PubKey),
    Message(Message),
    Ping(Ping),
    Blocks(Vec<BlockTypes>),
    Ack(Ack),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub inner: BlockTypes,
    pub metadata: BasicData,
}

impl Block {
    /// create a new block
    pub fn new(block: BlockTypes, metadata: BasicData) -> Self {
        Block {
            inner: block,
            metadata,
        }
    }

    /// create a new public key block
    pub fn new_pubkey(pubkey: RsaPublicKey, metadata: BasicData) -> Self {
        // get pkcs1 public key
        let rsa_pubkey = pubkey.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap();

        Block::new(BlockTypes::PubKey(PubKey {
            handle: metadata.handle.clone(),
            pubkey: rsa_pubkey,
        }), metadata)
    }

    /// create a new message block
    pub fn new_message(message: String, priv_key: RsaPrivateKey, metadata: BasicData) -> Self {

        // sign the message
        let signed_message = priv_key.rsa_sign(message.as_bytes());

        Block::new(BlockTypes::Message(Message {
            message: message.as_bytes().to_vec(),
            signed_message: signed_message,
        }), metadata)
    }

    /// create a new ping block
    pub fn new_ping(metadata: BasicData) -> Self {
        Block::new(BlockTypes::Ping(Ping {}), metadata)
    }  

    /// create a new blocks block (a block containing multiple blocks, e.g. for a chain of messages)
    pub fn new_blocks(blocks: Vec<BlockTypes>, metadata: BasicData) -> Self {
        Block::new(BlockTypes::Blocks(blocks), metadata)
    }

    /// create a new ack block
    pub fn new_ack(metadata: BasicData) -> Self {
        Block::new(BlockTypes::Ack(Ack {}), metadata)
    }

    /// convert the block to a JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }

    /// create a block from a JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl BasicData {
    /// create a new BasicData object, given the name of the relevant round, the handle of the user sending it and the user's private key (for signing the timestamp, isn't stored in the object!)
    pub fn new(round: String, handle: String, priv_key: &rsa::RsaPrivateKey) -> Self {
        // get timestamp (UTC) in seconds
        let timestamp = chrono::Utc::now().timestamp() as u64;
        
        // sign a timestamp converted to a string
        let signed_timestamp = priv_key.rsa_sign(timestamp.to_string().as_bytes());

        BasicData {
            timestamp,
            round,
            handle,
            signed_timestamp,
        }
    }

    /// verify the signature on the timestamp
    pub fn verify(&self, pubkey: &rsa::RsaPublicKey) -> bool {
        pubkey.rsa_verify(&self.timestamp.to_string().as_bytes(), &self.signed_timestamp)
    }
}

impl Block {
    /// verify that given a valid chain `chain`, this block is valid
    pub fn verify(&self, chain: Vec<Block>) -> bool {
        if chain.len() == 0 {
            match &self.inner {
                BlockTypes::PubKey(pkey) => {
                    return self.metadata.verify(&rsa::RsaPublicKey::from_pkcs1_pem(&pkey.pubkey).unwrap());
                }
                _ => {
                    return false;
                }
            }
        }
        // if the block is a pubkey, we only verify that a. it is the first message from that user and b. the signature is valid by the pubkey it gives us

        // now find the public key for the sender
        let pubkey = match self.inner.clone() {
            BlockTypes::PubKey(pubkey) => {
                Some(pubkey)
            }
            _ => {
                let mut searched_pubkey = None;
                for block in chain.clone() {
                    match block.inner {
                        BlockTypes::PubKey(found_pubkey) => {
                            if found_pubkey.handle == self.metadata.handle {
                                searched_pubkey = Some(found_pubkey);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                searched_pubkey
            }
        };

        match &self.inner {
            BlockTypes::PubKey(_) => {
                // if the pubkey is not the first message from the user, reject it
                for block in chain {
                    match block.inner {
                        BlockTypes::PubKey(found_pubkey) => {
                            if found_pubkey.handle == self.metadata.handle {
                                return false;
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        if pubkey.is_none() {
            return false;
        }

        let our_pubkey = match rsa::RsaPublicKey::from_pkcs1_pem(&pubkey.unwrap().pubkey) {
            Ok(pubkey) => pubkey,
            Err(err) => {
                // Handle the error by returning false or taking an alternative action.
                eprintln!("Error: {}", err);
                return false;
            }
        };

        

        if !self.metadata.verify(&our_pubkey) {
            return false;
        }


        // now verify the message
        match &self.inner {
            BlockTypes::Message(message) => {
                our_pubkey.rsa_verify(&message.message, &message.signed_message)
            }

            // for all other block types, we don't need to verify anything else
            _ => true,
        }
    }
}

pub trait ValidChain {
    /// verify that `other` is a valid continuation of `self`
    fn check_validity(&self, other: Self) -> bool;
}

impl ValidChain for Vec<Block> {
    /// verify that `other` is a valid continuation of `self` (`other` must contain `self` as a prefix)
    fn check_validity(&self, other: Self) -> bool {
        // if the other chain is empty, it is valid
        if other.len() == 0 {
            return true;
        }

        // if the other chain is shorter than the current chain, it is invalid
        if other.len() < self.len() {
            return false;
        }

        // now go through the chain and verify each block. If any block is invalid, the chain is invalid
        for (i, block) in other.iter().enumerate() {
            println!("verifying block {}", i);
            if !block.verify(other.clone().into_iter().take(i).collect()) {
                return false;
            }
        }

        true
    }
    
}