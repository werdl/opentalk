use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct BasicData {
    timestamp: u64,
    round: String,
    handle: String,
    ip: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PubKey {
    handle: String,

    /// hex-encoded RSA public key
    pubkey: String,

    metadata: BasicData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    signed_message: String,

    metadata: BasicData
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ping {}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ack {}

#[derive(Serialize, Deserialize, Debug)]
pub enum Block {
    PubKey(PubKey),
    Message(Message),
    Ping(Ping),
    Blocks(Vec<Block>),
    Ack(Ack),
}

impl Block {
    pub fn new_pubkey(handle: String, pubkey: String, metadata: BasicData) -> Self {
        Block::PubKey(PubKey {
            handle,
            pubkey,
            metadata,
        })
    }

    pub fn new_message(signed_message: String, metadata: BasicData) -> Self {
        Block::Message(Message {
            signed_message,
            metadata,
        })
    }

    pub fn new_ping() -> Self {
        Block::Ping(Ping {})
    }

    pub fn new_blocks(blocks: Vec<Block>) -> Self {
        Block::Blocks(blocks)
    }

    pub fn new_ack() -> Self {
        Block::Ack(Ack {})
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}