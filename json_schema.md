# JSON schema
> all messages are in JSON format, thus the client's programming language is irrelevant
> since any attempted manipulations will be caught by other clients' checks, any malicious client will be shut out of the round

# Message Types
- all messages have a field with some essential information
```json
{
    "timestamp": 1234567890,
    "round": "string", // the round that the message is associated with (the round is a hash of the genesis block)
    "handle": "string", // the handle of the sender
}
```

## PubKey
```json
{
    "type": "PubKey",
    "handle": "string",
    "pubkey": "string",
}
```
### required verification
- `handle` is unique and no other `PubKey` message has the same `handle`
- `pubkey` is a valid RSA public key

### uses
- once a peer receives a `PubKey` message, all future messages from that peer will be encrypted with the corresponding private key
- they now have a way to verify that all future messages from that peer are from the same peer (where the peer is identified by `handle`)

## Message
```json
{
    "type": "Message",
    "signed_message": "string",
}
```
### required verification
- `signed_message` is a valid RSA signature of `message` by the sender's private key (checked with the sender's public key, defined in their `PubKey` message)

### uses
- when a peer receives a valid message, they tack it to their version of the round chain
- they then send the updated version to all online peers, as a "Blocks" message

## Blocks
```json
{
    "type": "Blocks",
    "chain": {...},
}
```
### required verification
- `chain` is a valid version of the round chain, with all blocks signed by the correct private keys

### uses
- when a peer has received a `Blocks` message that they have verified, they modify their own chain to incorporate any unseen, valid blocks

## Ping
```json
{
    "type": "Ping",
}
```
### uses
- when a peer receives a `Ping` message, they respond with a `Blocks` message
- every five minutes, counted from logon (with one then), a peer sends a `Ping` message to all other peers in the round, 


