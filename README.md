
# opentalk
> a decentralized chat application

## Idea
- a fully P2P chat app
- no central server
- no third-party P2P libraries, relying solely on Unix sockets
- fully public/private encrypted

## Organization
- the project is based around "rounds", which are lists of peers that are connected to each other
- when a peer wants to send a message, they send it to all other peers in the round 
- if none are online, the message is stored until one is

## Example Usage
- Peer A wishes to send a message
- If no peers are online (responding to pings), the message is stored until one is
- now 1+ peers are online, Peer A first requests their working version of the round blockchain
- Peer A then verifies each of the peers' versions of the round blockchain
- Now they have an updated version of the round blockchain, their block is tacked on to the end and sent to all online peers
- all online peers verify that all new blocks are correctly signed (all peers, at first connection, exchange public keys by sending a Pubkey block)
- if Peer B is satisfied that all new blocks are correctly signed, they add the new block to their version of the round blockchain

## todo

## protocol examples
### Diffie-Hellman Key Exchange
```mermaid
sequenceDiagram
	participant A as Peer A ('server')
	participant B as Peer B ('client')
	B->>A: B's public key (raw RSA format as a series of bits)
	A->>B: A's public key in the same format
	A->>A: compute and store shared secret (AES128 key)
	B->>B: computer and store shared secret (AES128 key)
```
### Initial PubKey block issued
```mermaid
sequenceDiagram
	    participant A as Peer A (new member, who has been given B's IP)
		participant B as Peer B (existing member)
		A->>B: 
		B->>A: Initial key exchange to facilitate encrypted communication
		A->>B: SHA256 hash of the genesis block. This is the "round id", which acts as a password <br> and thus must be shared with any new participants via alternative means
		B->>Terminate connection: Hash wrong
		B->>A: Hash correct: issue ACK
		A->>B: PubKey block
		B->>B: store block in chain
	    
```
### Send new message
- the below exchange is replicated with all online peers
```mermaid
sequenceDiagram
	participant A as Peer A (message sender)
	participant B as Peer B (online round member)
	A->>B: Message Block
	B->>Terminate Connection: Message not correctly signed
	B->>A: Message correctly signed: ACK
```

### Catch peer "up to speed"
- all online peers should have this exchange
```mermaid
sequenceDiagram
	participant A as Peer A (newly online member)
	participant B as Peer B (online round member)
	A->>B: ACK
	B->>A: Updated version of chain
	A->>Terminate Connection: Chain contains badly signed blocks
	A->>B: Chain is signed correctly: ACK
```

## todo
- implement rounds