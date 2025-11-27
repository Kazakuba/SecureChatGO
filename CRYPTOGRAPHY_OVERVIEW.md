# Cryptography Implementation Overview

This document demonstrates the **cryptographic design** of SecureChat without revealing sensitive implementation details. It showcases principles of end-to-end encryption and Signal Protocol.

---

## 🔑 Key Management

### Identity Generation

Each user generates a long-term identity on first run:

```go
type Identity struct {
    SignPriv ed25519.PrivateKey
    SignPub  ed25519.PublicKey
    
    DhPriv   *ecdh.PrivateKey
    DhPub    *ecdh.PublicKey
}

// Keys are stored locally with restricted permissions / Owner-only access
os.WriteFile(identityFile, data, 0600)
```

**Security Principle**: Private keys never leave the device.

---

## 🤝 Key Exchange Protocol

### 1. Bundle Registration

Clients publish their public keys to the server:

```go
type Bundle struct {
    UserID      string
    SignPub     string
    DhPub       string
    DhPubSig    string
    Fingerprint string
}

// Server stores bundles but cannot use them to decrypt
server.RegisterBundle(bundle)
```

### 2. Initiator Handshake

When starting a conversation, the initiator:

```go
// Fetch peer's bundle from server
peerBundle := fetchBundle(peerUsername)

// Verify signature (prevent impersonation)
if !ed25519.Verify(peerBundle.SignPub, peerBundle.DhPub, peerBundle.Sig) {
    return error("invalid bundle")
}

// Generate ephemeral key
ephemeralPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)

// Perform 2-DH key agreement
dh1 := ephemeralPriv.ECDH(peerDhPub)
dh2 := ourStaticPriv.ECDH(peerDhPub)

// Derive root key via HKDF
rootKey := HKDF(concat(dh1, dh2), salt, info)
```

**Why 2-DH?**
- Provides mutual authentication
- Establishes forward secrecy
- Prevents MITM attacks

---

## 🔄 Double Ratchet Algorithm

### Session Initialization

```go
type Session struct {
    rootKey  []byte           // Root of key hierarchy
    sendCK   []byte           // Sending chain key
    recvCK   []byte           // Receiving chain key
    dhSelf   *ecdh.PrivateKey // Current DH ratchet key
    dhRemote []byte           // Peer's current DH public key
}

// KDF Chain: Derives message key from chain key
func kdfChain(chainKey []byte) (newChainKey, messageKey []byte) {
    newChainKey = HMAC-SHA256(chainKey, 0x01)
    messageKey  = HMAC-SHA256(chainKey, 0x02)
    return
}
```

### Message Encryption

```go
// Encrypt a message
func (s *Session) Encrypt(plaintext []byte) (header Header, ciphertext []byte) {
    // 1. Advance chain
    s.sendCK, messageKey := kdfChain(s.sendCK)
    
    // 2. Encrypt with AES-256-GCM
    ciphertext = AES_GCM_Encrypt(messageKey, plaintext, aad)
    
    // 3. Create header
    header = Header{
        DHPub: s.dhSelf.PublicKey(),
        N:     s.sendN,
    }
    
    s.sendN++
    return header, ciphertext
}
```

**Key Properties**:
- Each message uses a unique `messageKey`
- Chain keys are never reused
- Forward secrecy: Past keys cannot be derived from current state

### Message Decryption

```go
func (s *Session) Decrypt(header Header, ciphertext []byte) (plaintext []byte) {
    // 1. Check if peer rotated DH key (ratchet step)
    if header.DHPub != s.dhRemote {
        s.performRatchetStep(header.DHPub)
    }
    
    // 2. Handle out-of-order messages
    if header.N > s.recvN {
        s.skipMessages(s.recvN, header.N)  // Store skipped keys
    }
    
    // 3. Derive message key
    s.recvCK, messageKey := kdfChain(s.recvCK)
    
    // 4. Decrypt
    plaintext = AES_GCM_Decrypt(messageKey, ciphertext, aad)
    
    s.recvN++
    return plaintext
}
```

---

## 📡 Message Format (Over the Wire)

### Encrypted Message

```json
{
  "type": "message",
  "from": "alice",
  "to": "bob",
  "header": {
    "dh": "base64_encoded_public_key",
    "n": 42
  },
  "ciphertext": "base64_encoded_aes_gcm_output"
}
```

**What's visible to the server:**
- ✅ Sender and receiver (routing metadata)
- ✅ Ratchet public key (non-secret)
- ✅ Message counter (non-secret)
- ❌ **Plaintext message** (encrypted)
- ❌ **Message key** (derived locally)
- ❌ **Session keys** (derived locally)

---

## 🛡️ Security Properties Achieved

### 1. Confidentiality
```
Plaintext → AES-GCM(MessageKey) → Ciphertext
         ↑
         Derived via KDF from ChainKey
         Which comes from RootKey
         Which comes from DH key agreement
```

**Result**: Only holder of private DH key can derive message keys.

### 2. Forward Secrecy

```go
// After each message, the chain key is deleted
messageKey := deriveFromChain(chainKey)
chainKey = advanceChain(chainKey)  // Old chain key is gone
delete(messageKey)  // Used once and discarded
```

**Result**: Compromising current keys doesn't reveal past messages.

### 3. Post-Compromise Security

```go
// DH ratchet step (happens periodically)
newDH := generateEphemeralKey()
rootKey, chainKey = kdfRoot(rootKey, DH(newDH, peerDH))
```

**Result**: Compromised session recovers security after ratchet step.

### 4. Authentication

```go
// Bundle signature verification
verified := ed25519.Verify(peerSignPub, peerDhPub, signature)

// AEAD provides ciphertext authentication
plaintext, authenticated := AES_GCM_Decrypt(...)
```

**Result**: Prevents impersonation and tampering.

---

## 🔍 Code Flow Example

### Sending "Hello, World!"

```go
// 1. User types in TUI
input := "Hello, World!"

// 2. Encryption
aad := []byte("alice|bob|v1")
header, ciphertext := session.Encrypt([]byte(input), aad)

// 3. Construct message
msg := {
    "type": "message",
    "from": "alice",
    "to": "bob",
    "header": marshalHeader(header),
    "ciphertext": base64.Encode(ciphertext)
}

// 4. Send over WebSocket
wsConn.Send(json.Marshal(msg))
```

**What travels over the internet:**
```json
{
  "type": "message",
  "from": "alice",
  "to": "bob",
  "header": {"dh": "BpU7...", "n": 5},
  "ciphertext": "xF2k9A7qL..." ← Encrypted!
}
```

### Receiving the Message

```go
// 1. Receive from WebSocket
msg := receiveFromWS()

// 2. Extract components
header := unmarshalHeader(msg.header)
ciphertext := base64.Decode(msg.ciphertext)

// 3. Decrypt
aad := []byte("alice|bob|v1")
plaintext := session.Decrypt(header, ciphertext, aad)

// 4. Display in TUI
display(string(plaintext))  // "Hello, World!"
```

---

## 🔐 Additional Security Layers

### TLS with SPKI Pinning

```go
// Prevent MITM even if CA is compromised
tlsConfig := &tls.Config{
    VerifyPeerCertificate: func(rawCerts [][]byte) error {
        spki := extractSPKI(rawCerts[0])
        expectedSPKI := loadPinnedSPKI()
        
        if !bytes.Equal(spki, expectedSPKI) {
            return errors.New("SPKI mismatch")
        }
        return nil
    },
}
```

**Defense in Depth**: Even though messages are E2E encrypted, this prevents metadata leakage.

---

## 📊 Crypto Primitives Summary

| Primitive | Algorithm | Usage |
|-----------|-----------|-------|
| Key Agreement | X25519 (ECDH) | Derive shared secrets |
| Signatures | Ed25519 | Identity verification |
| Encryption | AES-256-GCM | Message confidentiality + auth |
| KDF | HKDF-SHA256 | Key derivation and ratcheting |
| MAC | HMAC-SHA256 | Chain key advancement |

All primitives are **vetted, standardized algorithms** implemented via Go's `crypto` package and `golang.org/x/crypto`.

---

## 🎓 Key Takeaways

1. **Zero Trust Server**: Server is designed to be untrusted—it cannot access messages
2. **Layered Security**: TLS + E2E provides defense in depth
3. **Forward Secrecy**: Past messages safe even if current keys leak
4. **Signal Protocol**: Industry-proven design used by Signal, WhatsApp, etc.
5. **No Custom Crypto**: Built on well-tested standard libraries

---

## 📚 Further Reading

- [Signal Protocol Specifications](https://signal.org/docs/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [Go Cryptography Libraries](https://pkg.go.dev/crypto)

---

**Note**: This document demonstrates cryptographic design principles. Actual implementation details are intentionally abstracted to protect the security of the deployed system.
