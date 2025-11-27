# SecureChat

A **privacy-first, end-to-end encrypted chat application** built from scratch using Go and the Signal Protocol. Messages are encrypted on the sender's device and can only be decrypted by the recipient—the server acts as a blind relay with zero knowledge of message contents.

---

## 🔒 Core Features

- **True End-to-End Encryption**: Double Ratchet algorithm (Signal Protocol)
- **Forward Secrecy**: Each message uses unique ephemeral keys
- **Zero-Knowledge Server**: Server cannot read messages or derive keys
- **Certificate Pinning**: SPKI pinning with auto-rotation for MITM protection
- **Minimal Attack Surface**: No chat history storage, no logging, no metadata leakage

---
## **Full code available for review upon request**
---

## 🏗️ Architecture

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Client A  │◄──E2E──►│    Server    │◄──E2E──►│   Client B  │
│  (Go + TUI) │         │  (Relay only)│         │  (Go + TUI) │
└─────────────┘         └──────────────┘         └─────────────┘
      │                        │                        │
      │                        │                        │
   Identity                 Public                  Identity
   Storage                  Bundles                 Storage
   (Local)                  (Server)                (Local)
```

## 🛠️ Technology Stack

### Language & Framework
- **Go 1.23**: Core language for both client and server
- **WebSockets** (`gorilla/websocket`): Real-time bidirectional communication
- **TLS 1.3**: Transport security with certificate pinning

### Cryptography
- **X25519** (ECDH): Key agreement for ephemeral session keys
- **Ed25519**: Digital signatures for identity verification
- **AES-256-GCM**: Authenticated encryption with associated data (AEAD)
- **HKDF-SHA256**: Key derivation function for ratcheting
- **Double Ratchet Protocol**: Forward secrecy and post-compromise security

### Infrastructure
- **Cloudflare Tunnel**: Secure public endpoint without port forwarding
- **Self-Signed Certificates**: TLS without relying on public CAs

---

## 🔐 Security Model

### Threat Protection

| Threat Vector | Protection Mechanism |
|--------------|---------------------|
| Network eavesdropping | TLS 1.3 + E2E encryption |
| Server compromise | Zero-knowledge design (server has no keys) |
| MITM attacks | SPKI pinning with signature verification |
| Replay attacks | Message counters in ratchet headers |
| Key impersonation | Ed25519 signature chains |
| Forward secrecy | Ephemeral DH keys per message |

### What the Server Knows
- User IDs (public metadata)
- Public key bundles (signed by users)
- Mess age routinginfo (from/to)
- **DOES NOT KNOW**: Message content, private keys, session keys

### What's Encrypted
- ✅ All message payloads
- ✅ Derived from unique per-message keys
- ✅ Authenticated with AEAD
- ❌ Metadata (sender/receiver usernames) - required for routing

---

## 🎯 Design Philosophy

1. **Privacy by Default**: No optional encryption—it's always on
2. **Minimal Trust**: Server designed to be untrusted from the start
3. **Simplicity**: Clean code, minimal dependencies, auditable
4. **User Control**: Keys stored locally, full user ownership
5. **No Persistence**: Messages exist only in memory during the session

---

## 📚 Technical Highlights

- **Custom TLS Verification**: SPKI pinning prevents CA-based MITM attacks
- **Double Ratchet Implementation**: Industry-standard Signal Protocol in pure Go
- **Thread-Safe Async I/O**: Goroutines with mutex protection for concurrent operations
- **TUI Event Loop**: Non-blocking input handling to prevent UI freezes
- **Automatic Key Rotation**: HKDF-based chain keys advance with each message

---

## ⚠️ Limitations

- **Not for Production**: Educational/research project, not audited by external cryptographers
- **Single Channel**: One active conversation at a time (design choice for simplicity)
- **No Group Chat**: Peer-to-peer only
- **No Message History**: Privacy-first means no persistent storage

---

## 🧪 Use Cases

- Learning cryptographic protocol implementation
- Understanding E2E encryption architectures
- Privacy-focused communication in controlled environments
- Demonstrating zero-knowledge server design

---

## 📄 License

This is a personal portfolio project. Not licensed for redistribution. For educational purposes only.

---

## 🔗 Related Technologies

- [Signal Protocol](https://signal.org/docs/)
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [X3DH Key Agreement](https://signal.org/docs/specifications/x3dh/)
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)
