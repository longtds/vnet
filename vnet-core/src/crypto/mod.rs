//! 加密模块

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// 握手时生成临时密钥对
pub fn generate_ephemeral_keypair() -> (PublicKey, StaticSecret) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    (public, secret)
}

/// 计算 X25519 shared secret 并派生 AES-256-GCM 密钥
pub fn derive_key(shared_secret: &[u8], network_secret: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(network_secret.as_bytes()), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"vnet-tunnel-key", &mut okm)
        .expect("32 is valid length");
    okm
}

/// 派生 peer_id: SHA256(network_secret || virtual_ip || hostname)[:8]
pub fn derive_peer_id(network_secret: &str, virtual_ip: &str, hostname: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(network_secret.as_bytes());
    hasher.update(b"|");
    hasher.update(virtual_ip.as_bytes());
    hasher.update(b"|");
    hasher.update(hostname.as_bytes());
    let out = hasher.finalize();
    u64::from_be_bytes(out[..8].try_into().unwrap())
}

/// 加密一帧数据
pub fn encrypt(cipher: &Aes256Gcm, nonce_bytes: &[u8; 12], plaintext: &[u8]) -> Option<Vec<u8>> {
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.encrypt(nonce, plaintext).ok()
}

/// 解密一帧数据
pub fn decrypt(cipher: &Aes256Gcm, nonce_bytes: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).ok()
}

/// 创建 AES-256-GCM cipher
pub fn make_cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(key.into())
}
