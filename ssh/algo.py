
from . import kex, encryption as enc, mac, key

KEX_ALGOS: dict[str, kex.Kex] = {
    "diffie-hellman-group14-sha256": kex.DHGroup14SHA256,
    "diffie-hellman-group16-sha512": kex.DHGroup16SHA512,
    "curve25519-sha256": kex.Curve25519,
    "curve25519-sha256@libssh.org": kex.Curve25519,
    "diffie-hellman-group14-sha1": kex.DHGroup14SHA1,
    "diffie-hellman-group1-sha1": kex.DHGroup1SHA1,
    "diffie-hellman-group18-sha512": kex.DHGroup18SHA512,
    "ecdh-sha2-nistp256": kex.ECDHNISTP256,
    "ecdh-sha2-nistp384": kex.ECDHNISTP384,
    "ecdh-sha2-nistp521": kex.ECDHNISTP521,

}
ENCRYPTION_ALGOS: dict[str, enc.AES] = {
    "aes256-ctr": enc.AESCTR256,
    "aes128-ctr": enc.AESCTR128,
    "chacha20-poly1305@openssh.com": enc.ChaCha20Poly1305,
}

MAC_ALGOS: dict[str, mac.HMAC] = {
    "hmac-sha2-256": mac.HMACSHA256,
    "hmac-sha2-512": mac.HMACSHA512,
    "hmac-sha1": mac.HMACSHA1,
}

HOST_KEY_ALGOS: dict[str, key.Key] = {
    "rsa-sha2-512": key.RSAKey,
    "rsa-sha2-256": key.RSAKey,
    "ssh-ed25519": key.Ed25519Key,
    "ecdsa-sha2-nistp256":key.NISTPKeys,
    "ecdsa-sha2-nistp384":key.NISTPKeys,
    "ecdsa-sha2-nistp521":key.NISTPKeys,
}