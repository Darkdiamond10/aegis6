import base64
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Constants matching C code
AEGIS_AES_KEY_BYTES = 32
AEGIS_GCM_IV_BYTES = 12
AEGIS_GCM_TAG_BYTES = 16
AEGIS_HKDF_SALT_BYTES = 32
AEGIS_SESSION_KEY_ROTATE_N = 50
AEGIS_PSK_B64 = "Rz9kX3BhcnRuZXJzX2luX2NyaW1lX0xPX2FuZF9FTkk="
AEGIS_HKDF_INFO = b"aegis-nightshade-v1"

class AegisCrypto:
    def __init__(self, psk_b64=AEGIS_PSK_B64):
        self.psk_raw = base64.b64decode(psk_b64)

        # Hardcoded salt in the server matching the memset(salt, 0xAA) that you observed!
        self.hkdf_salt = b'\xAA' * AEGIS_HKDF_SALT_BYTES

        # Master Key Derivation
        hkdf_master = HKDF(
            algorithm=hashes.SHA256(),
            length=AEGIS_AES_KEY_BYTES,
            salt=self.hkdf_salt,
            info=AEGIS_HKDF_INFO,
            backend=default_backend()
        )
        self.master_key = hkdf_master.derive(self.psk_raw)

        # Session Key Derivation
        session_info = b"aegis-session-key-v1-init"
        hkdf_session = HKDF(
            algorithm=hashes.SHA256(),
            length=AEGIS_AES_KEY_BYTES,
            salt=self.hkdf_salt,
            info=session_info,
            backend=default_backend()
        )
        self.session_key = hkdf_session.derive(self.master_key)

        self.msg_counter = 0
        self.total_messages = 0
        self.rekey_threshold = AEGIS_SESSION_KEY_ROTATE_N

    def encrypt(self, payload: bytes, aad: bytes = None) -> tuple[bytes, bytes, bytes]:
        self.msg_counter += 1
        self.total_messages += 1

        import os
        # Match generate_iv logic: first 4 bytes = truncated total_messages, last 8 bytes = random
        ctr = self.total_messages
        iv_prefix = struct.pack(">I", ctr)
        iv_suffix = os.urandom(8)
        iv = iv_prefix + iv_suffix

        aesgcm = AESGCM(self.session_key)
        ciphertext_and_tag = aesgcm.encrypt(iv, payload, aad)

        # Cryptography's AESGCM returns ciphertext + tag combined
        ciphertext = ciphertext_and_tag[:-AEGIS_GCM_TAG_BYTES]
        tag = ciphertext_and_tag[-AEGIS_GCM_TAG_BYTES:]

        return ciphertext, iv, tag

    def decrypt(self, ciphertext: bytes, iv: bytes, tag: bytes, aad: bytes = None) -> bytes:
        # Increment counters
        self.msg_counter += 1
        self.total_messages += 1

        aesgcm = AESGCM(self.session_key)

        # Cryptography expects ciphertext + tag
        payload = aesgcm.decrypt(iv, ciphertext + tag, aad)

        return payload

SERVER_CRYPTO = AegisCrypto()
