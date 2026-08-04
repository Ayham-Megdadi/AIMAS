#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Crypto Engine - Centralized cryptographic operations (AES, ChaCha20, RSA, Hashing, Base64, ROT13)
"""

import base64
import hashlib
import logging
from Crypto.Cipher import AES, ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

logger = logging.getLogger(__name__)

class CryptoEngine:
    # ---------- Key derivation ----------
    @staticmethod
    def pbkdf2_derive(password: str, salt: bytes, iterations: int = 100000, dklen: int = 32) -> bytes:
        """Derive a key from password using PBKDF2-HMAC-SHA256."""
        return PBKDF2(password, salt, dkLen=dklen, count=iterations, hmac_hash_module=hashlib.sha256)

    # ---------- Hashing (kept for completeness, though not used in UI) ----------
    @staticmethod
    def hash_md5(data: bytes) -> str:
        return hashlib.md5(data).hexdigest()
    @staticmethod
    def hash_sha1(data: bytes) -> str:
        return hashlib.sha1(data).hexdigest()
    @staticmethod
    def hash_sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
    @staticmethod
    def hash_sha512(data: bytes) -> str:
        return hashlib.sha512(data).hexdigest()
    @staticmethod
    def hash_sha224(data: bytes) -> str:
        return hashlib.sha224(data).hexdigest()
    @staticmethod
    def hash_sha384(data: bytes) -> str:
        return hashlib.sha384(data).hexdigest()

    # ---------- AES-256-GCM ----------
    @staticmethod
    def aes_encrypt(plaintext: bytes, password: str) -> str:
        salt = get_random_bytes(16)
        key = CryptoEngine.pbkdf2_derive(password, salt)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        # Format: salt (16) + nonce (16) + tag (16) + ciphertext
        encrypted = salt + cipher.nonce + tag + ciphertext
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def aes_decrypt(ciphertext_b64: str, password: str) -> bytes:
        data = base64.b64decode(ciphertext_b64)
        if len(data) < 48:
            raise ValueError("Invalid ciphertext")
        salt, nonce, tag, ct = data[:16], data[16:32], data[32:48], data[48:]
        key = CryptoEngine.pbkdf2_derive(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plain = cipher.decrypt_and_verify(ct, tag)
        return plain

    # ---------- ChaCha20-Poly1305 ----------
    @staticmethod
    def chacha_encrypt(plaintext: bytes, password: str) -> str:
        salt = get_random_bytes(16)
        key = CryptoEngine.pbkdf2_derive(password, salt)
        nonce = get_random_bytes(12)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        encrypted = salt + nonce + tag + ciphertext
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def chacha_decrypt(ciphertext_b64: str, password: str) -> bytes:
        data = base64.b64decode(ciphertext_b64)
        if len(data) < 44:
            raise ValueError("Invalid ciphertext")
        salt, nonce, tag, ct = data[:16], data[16:28], data[28:44], data[44:]
        key = CryptoEngine.pbkdf2_derive(password, salt)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        plain = cipher.decrypt_and_verify(ct, tag)
        return plain

    # ---------- RSA ----------
    @staticmethod
    def rsa_generate_keypair() -> tuple:
        """Generate RSA-2048 key pair. Returns (private_pem, public_pem)."""
        key = RSA.generate(2048)
        private_pem = key.export_key().decode()
        public_pem = key.publickey().export_key().decode()
        return private_pem, public_pem

    @staticmethod
    def rsa_encrypt(plaintext: bytes, public_key_pem: str) -> str:
        key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(key)
        encrypted = cipher.encrypt(plaintext)
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def rsa_decrypt(ciphertext_b64: str, private_key_pem: str) -> bytes:
        key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(key)
        ciphertext = base64.b64decode(ciphertext_b64)
        plain = cipher.decrypt(ciphertext)
        return plain

    # ---------- Base64 (standard and URL-safe) ----------
    @staticmethod
    def base64_decode(data: str) -> bytes:
        try:
            return base64.b64decode(data)
        except Exception:
            return base64.urlsafe_b64decode(data)

    # ---------- ROT13 ----------
    @staticmethod
    def rot13(text: str) -> str:
        import codecs
        return codecs.encode(text, 'rot_13')
