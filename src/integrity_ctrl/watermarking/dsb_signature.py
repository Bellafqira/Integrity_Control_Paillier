import pickle
import time

import numpy as np
import hashlib
from typing import Sequence
from phe import paillier

from src.integrity_ctrl.watermarking.base import AbstractWatermarkingScheme
from src.integrity_ctrl.crypto import ecdsa_utils

class DSB_Signature(AbstractWatermarkingScheme):
    """
    Implements the DSB (Deterministic Self-Blinding) Signature
    using the PHE library and ECDSA cryptography.
    """

    def __init__(self, public_key: paillier.PaillierPublicKey, signing_keys: dict, signature_length: int = 512):
        """
        Args:
            public_key: PHE Paillier public key.
            signing_keys: Dict of ECDSA keys from ecdsa_utils.py.
            signature_length: Number of bits for the signature.
        """
        super().__init__()
        self.public_key = public_key
        self.sk = signing_keys["signing_key"]
        self.vk = signing_keys["verification_key"]
        self.signature_length = int(signature_length)

        # --- The "Flipper" Trick ---
        # c + E(0, r=-1) == -c mod N^2
        print("DSB: Pre-computing the flipper E(0, r=-1)...")
        self.flipper = self.public_key.encrypt(0, r_value=-1)

        # Threshold for reading a bit (N^2 / 2)
        self.threshold = self.public_key.nsquare // 2

        print(f"DSB_Signature initialized (length={self.signature_length} bits).")

    # --- Low-level functions (DSB) ---

    def _get_bit(self, c: paillier.EncryptedNumber) -> int:
        """Reads the 'natural' bit of a ciphertext (0 or 1)."""
        return 1 if c.ciphertext(be_secure=False) > self.threshold else 0

    def _flip_bit(self, c: paillier.EncryptedNumber) -> paillier.EncryptedNumber:
        """Flips the bit of a ciphertext (E(m) -> E(-m))."""
        return c + self.flipper

    @staticmethod
    def _hash_model(encrypted_data: np.ndarray) -> bytes:
        """
        Deterministically hashes an array of ciphertexts.

        We keep the same logic : hash(str(ciphertext)).
        """
        hasher = hashlib.sha256(pickle.dumps([c.ciphertext(be_secure=False) for c in encrypted_data.ravel()])).digest()
        return hasher

    # --- Pipeline Implementation ---

    def prepare_data_for_signing(self, encrypted_data: np.ndarray) -> np.ndarray:
        """
        "Inserts zeros": ensures that all bits in the
        signature zone are '0'. (pre-processing).
        """
        print("DSB: Preparing data (inserting '0's)...")
        prepared_data = encrypted_data.copy()
        flat_data = prepared_data.ravel()
        n = min(self.signature_length, flat_data.size)
        get_bit = self._get_bit
        flip_bit = self._flip_bit

        for i in range(n):
            if get_bit(flat_data[i]) == 1:
                flat_data[i] = flip_bit(flat_data[i])

        return prepared_data.reshape(encrypted_data.shape)

    def generate_watermark(self, data_to_sign: np.ndarray) -> tuple[list[int], bytes]:
        """
        Calculates the signature (hash + signature) and returns it
        as bits and bytes.
        """
        print("DSB: Generating signature...")
        # 1. Hash the model (must be the "prepared" model)
        data_hash = self._hash_model(data_to_sign)

        # 2. Sign the hash
        signature_bytes = ecdsa_utils.generate_signature(data_hash, self.sk)

        # 3. Convert to bits
        signature_bits = ecdsa_utils.bytes_to_bits(signature_bytes)
        # On suppose que bytes_to_bits renvoie >= signature_length bits
        if len(signature_bits) < self.signature_length:
            raise ValueError(
                f"Signature bits too short: got {len(signature_bits)}, "
                f"expected at least {self.signature_length}."
            )

        return signature_bits[: self.signature_length], signature_bytes

    def embed(self, host_data: np.ndarray, signature_bits: Sequence[int]) -> np.ndarray:
        """
        Embeds the signature (list of bits) into the "prepared" host data.
        """
        print("DSB: Embedding signature...")
        signed_data = host_data.copy()
        flat_data = signed_data.ravel()

        n = min(self.signature_length, flat_data.size)

        if len(signature_bits) < n:
            raise ValueError(
                f"signature_bits too short: got {len(signature_bits)}, "
                f"expected at least {n}."
            )

        flip_bit = self._flip_bit

        # Indices of bits set to 1: we avoid an if statement in the loop
        one_indices = [i for i, b in enumerate(signature_bits[:n]) if b]

        for i in one_indices:
            flat_data[i] = flip_bit(flat_data[i])

        return signed_data.reshape(host_data.shape)

    def extract(self, watermarked_data: np.ndarray) -> list[int]:
        """
        Extracts the signature (list of bits) from the encrypted model.
        """
        print("DSB: Extracting signature...")
        flat_data = watermarked_data.ravel()
        n = min(self.signature_length, flat_data.size)
        get_bit = self._get_bit

        # List comprehension faster than append in a loop
        return [get_bit(flat_data[i]) for i in range(n)]

    def verify(self, watermarked_data: np.ndarray) -> bool:
        """
        Full verification process.
        """
        print("DSB: Starting full verification...")

        # 1. Extract the embedded signature
        extracted_bits = self.extract(watermarked_data)
        extracted_sig_bytes = ecdsa_utils.bits_to_bytes(extracted_bits)

        # 2. Restore coordinates to zero (pre-processing)
        restored_data = self.prepare_data_for_signing(watermarked_data)

        # 3. Calculate the hash of this restored model
        restored_hash = self._hash_model(restored_data)

        # 4. Verify ECDSA signature
        print("DSB: Verifying ECDSA signature...")
        is_valid = ecdsa_utils.verify_signature(
            restored_hash,
            extracted_sig_bytes,
            self.vk,
        )

        return is_valid
