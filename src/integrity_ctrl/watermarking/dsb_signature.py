import numpy as np
import hashlib
from phe import paillier

# Import from your project files
from src.integrity_ctrl.watermarking.base import AbstractWatermarkingScheme
from src.integrity_ctrl.crypto import ecdsa_utils


class DSB_Signature(AbstractWatermarkingScheme):
    """
    Implements the DSB (Deterministic Self-Blinding) Signature
    using the PHE library and ECDSA cryptography.
    """

    def __init__(self,
                 public_key: paillier.PaillierPublicKey,
                 signing_keys: dict,
                 signature_length: int = 512):
        """
        Initializes the DSB signature scheme.

        Args:
            public_key (paillier.PaillierPublicKey): PHE Paillier public key.
            signing_keys (dict): Dictionary of ECDSA keys from ecdsa_utils.py.
            signature_length (int): Number of bits for the signature (512 for 256-bit curve).
        """
        self.public_key = public_key
        self.sk = signing_keys["signing_key"]
        self.vk = signing_keys["verification_key"]
        self.signature_length = signature_length  # 512 bits = 64 bytes

        # --- The "Flipper" Trick (your discovery) ---
        # c + E(0, r=-1) == -c mod N^2
        print("DSB: Pre-computing the flipper E(0, r=-1)...")
        self.flipper = self.public_key.encrypt(0, r_value=-1)

        # Threshold for reading a bit (N^2 / 2)
        self.threshold = self.public_key.nsquare // 2

        print(f"DSB_Signature initialized (length={signature_length} bits).")

    # --- Low-level functions (DSB) ---

    def _get_bit(self, c: paillier.EncryptedNumber) -> int:
        """ Reads the 'natural' bit of a ciphertext (0 or 1). """
        return 1 if c.ciphertext(be_secure=False) > self.threshold else 0

    def _flip_bit(self, c: paillier.EncryptedNumber) -> paillier.EncryptedNumber:
        """ Flips the bit of a ciphertext (E(m) -> E(-m)). """
        return c + self.flipper

    def _hash_model(self, encrypted_data: np.array) -> bytes:
        """
        Deterministically hashes an array of ciphertexts.
        """
        hasher = hashlib.sha256()
        flat_data = encrypted_data.flatten()

        for c in flat_data:
            # Hash the textual representation of the ciphertext (deterministic)
            hasher.update(str(c.ciphertext(be_secure=False)).encode('utf-8'))

        return hasher.digest()

    # --- Pipeline Implementation ---

    def _prepare_data_for_signing(self, encrypted_data: np.array) -> np.array:
        """
        "Inserts zeros": ensures that all bits in the
        signature zone are '0'. (Your "pre-processing" step).
        """
        print("DSB: Preparing data (inserting '0's)...")
        prepared_data = encrypted_data.copy()
        flat_data = prepared_data.flatten()

        for i in range(self.signature_length):
            if self._get_bit(flat_data[i]) == 1:
                # If the bit is '1', flip it to set it to '0'
                flat_data[i] = self._flip_bit(flat_data[i])


        return flat_data.reshape(encrypted_data.shape)

    def generate_watermark(self, data_to_sign: np.array) -> (list, bytes):
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
        signature_bits = ecdsa_utils.bytes_to_bits(signature_bytes)# [:self.signature_length]

        return signature_bits, signature_bytes

    def embed(self, host_data: np.array, signature_bits: list) -> np.array:
        """
        Embeds the signature (list of bits) into the "prepared" host data.
        (Your "signature embedding" step).
        """
        print("DSB: Embedding signature...")
        signed_data = host_data.copy()
        flat_data = signed_data.flatten()

        for i in range(self.signature_length):

            if signature_bits[i] == 1:
                # Flip the '0' (which is there) to make it a '1'
                flat_data[i] = self._flip_bit(flat_data[i])


        return flat_data.reshape(host_data.shape)

    def extract(self, watermarked_data: np.array) -> list:
        """
        Extracts the signature (list of bits) from the encrypted model.
        (Your "extraction" step).
        """
        print("DSB: Extracting signature...")
        extracted_bits = []
        flat_data = watermarked_data.flatten()

        for i in range(self.signature_length):
            extracted_bits.append(self._get_bit(flat_data[i]))

        return extracted_bits

    def verify(self, watermarked_data: np.array) -> bool:
        """
        Full verification process.
        (Your "verification" step).
        """
        print("DSB: Starting full verification...")

        # 1. Extract the embedded signature
        extracted_bits = self.extract(watermarked_data)
        extracted_sig_bytes = ecdsa_utils.bits_to_bytes(extracted_bits)

        # 2. Restore coordinates to zero
        # (take the signed model and put zeros back everywhere)
        restored_data = self._prepare_data_for_signing(watermarked_data.copy())

        # 3. Calculate the hash of this restored model
        restored_hash = self._hash_model(restored_data)
        print("restored_hash", restored_hash)
        # 4. Compare both signatures
        print("DSB: Verifying ECDSA signature...")
        is_valid = ecdsa_utils.verify_signature(
            restored_hash,  # The hash of the restored model
            extracted_sig_bytes,  # The extracted signature
            self.vk  # The public verification key
        )

        return is_valid