import numpy as np
from phe import paillier
from src.integrity_ctrl.watermarking.base import AbstractWatermarkingScheme


class PSB_Parity(AbstractWatermarkingScheme):
    """
    Implements 'Probabilistic Self-Blinding' (PSB)
    based on the parity (LSB) of the ciphertext.

    WARNING: This scheme is not secure. Exposing the LSB parity
    of the ciphertext can be a security vulnerability (Malleability attack).
    It is presented here for testing purposes.
    """

    # Max number of trials to find a matching parity
    # (to avoid an infinite loop, although statistically improbable)
    MAX_TRIALS = 100

    def __init__(self,
                 public_key: paillier.PaillierPublicKey,
                 watermark_length: int):
        """
        Initializes the PSB Parity scheme.

        Args:
            public_key (paillier.PaillierPublicKey): PHE Paillier public key.
            watermark_length (int): Number of bits in the watermark.
        """
        self.public_key = public_key
        self.watermark_length = watermark_length
        print(f"PSB_Parity (LSB) initialized (length={watermark_length} bits).")

    def _get_parity(self, c: paillier.EncryptedNumber) -> int:
        """ Reads the LSB parity (0 or 1) of the ciphertext. """
        return c.ciphertext(be_secure=False) % 2

    def generate_watermark(self, *args, **kwargs) -> list:
        """ Generates a random binary watermark. """
        return list(np.random.randint(0, 2, self.watermark_length))

    def embed(self, encrypted_host_data: np.array, watermark_bits: list) -> np.array:
        """
        Embeds the watermark by forcing the LSB parity of the ciphertext.
        """
        print(f"PSB_Parity: Embedding {self.watermark_length} bits...")

        # Copy to avoid modifying the original
        watermarked_data = encrypted_host_data.copy()
        flat_data = watermarked_data.flatten()

        for i in range(self.watermark_length):
            target_bit = watermark_bits[i]  # 0 (even) or 1 (odd)
            current_c = flat_data[i]

            current_bit = self._get_parity(current_c)

            trials = 0
            # Loop "find an r..."
            while current_bit != target_bit and trials < self.MAX_TRIALS:
                # E(0, r) has ~50% chance of being even, ~50% odd
                c_random = self.public_key.encrypt(0)

                # Homomorphic multiplication: c_new = c_old + c_random
                current_c = current_c + c_random
                current_bit = self._get_parity(current_c)
                trials += 1

            if trials == self.MAX_TRIALS:
                print(f"  WARNING: Failed to embed bit {i} "
                      f"(max trials reached). Bit left unchanged.")

            flat_data[i] = current_c

        return flat_data.reshape(encrypted_host_data.shape)

    def extract(self, watermarked_data: np.array) -> list:
        """
        Extracts the watermark by reading the LSB parity of the ciphertext.
        """
        print(f"PSB_Parity: Extracting {self.watermark_length} bits...")
        extracted_bits = []
        flat_data = watermarked_data.flatten()

        for i in range(self.watermark_length):
            extracted_bits.append(self._get_parity(flat_data[i]))

        return extracted_bits