import numpy as np
from typing import Sequence
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
    MAX_TRIALS = 100

    def __init__(
        self,
        public_key: paillier.PaillierPublicKey,
        watermark_length: int,
    ):
        """
        Initializes the PSB Parity scheme.

        Args:
            public_key: PHE Paillier public key.
            watermark_length: Number of bits in the watermark.
        """
        self.public_key = public_key
        self.watermark_length = int(watermark_length)
        print(f"PSB_Parity (LSB) initialized (length={self.watermark_length} bits).")

    def _get_parity(self, c: paillier.EncryptedNumber) -> int:
        """Reads the LSB parity (0 or 1) of the ciphertext."""
        # Pré-bind de ciphertext est possible ailleurs, mais ici on garde simple
        return c.ciphertext(be_secure=False) & 1  # & 1 plus rapide que % 2

    def generate_watermark(self, *args, **kwargs) -> list[int]:
        """Generates a random binary watermark."""
        bits = np.random.randint(0, 2, size=self.watermark_length, dtype=np.uint8)
        return bits.tolist()

    def embed(
        self,
        encrypted_host_data: np.ndarray,
        watermark_bits: Sequence[int],
    ) -> np.ndarray:
        """
        Embeds the watermark by forcing the LSB parity of the ciphertext.
        """
        print(f"PSB_Parity: Embedding {self.watermark_length} bits...")

        watermarked_data = encrypted_host_data.copy()
        flat_data = watermarked_data.ravel()  # vue, pas de copie

        n = min(self.watermark_length, flat_data.size)
        if len(watermark_bits) < n:
            raise ValueError(
                f"watermark_bits too short: got {len(watermark_bits)}, expected at least {n}."
            )

        # Pré-bind pour réduire l’overhead dans la boucle
        get_parity = self._get_parity
        encrypt_zero = self.public_key.encrypt
        max_trials = self.MAX_TRIALS

        for i in range(n):
            target_bit = 1 if watermark_bits[i] else 0
            current_c = flat_data[i]
            current_bit = get_parity(current_c)

            trials = 0
            # Si le bit est déjà correct, on skip direct
            while current_bit != target_bit and trials < max_trials:
                # E(0, r) a ~50% de chance de changer la parité
                c_random = encrypt_zero(0)
                current_c = current_c + c_random
                current_bit = get_parity(current_c)
                trials += 1

            if trials == max_trials and current_bit != target_bit:
                # On log seulement si vraiment on n’a pas atteint la parité
                print(
                    f"  WARNING: Failed to embed bit {i} "
                    f"(max trials reached). Bit left as {current_bit}, "
                    f"target was {target_bit}."
                )

            flat_data[i] = current_c

        return watermarked_data.reshape(encrypted_host_data.shape)

    def extract(self, watermarked_data: np.ndarray) -> list[int]:
        """
        Extracts the watermark by reading the LSB parity of the ciphertext.
        """
        print(f"PSB_Parity: Extracting {self.watermark_length} bits...")

        flat_data = watermarked_data.ravel()
        n = min(self.watermark_length, flat_data.size)
        get_parity = self._get_parity

        # list comprehension plus rapide qu’un append dans une boucle
        return [get_parity(flat_data[i]) for i in range(n)]
