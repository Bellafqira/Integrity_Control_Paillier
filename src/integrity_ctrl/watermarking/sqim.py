import numpy as np
# Import the abstract class from your project
from src.integrity_ctrl.watermarking.base import AbstractWatermarkingScheme
from phe import paillier  # Uses the PHE library


class SQIM(AbstractWatermarkingScheme):
    """
    Implements 'Secured QIM' (SQIM) in the ENCRYPTED domain
    using the 'phe' library.
    """

    def __init__(self, public_key: paillier.PaillierPublicKey, qim_step: int, watermark_length: int):
        """
        Initializes the SQIM scheme.

        Args:
            public_key (paillier.PaillierPublicKey): The PHE public key.
            qim_step (int): The quantization step 'q' to add.
            watermark_length (int): The number of bits in the watermark.
        """
        # We only need the public key for encryption
        self.public_key = public_key
        self.q = qim_step
        self.watermark_length = watermark_length
        self.secret_key = {"qim_step": qim_step}
        print(f"SQIM (Encrypted) initialized with q_step={qim_step}.")

    def generate_watermark(self, *args, **kwargs) -> list:
        """
        Generates a random binary watermark.
        """
        print(f"SQIM: Generating {self.watermark_length}-bit watermark...")
        return list(np.random.randint(0, 2, self.watermark_length))

    def embed(self, encrypted_host_data: np.array, watermark_bits: list) -> np.array:
        """
        Embeds the watermark in the ENCRYPTED domain.

        Logic (as requested):
        if w == 0: do nothing
        if w == 1: c_new = c + q (using homomorphic addition from PHE)
        """
        print("SQIM: Embedding watermark in encrypted domain...")

        # Copy the array to avoid modifying the original
        watermarked_data = encrypted_host_data.copy()

        # Flatten for easy iteration
        flat_data = watermarked_data.flatten()

        for i in range(self.watermark_length):
            bit = watermark_bits[i]

            if bit == 1:
                # This is the magic of PHE:
                # EncryptedNumber + plaintext_int = EncryptedNumber
                # E(m) + q -> E(m + q)
                flat_data[i] = flat_data[i] + self.q

            # If bit == 0, do nothing, as requested.

        # Reshape and return
        return flat_data.reshape(watermarked_data.shape)

    def extract(self, watermarked_data: np.array) -> object:
        """
        Extraction is not possible in the encrypted domain.
        """
        print("ERROR: SQIM extraction is not possible in the encrypted domain.")
        raise NotImplementedError(
            "SQIM extraction is not possible in the encrypted domain. "
            "You must decrypt the data first, then use the 'QIMClear' class."
        )