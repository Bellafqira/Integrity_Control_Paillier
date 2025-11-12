import numpy as np
from watermarks.watermark import AbstractWatermarkingScheme
from utils.paillier_context import PaillierContext


class PSB_Watermark(AbstractWatermarkingScheme):
    """
    Implements a Probabilistic Self-Blinding (PSB) scheme.

    This scheme embeds a binary watermark directly over existing
    encrypted data. It reads the "natural" bit of a ciphertext
    (based on its position in Z_N2) and "flips" the ciphertext
    using self-blinding if the natural bit does not match the
    target watermark bit.

    This is "probabilistic" because the underlying plaintext is
    unmodified, and the effect of the flip on the decrypted
    data is probabilistic.
    """

    def __init__(self, paillier_context: PaillierContext, watermark_length: int):
        """
        Initializes the PSB scheme.

        Args:
            paillier_context (PaillierContext): The crypto engine.
            watermark_length (int): The number of bits in the watermark.
        """
        super().__init__(paillier_context)
        self.watermark_length = watermark_length
        self.secret_key = None  # No specific secret key for this scheme

        # Pre-calculate the threshold for bit extraction
        self.threshold = (self.paillier.N2 + 1) // 2
        print(f"PSB_Watermark initialized for {watermark_length} bits.")

    def _extract_bit_from_ciphertext(self, c: 'mpz') -> int:
        """
        Helper function to extract the "natural" bit from a ciphertext.
        Checks if the ciphertext is in the 'positive' or 'negative'
        half of the Z_N2 space.

        Args:
            c (mpz): The ciphertext.

        Returns:
            int: 0 or 1.
        """
        return 1 if c >= self.threshold else 0

    def generate_watermark(self, *args, **kwargs) -> list:
        """
        Generates a random binary watermark.

        Returns:
            list: A list of 0s and 1s of length 'self.watermark_length'.
        """
        print(f"PSB: Generating {self.watermark_length}-bit random watermark...")
        return list(np.random.randint(0, 2, self.watermark_length))

    def embed(self, host_data: np.array, watermark_bits: list) -> np.array:
        """
        Embeds the watermark in the ENCRYPTED domain using PSB.

        It compares the target bit with the current "natural" bit
        of the ciphertext and flips it (c -> -c) if they differ.

        Args:
            host_data (np.array): The *encrypted* vertex data.
            watermark_bits (list): The list of watermark bits to embed.

        Returns:
            np.array: The PSB-watermarked encrypted data.
        """
        print("PSB: Embedding watermark in encrypted domain...")
        if len(watermark_bits) != self.watermark_length:
            raise ValueError(
                f"Watermark length mismatch. Expected {self.watermark_length}, "
                f"got {len(watermark_bits)}"
            )

        self.host_data = host_data
        watermarked_data = self.host_data.copy()

        for i in range(self.watermark_length):
            idx_v = i // 3
            idx_c = i % 3

            ciphertext = watermarked_data[idx_v][idx_c]

            # 1. Read the current bit
            current_bit = self._extract_bit_from_ciphertext(ciphertext)

            # 2. Get the target bit
            target_bit = watermark_bits[i]

            # 3. Flip *only if* they do not match
            if current_bit != target_bit:
                watermarked_data[idx_v][idx_c] = self.paillier.deterministic_self_blind(
                    ciphertext
                )

        self.watermarked_data = watermarked_data
        return self.watermarked_data

    def extract(self, watermarked_data: np.array) -> list:
        """
        Extracts the embedded watermark from the ENCRYPTED domain.

        It simply reads the "natural" bit from each ciphertext
        in the watermark space.

        Args:
            watermarked_data (np.array): The watermarked encrypted data.

        Returns:
            list: The extracted list of watermark bits.
        """
        print("PSB: Extracting watermark from encrypted domain...")
        extracted_bits = []

        for i in range(self.watermark_length):
            idx_v = i // 3
            idx_c = i % 3

            ciphertext = watermarked_data[idx_v][idx_c]

            # Read the bit from the ciphertext
            bit = self._extract_bit_from_ciphertext(ciphertext)
            extracted_bits.append(bit)

        return extracted_bits