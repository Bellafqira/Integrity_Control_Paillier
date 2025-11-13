import numpy as np


class QIMClear:
    """
    Implements the standard Quantization Index Modulation (QIM) scheme.

    This version uses the "Index Parity" method requested by the user.
    - Bit 0 is mapped to EVEN bin indices.
    - Bit 1 is mapped to ODD bin indices.
    """

    def __init__(self, qim_step: int, watermark_length: int):
        """
        Initializes the plaintext QIM scheme.

        Args:
            qim_step (int): The quantization step (q).
            watermark_length (int): The number of bits in the QIM watermark.
        """
        if qim_step <= 0:
            raise ValueError("qim_step must be positive")

        self.q = qim_step  # The 'q' from your formulas

        self.watermark_length = watermark_length
        self.secret_key = {"qim_step": qim_step}
        print(f"QIMClear (Index Parity) initialized with q_step={qim_step}.")

    def generate_watermark(self, *args, **kwargs) -> list:
        """
        Generates a random binary watermark.
        """
        print(f"QIMClear: Generating {self.watermark_length}-bit watermark...")
        return list(np.random.randint(0, 2, self.watermark_length))

    def embed(self, clear_data: np.array, watermark_bits: list) -> np.array:
        """
        Embeds the QIM watermark in PLAINTEXT domain using user's logic.

        Logic:
        w_test = [x/q] % 2
        if w_test == w:
            x_wat = [x/q] * q
        else:
            x_wat = [x/q] * q + q
        """
        print("QIMClear: Embedding watermark (Index Parity)...")
        watermarked_data = clear_data.copy()

        # Flatten data for easy insertion
        flat_data = watermarked_data.flatten()

        for i in range(len(watermark_bits)):
            val = flat_data[i]  # 'x'
            bit = watermark_bits[i]  # 'w'

            # 1. Calculate bin index
            # This is your [x/q] (integer division)
            bin_index = val // self.q

            # 2. Calculate "natural" bit
            # This is your [x/q] % 2
            w_test = bin_index % 2

            # 3. Calculate bin start
            # This is your [x/q] * q
            bin_start = bin_index * self.q

            # 4. Apply logic
            if w_test == bit:
                # Bit matches. Quantize to the start of this bin.
                flat_data[i] = bin_start + self.q//2
            else:
                # Bit mismatch. Move to the start of the *next* bin
                # (which will have the opposite bit parity).
                flat_data[i] = bin_start - self.q//2

        # Reshape
        return flat_data.reshape(watermarked_data.shape)

    def extract(self, clear_data: np.array) -> list:
        """
        Extracts the QIM watermark from PLAINTEXT data.

        Logic:
        w_ext = [x_wat / q] % 2
        """
        print("QIMClear: Extracting watermark (Index Parity)...")
        extracted_bits = []

        # Flatten data for easy extraction
        flat_data = clear_data.flatten()

        for i in range(self.watermark_length):
            val = flat_data[i]  # 'x_wat'

            # 1. Calculate bin index
            # This is your [x_wat / q]
            bin_index = val // self.q

            # 2. Calculate the bit
            # This is your [x_wat / q] % 2
            w_ext = bin_index % 2

            extracted_bits.append(w_ext)

        return extracted_bits