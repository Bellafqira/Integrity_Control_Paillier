import numpy as np


class QIMClear:
    """
    Implements the standard Quantization Index Modulation (QIM) scheme.

    This version uses the "Index Parity" method requested by the user.
    - Bit 0 is mapped to EVEN bin indices.
    - Bit 1 is mapped to ODD bin indices.
    """

    def __init__(self, qim_step: int):
        """
        Initializes the plaintext QIM scheme.

        Args:
            qim_step (int): The quantization step (q).
        """
        self.watermark_length = None
        if qim_step <= 0:
            raise ValueError("qim_step must be positive")

        self.delta = qim_step  # The 'delta' from the paper

        self.secret_key = {"qim_step": qim_step}
        print(f"QIMClear (Index Parity) initialized with q_step={qim_step}.")

    def generate_watermark(self, watermark_length: int) -> np.ndarray:
        """
        Generates a random binary watermark.
        """
        self.watermark_length = watermark_length
        print(f"QIMClear: Generating {self.watermark_length}-bit watermark...")
        return np.random.randint(0, 2, self.watermark_length)

    import numpy as np

    def embed(self, clear_data: np.ndarray, watermark_bits: np.ndarray) -> np.ndarray:
        """
        Embeds the QIM watermark in PLAINTEXT domain using index parity.

        Logic:
            w_test = [x/delta] % 2
            if w_test == w:
                x_wat = [x/delta] * delta + delta/2
            else:
                x_wat = [x/delta] * delta - delta/2
        """
        # Optional: remove or gate behind a verbose flag for speed
        print("QIMClear: Embedding watermark (Index Parity)...")

        watermarked_data = clear_data.copy()
        flat_data = watermarked_data.ravel()  # view, no extra copy

        n_bits = len(watermark_bits)
        if n_bits == 0:
            return watermarked_data

        if n_bits > flat_data.size:
            raise ValueError(
                f"Not enough samples to embed watermark: "
                f"{n_bits} bits for {flat_data.size} values."
            )

        # Work only on the slice we actually watermark
        target = flat_data[:n_bits]

        delta = self.delta
        half_delta = delta // 2

        # Vectorized computations
        bits = np.asarray(watermark_bits, dtype=np.int64)  # shape (n_bits)
        bin_index = target // delta  # [x/delta]
        w_test = bin_index & 1  # [x/delta] % 2
        bin_start = bin_index * delta  # [x/delta] * delta

        # Mask where parity matches
        mask = (w_test == bits)

        # Apply QIM rule
        target[:] = np.where(mask,
                             bin_start + half_delta,  # match
                             bin_start - half_delta)  # mismatch

        return watermarked_data

    def extract(self, clear_data: np.ndarray) -> np.ndarray:
        """
        Extracts the QIM watermark from PLAINTEXT data.

        Logic:
            w_ext = (x // delta) % 2
        """
        print("QIMClear: Extracting watermark (Index Parity)...")

        # Flatten as a view (no copy)
        flat = clear_data.ravel()

        # Vectorized extraction on first n elements
        delta = self.delta
        extracted_bits = (flat // delta) & 1  # faster than % 2

        return extracted_bits.astype(np.uint8)
