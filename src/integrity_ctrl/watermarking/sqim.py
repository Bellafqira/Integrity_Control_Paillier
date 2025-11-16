import numpy as np
from src.integrity_ctrl.watermarking.base import AbstractWatermarkingScheme
from phe import paillier


class SQIM(AbstractWatermarkingScheme):
    """
    Implements 'Secured QIM' (SQIM) in the ENCRYPTED domain using the 'phe' library.
    """

    def __init__(self, public_key: paillier.PaillierPublicKey, qim_step: int):
        """
        Initializes the SQIM scheme.

        Args:
            public_key (paillier.PaillierPublicKey): The PHE public key.
            qim_step (int): The quantization step 'delta' to add.
        """
        super().__init__()
        self.public_key = public_key
        self.delta = int(qim_step)
        self.watermark_length = None
        self.secret_key = {"qim_step": self.delta}

        print(f"SQIM (Encrypted) initialized with q_step={self.delta}.")

    def generate_watermark(self, watermark_length) -> np.ndarray:
        """
        Generates a random binary watermark.
        """
        self.watermark_length = watermark_length
        print(f"SQIM: Generating {self.watermark_length}-bit watermark...")
        # Use uint8 to be explicit, then convert to plain Python ints if needed
        bits = np.random.randint(0, 2, size=self.watermark_length, dtype=np.uint8)
        return bits

    def embed(self, encrypted_host_data: np.ndarray, watermark_bits: np.ndarray) -> np.ndarray:
        """
        Embeds the watermark in the ENCRYPTED domain.

        Logic:
            if w == 0: do nothing
            if w == 1: c_new = c + q  (homomorphic addition)
        """
        print("SQIM: Embedding watermark in encrypted domain...")

        # Safety checks
        self.watermark_length = len(watermark_bits)

        if len(watermark_bits) < self.watermark_length:
            raise ValueError(
                f"watermark_bits too short: got {len(watermark_bits)}, "
                f"expected at least {self.watermark_length}."
            )

        # Copy the array (shallow copy of object references)
        watermarked_data = encrypted_host_data.copy()

        # ravel() -> view when possible, avoids a full copy like flatten()
        flat_data = watermarked_data.ravel()

        if flat_data.size < self.watermark_length:
            raise ValueError(
                f"Not enough encrypted samples to embed watermark: "
                f"need {self.watermark_length}, have {flat_data.size}."
            )

        # Convert bits to a NumPy array for efficient masking
        bits = np.fromiter(
            (1 if b else 0 for b in watermark_bits[:self.watermark_length]),
            dtype=np.uint8,
            count=self.watermark_length,
        )

        # Indices where bit == 1 → only here where additions are expensive
        one_indices = np.nonzero(bits)[0]

        # Loop only on 1-bits
        delta = self.delta
        delta_enc = (1+delta*self.public_key.n)%self.public_key.nsquare
        for idx in one_indices:
            flat_data[idx] = (flat_data[idx]*delta_enc)%self.public_key.nsquare

        # flat_data is a view on watermarked_data, so reshape is cheap
        return watermarked_data.reshape(encrypted_host_data.shape)

    def extract(self, watermarked_data: np.ndarray) -> object:
        """
        Extraction is not possible in the encrypted domain.
        """
        print("ERROR: SQIM extraction is not possible in the encrypted domain.")
        raise NotImplementedError(
            "SQIM extraction is not possible in the encrypted domain. "
            "You must decrypt the data first, then use the 'QIMClear' class."
        )

    def set_watermark(self, watermark):
        self.secret_key["watermark"] = watermark
        self.watermark_length = len(watermark)