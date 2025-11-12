import numpy as np
from watermarks.watermark import AbstractWatermarkingScheme
from utils.paillier_context import PaillierContext


class SQIM(AbstractWatermarkingScheme):
    """
    Implements the Secured QIM (SQIM) watermarking scheme.

    This class operates on ENCRYPTED data for embedding.
    It corresponds to the user's 'Class SQIM'.

    - Embedding is done in the ENCRYPTED domain via homomorphic addition.
    - Extraction is NOT possible in the encrypted domain.
    """

    def __init__(self, paillier_context: PaillierContext, qim_step: int, watermark_length: int):
        """
        Initializes the SQIM scheme.

        Args:
            paillier_context (PaillierContext): The crypto engine.
            qim_step (int): The quantization step for QIM.
            watermark_length (int): The number of bits in the watermark.
        """
        super().__init__(paillier_context)  # Pass the context to parent
        self.qim_step = qim_step
        self.watermark_length = watermark_length
        self.secret_key = {"qim_step": qim_step}

        # Pre-compute E(qim_step) for efficient embedding
        print(f"SQIM (encrypted): Pre-computing E(qim_step={qim_step})...")
        self.encrypted_qim_step = self.paillier.encrypt_deterministic(self.qim_step)

    def generate_watermark(self, *args, **kwargs) -> list:
        """
        Generates a random binary watermark.

        Returns:
            list: A list of 0s and 1s of length 'self.watermark_length'.
        """
        print(f"SQIM: Generating {self.watermark_length}-bit watermark...")
        return list(np.random.randint(0, 2, self.watermark_length))

    def embed(self, host_data: np.array, watermark_bits: list) -> np.array:
        """
        Embeds the QIM watermark in the ENCRYPTED domain.

        Logic: If watermark_bit[i] is 1, homomorphically add E(qim_step)
               to the corresponding ciphertext.
               E(v') = E(v) * E(qim_step)  <==>  E(v + qim_step)

        Args:
            host_data (np.array): The *encrypted* vertex data.
            watermark_bits (list): The list of watermark bits to embed.

        Returns:
            np.array: The QIM-watermarked encrypted data.
        """
        print("SQIM: Embedding watermark in encrypted domain...")
        self.host_data = host_data
        watermarked_data = self.host_data.copy()

        for i in range(len(watermark_bits)):
            if watermark_bits[i] == 1:
                # Get 3D index (vertex_index, coordinate_index)
                idx_v = i // 3
                idx_c = i % 3

                # E(v') = E(v) * E(qim_step)
                watermarked_data[idx_v][idx_c] = self.paillier.homomorphic_add(
                    watermarked_data[idx_v][idx_c],
                    self.encrypted_qim_step
                )

        self.watermarked_data = watermarked_data
        return self.watermarked_data

    def extract(self, watermarked_data: np.array) -> object:
        """
        Extraction for SQIM is not possible in the encrypted domain.

        This method raises an error to enforce the correct pipeline,
        which is to decrypt first, then use QIMClear.extract().
        """
        raise NotImplementedError(
            "SQIM extraction is not possible in the encrypted domain. "
            "You must decrypt the data first, then use the 'QIMClear' class "
            "to extract from the plaintext."
        )