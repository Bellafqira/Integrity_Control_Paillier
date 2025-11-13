import unittest
import os
import numpy as np
from phe import paillier

# Import from your project package (assumes `pip install -e .`)
from src.integrity_ctrl.io import mesh_utils
from src.integrity_ctrl.watermarking.qim import QIMClear  # Plaintext extraction/embedding module
from src.integrity_ctrl.watermarking.sqim import SQIM  # Encrypted embedding module


class TestCompositeQIM(unittest.TestCase):
    """
    Tests the complete composite watermarking pipeline:
    1. Plaintext QIM(w=0)
    2. Encrypt
    3. Encrypted SQIM(w=watermark)
    4. Decrypt
    5. Plaintext QIMExtract() -> must extract 'watermark'
    """

    # Class-level variables to store setup data
    public_key = None
    private_key = None
    qim_clear = None
    sqim = None
    pre_watermark = None
    watermark = None
    original_vertices = None
    original_faces = None

    QIM_STEP = 100
    WATERMARK_LENGTH = 1000
    KEY_SIZE = 1024
    QUANT_FACTOR = 10 ** 6
    input_file = "data/meshes/casting.obj"

    @classmethod
    def setUpClass(cls):
        """
        Initializes all necessary components once.
        (This is for heavy, shared setup)
        """
        # --- Parameters ---
        print("\n[Test Composite QIM] Generating PHE Paillier keys...")
        cls.public_key, cls.private_key = paillier.generate_paillier_keypair(n_length=cls.KEY_SIZE)

        # Initialize the two watermarking modules
        cls.qim_clear = QIMClear(cls.QIM_STEP, cls.WATERMARK_LENGTH)
        cls.sqim = SQIM(cls.public_key, cls.QIM_STEP, cls.WATERMARK_LENGTH)

        # --- Create watermarks (as requested) ---
        print("Generating watermarks...")
        # 1. The pre-watermark (all zeros)
        cls.pre_watermark = [0] * cls.WATERMARK_LENGTH

        # 2. The second (random) watermark
        cls.watermark = cls.qim_clear.generate_watermark()
        # Ensure it's not empty or all zeros for a good test
        if all(bit == 0 for bit in cls.watermark):
            cls.watermark[0] = 1

        # --- Load the model ---
        print("Loading test model...")

        # --- FIX 1 ---
        # Do not use cls.assertTrue. Use a standard Python check.
        if not os.path.exists(cls.input_file):
            raise FileNotFoundError(f"Test model not found: {cls.input_file}")

        model_data = mesh_utils.load_3d_model(cls.input_file)

        # --- FIX 2 ---
        # Do not use cls.assertIsNotNone. Use a standard Python check.
        if model_data is None:
            raise ValueError(f"Failed to load test model from {cls.input_file}")
        # --- END FIX ---

        cls.original_vertices = model_data["vertices"]
        cls.original_faces = model_data["faces"]

        # --- FIX 3 ---
        # Do not use cls.assertGreater. Use a standard Python check.
        if cls.original_vertices.size <= cls.WATERMARK_LENGTH:
            raise ValueError(
                f"Model is too small ({cls.original_vertices.size} coords) "
                f"for the defined watermark length ({cls.WATERMARK_LENGTH})."
            )
        # --- END FIX ---

    def test_full_composite_pipeline(self):
        """
        Executes the full test scenario as requested by the user.
        """
        print("\n[Test Composite QIM] Running: test_full_composite_pipeline")

        # 1. Quantify the model
        print("  (1/7) Quantifying model...")
        quantized_vertices = (self.original_vertices * self.QUANT_FACTOR).astype(np.int64)

        # 2. Embed the pre-watermark (w=0) with QIMClear
        print("  (2/7) Embedding pre-watermark (w=0) in plaintext...")
        pre_watermarked_data = self.qim_clear.embed(
            quantized_vertices,
            self.pre_watermark
        )

        # Optional check: extraction must yield zeros
        # (Here we CAN use self.assertEqual)
        test_extract = self.qim_clear.extract(pre_watermarked_data)
        self.assertEqual(test_extract, self.pre_watermark, "Pre-watermark embedding failed.")

        # 3. Encrypt this model
        print("  (3/7) Encrypting pre-watermarked model...")
        # We only need to encrypt the part we are going to use
        flat_data_to_encrypt = pre_watermarked_data.flatten()[:self.WATERMARK_LENGTH]

        encrypted_data = np.array(
            [self.public_key.encrypt(int(c)) for c in flat_data_to_encrypt],
            dtype=object
        )

        # 4. Embed the second (random) watermark with SQIM
        print("  (4/7) Embedding second watermark in encrypted domain...")
        final_encrypted_data = self.sqim.embed(encrypted_data, self.watermark)

        # 5. Decrypt the final model
        print("  (5/7) Decrypting final model...")
        decrypted_data = np.array(
            [self.private_key.decrypt(c) for c in final_encrypted_data],
            dtype=np.int64
        )

        # 6. Extract the watermark with QIMClear
        print("  (6/7) Extracting final watermark in plaintext...")
        extracted_watermark = self.qim_clear.extract(decrypted_data)

        # 7. Compare the extracted watermark to the *second* watermark
        print("  (7/7) Verifying watermark...")
        self.assertListEqual(
            list(self.watermark),
            list(extracted_watermark),
            "Extracted watermark does not match the second embedded watermark!"
        )

        print("[Test Composite QIM] Composite pipeline PASSED.")