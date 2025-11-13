import unittest
import os
import numpy as np

# Import from your project package (assumes `pip install -e .`)
from src.integrity_ctrl.io import mesh_utils
from src.integrity_ctrl.watermarking.qim import QIMClear  # Import our plaintext QIM class


class TestQIMClear(unittest.TestCase):
    """
    Tests the full plaintext (clear) QIM cycle:
    Load -> Quantify -> Embed -> Extract -> De-quantify -> Save
    """

    @classmethod
    def setUpClass(cls):
        """
        Set up parameters and paths for the test.
        """
        # --- Parameters ---
        cls.QIM_STEP = 100  # Must be > 0
        cls.WATERMARK_LENGTH = 1000  # Number of bits to embed
        cls.QUANT_FACTOR = 10 ** 6  # 6 decimal places of precision

        # --- Initialize the QIM module ---
        cls.qim = QIMClear(cls.QIM_STEP, cls.WATERMARK_LENGTH)

        # --- Files ---
        cls.input_file = "data/meshes/casting.obj"
        cls.output_dir = "outputs/tests/test03"
        cls.output_file = os.path.join(cls.output_dir, "watermarked_qim_casting.obj")

        os.makedirs(cls.output_dir, exist_ok=True)
        cls.assertTrue(os.path.exists(cls.input_file), "Test model not found")

    def tearDown(self):
        """
        Clean up created files after tests.
        """
        if os.path.exists(self.output_file):
            os.remove(self.output_file)

    def test_full_qim_cycle(self):
        """
        Executes the full plaintext QIM pipeline.
        """
        print("\n[Test QIM Clear] Running: test_full_qim_cycle")

        # 1. Load the 3D model
        print("  (1/7) Loading model...")
        model_data = mesh_utils.load_3d_model(self.input_file)
        self.assertIsNotNone(model_data)
        original_vertices = model_data["vertices"]
        original_faces = model_data["faces"]

        # Check that the model is large enough for the watermark
        self.assertGreater(
            original_vertices.flatten().size, self.WATERMARK_LENGTH,
            "Model is too small for the defined watermark length."
        )

        # 2. Quantify
        print("  (2/7) Quantifying vertices...")
        quantized_vertices = (original_vertices * self.QUANT_FACTOR).astype(np.int64)

        # 3. Generate and embed the watermark
        print("  (3/7) Generating watermark...")
        watermark = self.qim.generate_watermark()
        self.assertEqual(len(watermark), self.WATERMARK_LENGTH)

        print("  (4/7) Embedding watermark...")
        watermarked_q_vertices = self.qim.embed(quantized_vertices, watermark)

        # 4. Extract the watermark
        print("  (5/7) Extracting watermark...")
        extracted_watermark = self.qim.extract(watermarked_q_vertices)

        # 5. Verify the watermark (the most important step)
        print("  (6/7) Verifying watermark...")
        np.testing.assert_array_equal(
            watermark,
            extracted_watermark,
            "Extracted watermark does not match the original!"
        )
        print("  -> Watermark integrity VERIFIED.")

        # 6. De-quantify the watermarked model
        print("  (7/7) De-quantifying and saving watermarked model...")
        final_watermarked_vertices = watermarked_q_vertices.astype(float) / self.QUANT_FACTOR

        # 7. Save
        mesh_utils.save_3d_model(
            final_watermarked_vertices,
            original_faces,
            self.output_file
        )
        self.assertTrue(os.path.exists(self.output_file))
        print(f"  -> Watermarked model saved to {self.output_file}")

        print("[Test QIM Clear] Full QIM cycle PASSED.")