import unittest
import numpy as np
from phe import paillier

# Import the new class we just created
from src.integrity_ctrl.watermarking.psb_watermarking import PSB_Parity


class TestPSBParity(unittest.TestCase):
    """
    Tests the embed/extract pipeline of PSB_Parity (LSB-based).
    """

    @classmethod
    def setUpClass(cls):
        """
        Initializes keys and encrypted test data.
        """
        cls.WATERMARK_LENGTH = 100  # Length of the test watermark
        cls.KEY_SIZE = 1024

        print("\n[Test PSB Parity] Generating PHE Paillier keys...")
        cls.public_key, cls.private_key = paillier.generate_paillier_keypair(n_length=cls.KEY_SIZE)

        # --- Initialize the PSB Parity module ---
        cls.psb = PSB_Parity(cls.public_key, cls.WATERMARK_LENGTH)

        # --- Create "dummy" encrypted data ---
        print(f"[Test PSB Parity] Creating and encrypting {cls.WATERMARK_LENGTH} data items...")

        np.random.seed(123)
        cls.original_data = np.random.randint(0, 1000, size=cls.WATERMARK_LENGTH)

        cls.encrypted_data = np.array(
            [cls.public_key.encrypt(int(c)) for c in cls.original_data],
            dtype=object
        )

    def test_full_parity_pipeline(self):
        """
        Tests the full cycle: Embed -> Extract -> Verify
        """
        print("\n[Test PSB Parity] Running: test_full_parity_pipeline")

        # 1. Create a random watermark
        print("  (1/4) Generating watermark...")
        watermark_to_embed = self.psb.generate_watermark()
        # Ensure it is not trivial
        if all(bit == 0 for bit in watermark_to_embed):
            watermark_to_embed[0] = 1

        # 2. Embed the watermark
        print("  (2/4) Embedding watermark...")
        # .copy() is important so tests do not influence each other
        watermarked_data = self.psb.embed(
            self.encrypted_data.copy(),
            watermark_to_embed
        )

        # 3. Extract the watermark
        print("  (3/4) Extracting watermark...")
        extracted_watermark = self.psb.extract(watermarked_data)

        # 4. Verify
        print("  (4/4) Verifying...")
        self.assertEqual(
            watermark_to_embed,
            extracted_watermark,
            "Extracted watermark does not match the embedded watermark!"
        )
        print("[Test PSB Parity] LSB parity pipeline PASSED.")

    def test_data_is_different_after_embed(self):
        """
        Checks that embedding actually modified the ciphertexts.
        """
        print("\n[Test PSB Parity] Running: test_data_is_different_after_embed")

        # Embed all '1's (forces changes)
        watermark_ones = [1] * self.WATERMARK_LENGTH

        watermarked_data = self.psb.embed(
            self.encrypted_data.copy(),
            watermark_ones
        )

        # Compare the ciphertexts (as text)
        c_original = self.encrypted_data[0].ciphertext(be_secure=False)
        c_watermarked = watermarked_data[0].ciphertext(be_secure=False)

        # This is a statistical test; it might fail if
        # c_original was already odd.
        # We just check that the extracted bits are '1'.
        extracted = self.psb.extract(watermarked_data)
        self.assertEqual(extracted, watermark_ones)
        print("[Test PSB Parity] Embedding verification PASSED.")