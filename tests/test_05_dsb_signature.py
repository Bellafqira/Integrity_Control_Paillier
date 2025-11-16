import unittest
import numpy as np
from phe import paillier

# Import from your project package (assumes `pip install -e .`)
from src.integrity_ctrl.watermarking.dsb_signature import DSB_Signature
from src.integrity_ctrl.crypto import ecdsa_utils # Corrected import


class TestDSBSignature(unittest.TestCase):
    """
    Tests the DSB (Deterministic Self-Blinding) signature pipeline
    using PHE and ECDSA.
    """

    @classmethod
    def setUpClass(cls):
        """
        Initializes keys and test data.
        """
        cls.SIGNATURE_LENGTH = 512  # 512 bits = 64 bytes

        print("\n[Test DSB] Generating Paillier (1024-bit) keys...")
        cls.public_key, cls.private_key = paillier.generate_paillier_keypair(n_length=128)

        print("[Test DSB] Generating ECDSA signature keys...")
        cls.signing_keys = ecdsa_utils.generate_signing_keys() # Corrected module name

        # --- Initialize the DSB module ---
        cls.dsb = DSB_Signature(
            cls.public_key,
            cls.signing_keys,
            cls.SIGNATURE_LENGTH
        )

        # --- Create a "dummy" encrypted model ---
        # (No need to load a real model, just encrypted data)
        # Large enough for the signature (512) + 10 others for the tampering test
        data_size = cls.SIGNATURE_LENGTH + 10
        print(f"[Test DSB] Creating and encrypting {data_size} test data items...")

        # Fill with random numbers (simulates real data)
        np.random.seed(42)
        cls.original_data = np.random.randint(0, 1000, size=data_size)

        cls.encrypted_data = np.array(
            [cls.public_key.encrypt(int(c)).ciphertext(be_secure=False) for c in cls.original_data],
            dtype=object
        )

    def test_full_signature_pipeline(self):
        """
        Tests the full cycle: Prepare -> Sign -> Embed -> Verify.
        """
        print("\n[Test DSB] Running: test_full_signature_pipeline")

        # 1. Prepare data (insert '0's)
        prepared_data = self.dsb.prepare_data_for_signing(self.encrypted_data)

        # 2. Generate the signature from the prepared data
        signature_bits, _ = self.dsb.generate_watermark(prepared_data)

        # 3. Embed the signature
        signed_data = self.dsb.embed(prepared_data, signature_bits)


        # 4. Verify
        is_valid = self.dsb.verify(signed_data)

        self.assertTrue(is_valid, "The valid signature was marked as INVALID.")
        print("[Test DSB] Valid signature pipeline PASSED.")

    def test_tampering_data_fails(self):
        """
        Tests that verification fails if data *outside* the
        signature is modified.
        """
        print("\n[Test DSB] Running: test_tampering_data_fails")

        # 1. Create a signed model (as in the previous test)
        prepared_data = self.dsb.prepare_data_for_signing(self.encrypted_data)
        signature_bits, _ = self.dsb.generate_watermark(prepared_data)
        signed_data = self.dsb.embed(prepared_data, signature_bits)

        # 2. Modify a part of the model *outside* the signature area
        # (index 512 is just after the 512-bit signature)
        print("  -> Tampering with model (outside signature)...")
        index_to_tamper = self.SIGNATURE_LENGTH

        # Tampering (homomorphic addition of '1')
        signed_data[index_to_tamper] = signed_data[index_to_tamper] + 1

        # 3. Verify
        is_valid = self.dsb.verify(signed_data)

        self.assertFalse(is_valid, "The tampered signature was marked as VALID.")
        print("[Test DSB] Tamper detection (data) PASSED.")

    def test_tampering_signature_fails(self):
        """
        Tests that verification fails if the signature *itself* is modified.
        """
        print("\n[Test DSB] Running: test_tampering_signature_fails")

        # 1. Create a signed model
        prepared_data = self.dsb.prepare_data_for_signing(self.encrypted_data)
        signature_bits, _ = self.dsb.generate_watermark(prepared_data)
        signed_data = self.dsb.embed(prepared_data, signature_bits)

        # 2. Modify one bit of the signature
        print("  -> Tampering with model (inside signature)...")
        signed_data[0] = self.dsb._flip_bit(signed_data[0])  # Flip the 1st bit

        # 3. Verify
        is_valid = self.dsb.verify(signed_data)

        self.assertFalse(is_valid, "The tampered signature was marked as VALID.")
        print("[Test DSB] Tamper detection (signature) PASSED.")