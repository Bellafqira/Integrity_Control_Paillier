import unittest
import os
import numpy as np
import pickle  # Needed for serialization

# --- New imports ---
from phe import paillier
# ------------------------------

# Import from your project package (assumes `pip install -e .`)
from src.integrity_ctrl.io import mesh_utils


class TestPheCrypto(unittest.TestCase):
    """
    Tests the core encryption/decryption of model vertices
    using the 'pure-python-phe' library, including serialization.
    """

    @classmethod
    def setUpClass(cls):
        """
        Set up the Paillier context and load the model once.
        Key generation is slow, so we do it once.
        """
        print("\n[Test PHE Crypto] Initializing PHE Paillier keys (1024-bit)...")
        cls.public_key, cls.private_key = paillier.generate_paillier_keypair(n_length=1024)
        print("[Test PHE Crypto] Keys generated.")

        cls.model_path = "data/meshes/casting.obj"
        cls.assertTrue(os.path.exists(cls.model_path), "Test model not found")

        model_data = mesh_utils.load_3d_model(cls.model_path)
        cls.assertIsNotNone(model_data, "Failed to load test model")

        cls.sample_vertices = model_data["vertices"][:10]  # First 10 vertices
        cls.quant_factor = 10 ** 6

    def setUp(self):
        """
        Set up paths for serialized files.
        """
        self.output_dir = "outputs/tests/test02"
        self.pub_key_file = os.path.join(self.output_dir, "test_pub.key")
        self.priv_key_file = os.path.join(self.output_dir, "test_priv.key")
        self.model_data_file = os.path.join(self.output_dir, "test_model_phe.npy")

        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

    def tearDown(self):
        """
        Clean up created files.
        """
        for f in [self.pub_key_file, self.priv_key_file, self.model_data_file]:
            if os.path.exists(f):
                os.remove(f)

    def test_01_quantization(self):
        """
        Tests that float vertices can be correctly converted to integers.
        """
        print("[Test PHE Crypto] Running: test_01_quantization")
        quantized_sample = (self.sample_vertices * self.quant_factor).astype(np.int64)
        self.assertEqual(quantized_sample.shape, self.sample_vertices.shape)
        self.assertNotIsInstance(quantized_sample[0, 0], float)
        # Note: numpy scalars are not base python types
        self.assertIsInstance(quantized_sample[0, 0], np.int64)
        print("[Test PHE Crypto] Quantization PASSED.")

    def test_02_encrypt_decrypt_cycle(self):
        """
        Tests a full encrypt -> decrypt cycle on vertex data (in memory).
        """
        print("[Test PHE Crypto] Running: test_02_encrypt_decrypt_cycle")

        # 1. Prepare data (quantize)
        quantized_data = (self.sample_vertices * self.quant_factor).astype(np.int64)

        # 2. Encrypt
        print("  Encrypting sample...")
        # Flatten for easier encryption
        flat_data = quantized_data.flatten()
        encrypted_data = np.array(
            [self.public_key.encrypt(int(c)) for c in flat_data], # Cast to int
            dtype=object
        )
        # Reshape
        encrypted_data = encrypted_data.reshape(quantized_data.shape)

        # 3. Decrypt
        print("  Encryption done. Decrypting...")
        flat_encrypted = encrypted_data.flatten()
        decrypted_data = np.array(
            [self.private_key.decrypt(c_enc) for c_enc in flat_encrypted],
            dtype=np.int64
        )
        decrypted_data = decrypted_data.reshape(quantized_data.shape)

        # 4. Compare
        print("  Decryption done. Comparing arrays...")
        np.testing.assert_array_equal(quantized_data, decrypted_data)
        print("[Test PHE Crypto] Encrypt/Decrypt cycle PASSED.")

    def test_03_homomorphic_addition(self):
        """
        Tests the homomorphic addition feature of PHE.
        """
        print("[Test PHE Crypto] Running: test_03_homomorphic_addition")
        m1, m2 = 12345, 67890
        c1, c2 = self.public_key.encrypt(m1), self.public_key.encrypt(m2)
        c_sum = c1 + c2
        decrypted_sum = self.private_key.decrypt(c_sum)

        self.assertEqual(decrypted_sum, m1 + m2)
        print("[Test PHE Crypto] Homomorphic addition PASSED.")

    def test_04_save_load_encrypted_model(self):
        """
        Tests serializing (saving) and deserializing (loading)
        an encrypted model and its keys.
        """
        print("[Test PHE Crypto] Running: test_04_save_load_encrypted_model")

        # 1. Prepare and encrypt data (as in test_02)
        quantized_data = (self.sample_vertices * self.quant_factor).astype(np.int64)
        flat_data = quantized_data.flatten()
        encrypted_data = np.array(
            [self.public_key.encrypt(int(c)) for c in flat_data], # Cast to int
            dtype=object
        ).reshape(quantized_data.shape)

        # 2. Save keys (with pickle)
        print(f"  Saving keys to {self.output_dir}...")
        with open(self.pub_key_file, 'wb') as f:
            pickle.dump(self.public_key, f)
        with open(self.priv_key_file, 'wb') as f:
            pickle.dump(self.private_key, f)

        # 3. Save the encrypted model (with numpy + pickle)
        print(f"  Saving encrypted model to {self.model_data_file}...")
        np.save(self.model_data_file, encrypted_data, allow_pickle=True)

        # --- Simulate a new session (deleting variables) ---
        print("  Data saved. Simulating new session (deleting variables)...")
        # del encrypted_data
        # del self.public_key
        # del self.private_key

        # 4. Load keys
        print("  Loading keys...")
        with open(self.pub_key_file, 'rb') as f:
            loaded_pub_key = pickle.load(f)
        with open(self.priv_key_file, 'rb') as f:
            loaded_priv_key = pickle.load(f)

        self.assertIsInstance(loaded_pub_key, paillier.PaillierPublicKey)
        self.assertIsInstance(loaded_priv_key, paillier.PaillierPrivateKey)

        # 5. Load the encrypted model data
        print("  Loading encrypted model...")
        loaded_encrypted_data = np.load(self.model_data_file, allow_pickle=True)
        self.assertEqual(loaded_encrypted_data.shape, quantized_data.shape)
        self.assertIsInstance(loaded_encrypted_data[0, 0], paillier.EncryptedNumber)

        # 6. Decrypt with the loaded keys
        print("  Decrypting loaded model with loaded keys...")
        flat_loaded_data = loaded_encrypted_data.flatten()
        decrypted_data = np.array(
            [loaded_priv_key.decrypt(c) for c in flat_loaded_data],
            dtype=np.int64
        ).reshape(quantized_data.shape)

        # 7. Compare
        print("  Comparing final data...")
        np.testing.assert_array_equal(
            quantized_data,
            decrypted_data,
            err_msg="Decrypted data after loading does not match original!"
        )
        print("[Test PHE Crypto] Save/Load encrypted model PASSED.")

        # --- Restore keys for other tests ---
        cls = self.__class__
        cls.public_key, cls.private_key = paillier.generate_paillier_keypair(n_length=1024)

    def test_05_save_encrypted_model_obj(self):
        """
        Tests serializing (saving) an encrypted model in obj format to be displayed.
        """
        print("[Test PHE Crypto] Running: test_05_save_encrypted_model_obj")

        # 1. Prepare and encrypt data (as in test_02)
        quantized_data = (self.sample_vertices * self.quant_factor).astype(np.int64)
        flat_data = quantized_data.flatten()
        encrypted_data = np.array(
            [self.public_key.encrypt(int(c)) for c in flat_data],
            dtype=object
        ).reshape(quantized_data.shape)

        # 2. Save keys (with pickle)
        print(f"  Saving keys to {self.output_dir}...")
        with open(self.pub_key_file, 'wb') as f:
            pickle.dump(self.public_key, f)
        with open(self.priv_key_file, 'wb') as f:
            pickle.dump(self.private_key, f)

        # 3. Save the encrypted model (with numpy + pickle)
        print(f"  Saving encrypted model to {self.model_data_file}...")
        np.save(self.model_data_file, encrypted_data, allow_pickle=True)