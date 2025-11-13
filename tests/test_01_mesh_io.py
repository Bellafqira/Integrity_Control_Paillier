import unittest
import os
import numpy as np
# Make sure PyMeshLab is installed (pip install pymeshlab)

# We import the real functions from your src package
# This import assumes you have run `pip install -e .`
from src.integrity_ctrl.io import mesh_utils


class TestMeshIO(unittest.TestCase):
    """
    Tests the read/write functionality for .obj files
    using the PyMeshLab utilities.
    """

    def setUp(self):
        """
        Set up test paths.
        """
        # Input file for tests
        self.input_file = "data/meshes/casting.obj"

        # Output folder for test results
        self.output_dir = "outputs/tests/test01"
        self.output_file = os.path.join(self.output_dir, "test_output_casting.obj")

        # Create the output folder if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)

        # Check that the input file exists
        self.assertTrue(os.path.exists(self.input_file),
                        f"Input test file not found: {self.input_file}")

    def tearDown(self):
        """
        Clean up created files after tests.
        """
        if os.path.exists(self.output_file):
            os.remove(self.output_file)

    def test_read_obj_file(self):
        """
        Tests that loading an .obj file with PyMeshLab works
        and returns the expected dictionary.
        """
        print("\n[Test IO] Running: test_read_obj_file")

        # Call the REAL loading function
        model_data = mesh_utils.load_3d_model(self.input_file)

        self.assertIsNotNone(model_data)
        self.assertIn("vertices", model_data)
        self.assertIn("faces", model_data)
        self.assertIsInstance(model_data["vertices"], np.ndarray)
        self.assertIsInstance(model_data["faces"], np.ndarray)
        self.assertGreater(len(model_data["vertices"]), 0)
        self.assertGreater(len(model_data["faces"]), 0)
        print("[Test IO] Read .obj file PASSED.")

    def test_read_write_integrity(self):
        """
        Tests that saving and then re-loading a model preserves the data.
        """
        print("\n[Test IO] Running: test_read_write_integrity")

        # 1. Load original data
        print(f" (1/4) Loading original model: {self.input_file}")
        original_data = mesh_utils.load_3d_model(self.input_file)
        self.assertIsNotNone(original_data)

        original_vertices = original_data["vertices"]
        original_faces = original_data["faces"]

        # 2. Save the data to a new file
        print(f" (2/4) Saving test model to: {self.output_file}")
        mesh_utils.save_3d_model(original_vertices,
                                 original_faces,
                                 self.output_file)

        # 3. Check that the output file was created
        self.assertTrue(os.path.exists(self.output_file),
                        f"Save failed. Output file not created at: {self.output_file}")

        # 4. Re-load the data from the *new* file
        print(f" (3/4) Re-loading model from: {self.output_file}")
        loaded_data = mesh_utils.load_3d_model(self.output_file)
        self.assertIsNotNone(loaded_data)

        loaded_vertices = loaded_data["vertices"]
        loaded_faces = loaded_data["faces"]

        # 5. Compare original and re-loaded data
        print(" (4/4) Comparing original and re-loaded data...")
        np.testing.assert_allclose(original_vertices, loaded_vertices,
                                   rtol=1e-5, atol=1e-8,
                                   err_msg="Vertices data mismatch after save/load cycle")
        np.testing.assert_array_equal(original_faces, loaded_faces,
                                      err_msg="Faces data mismatch after save/load cycle")

        print("[Test IO] Read/Write Meshes .obj files check PASSED.")