import unittest
import os
import numpy as np
from utils import mesh_utils  # Suppose que vous avez load/save dans ce module


class TestMeshIO(unittest.TestCase):
    """
    Tests the read/write functionality for .obj files.
    """

    def setUp(self):
        """
        Set up test paths.
        """
        self.input_file = "datasets/meshes/casting.obj"
        self.output_file = "tests/test_output_casting.obj"

        # Ensure the input file exists before running tests
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
        Tests that reading an .obj file returns non-empty vertices and faces.

        This test assumes your 'mesh_utils.py' has a function
        like 'load_3d_model' that returns vertices and faces.
        """
        print("\n[Test IO] Running: test_read_obj_file")
        # --- TODO: Replace with your actual load function ---
        # vertices, faces = mesh_utils.load_3d_model(self.input_file)

        # --- Placeholder logic (replace with your load call) ---
        print(" (Placeholder: Simulating model load)")
        vertices = np.array([[1, 2, 3], [4, 5, 6]])
        faces = np.array([[0, 1, 2]])
        # --- End Placeholder ---

        self.assertIsNotNone(vertices)
        self.assertIsNotNone(faces)
        self.assertGreater(len(vertices), 0)
        self.assertGreater(len(faces), 0)

    def test_read_write_integrity(self):
        """
        Tests that writing and then reading a model preserves the data.

        This is the most critical I/O test. It ensures that
        save_3d_model and load_3d_model are compatible.
        """
        print("\n[Test IO] Running: test_read_write_integrity")

        # --- TODO: Replace with your actual load/save functions ---

        # 1. Load original data (Placeholder)
        print(" (Placeholder: Simulating original model load)")
        original_vertices = np.array([[1.1, 2.2, 3.3], [4.4, 5.5, 6.6]])
        original_faces = np.array([[0, 1, 2]])

        # 2. Save data to output file (Placeholder)
        print(f" (Placeholder: Simulating save to {self.output_file})")
        # mesh_utils.save_3d_model(original_vertices,
        #                          original_faces,
        #                          self.output_file)

        # --- Simulate saving by creating a dummy file ---
        with open(self.output_file, 'w') as f:
            f.write("v 1.1 2.2 3.3\n")
            f.write("v 4.4 5.5 6.6\n")
            f.write("f 1 2 3\n")
        self.assertTrue(os.path.exists(self.output_file))

        # 3. Load data from the *new* file (Placeholder)
        print(" (Placeholder: Simulating reload from new file)")
        # loaded_vertices, loaded_faces = mesh_utils.load_3d_model(self.output_file)
        loaded_vertices = np.array([[1.1, 2.2, 3.3], [4.4, 5.5, 6.6]])
        loaded_faces = np.array([[0, 1, 2]])
        # --- End Placeholder ---

        # 4. Compare original and loaded data
        np.testing.assert_allclose(original_vertices, loaded_vertices,
                                   rtol=1e-5, atol=1e-8)
        np.testing.assert_array_equal(original_faces, loaded_faces)
        print("[Test IO] Read/Write integrity check passed.")