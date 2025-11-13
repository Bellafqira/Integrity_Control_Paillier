import trimesh
import sys
# Import from your project package (assumes `pip install -e .`)
from src.integrity_ctrl.io import mesh_utils

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/visualize_mesh.py <path_to_file.obj>")
        sys.exit(1)

    filepath = sys.argv[1]

    print(f"Loading model: {filepath}")
    model = mesh_utils.load_3d_model(filepath)

    if model:
        # 1. Create a Trimesh object from your vertices and faces
        mesh = trimesh.Trimesh(vertices=model["vertices"],
                               faces=model["faces"])

        # 2. Show it!
        print("Displaying model... (Close the window to continue)")
        mesh.show()
    else:
        print(f"Failed to load model from {filepath}")