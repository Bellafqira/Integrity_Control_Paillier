import os
import pymeshlab
import time


def load_3d_model(filename=None):
    """
    Loads a 3D model from an .obj file using PyMeshLab.
    """
    if not os.path.exists(filename):
        print(f"Error: File {filename} does not exist.")
        return None

    ms = pymeshlab.MeshSet()

    try:
        ms.load_new_mesh(filename)
        m = ms.current_mesh()
        vertices = m.vertex_matrix()
        faces = m.face_matrix()

        print(f"File {os.path.basename(filename)} loaded successfully (via PyMeshLab)")
        print(f"  Number of vertices: {len(vertices)}")
        print(f"  Number of faces: {len(faces)}")

        return {"vertices": vertices, "faces": faces}

    except Exception as e:
        print(f"PyMeshLab error while loading {filename}: {e}")
        return None


def save_3d_model(vertices, faces, filename):
    """
    Saves a 3D model to an .obj file using PyMeshLab.
    (Corrected version with proper save flags)
    """
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        ms = pymeshlab.MeshSet()

        m = pymeshlab.Mesh(vertices, faces if faces is not None and faces.size > 0 else None)

        ms.add_mesh(m, "new_model")

        # --- MODIFICATION HERE ---
        # We only use flags for color and normals,
        # which were the source of the display issue.
        ms.save_current_mesh(
            filename,
            save_vertex_color=False,  # Do not save colors (r g b)
            save_vertex_normal=False  # Do not save normals (vn)
        )
        # --- END OF MODIFICATION ---

        print(f"Model saved (minimal) to {filename} (via PyMeshLab)")

    except Exception as e:
        print(f"PyMeshLab error while saving: {e}")


def compute_hausdorff(file1, file2):
    """
    Compares two .obj files and calculates the Hausdorff distance.
    """

    ms = pymeshlab.MeshSet()

    try:
        ms.load_new_mesh(file1)  # Index 0
        ms.load_new_mesh(file2)  # Index 1

        start_time = time.time()
        print("Computing Hausdorff distance (PyMeshLab)...")

        # --- FIX APPLIED ---
        # Using the direct method found via introspection
        # (replaces the problematic apply_filter call)
        hausdorff_dict = ms.get_hausdorff_distance(
            sampledmesh=0,
            targetmesh=1
        )

        max_dist = hausdorff_dict['max']
        mean_dist = hausdorff_dict['mean']
        # --- END OF FIX ---

        print(f"Calculation finished in {time.time() - start_time:.2f}s")
        print(f"  Hausdorff Distance (Max): {max_dist}")
        print(f"  Hausdorff Distance (Mean): {mean_dist}")

        return max_dist, mean_dist

    except Exception as e:
        print(f"PyMeshLab error during Hausdorff calculation: {e}")
        return None, None