import os
import glob
import numpy as np
import matplotlib.pyplot as plt
import pymeshlab

# Import your custom modules
# This import path assumes you are running from the project root directory
from src.integrity_ctrl.io import mesh_utils
from src.integrity_ctrl.watermarking.qim import QIMClear
from src.integrity_ctrl.util.watermark_util import quantize_vertices, dequantize_vertices

# --- Evaluation Parameters ---
DELTAS_TO_TEST = [2, 4, 6, 8, 10, 20, 30]
QUANT_FACTOR = 10 ** 6
DATASET_PATH = "data/meshes/*.obj"
RESULTS_DIR = "outputs/figures"
PLOT_FILENAME = os.path.join(RESULTS_DIR, "distortion_hausdorff_vs_delta.png")


# --- Functions ---

def calculate_hausdorff_on_arrays(vertices1: np.ndarray,
                                  vertices2: np.ndarray,
                                  faces: np.ndarray,
                                  ms: pymeshlab.MeshSet) -> float:
    """
    Calculates the max Hausdorff distance between two in-memory meshes.
    Uses the direct .get_hausdorff_distance() method.
    """
    ms.clear()

    # PyMeshLab expects floats for coordinates
    v1_float = vertices1.astype(np.float64)
    v2_float = vertices2.astype(np.float64)

    mesh1 = pymeshlab.Mesh(v1_float, faces)
    mesh2 = pymeshlab.Mesh(v2_float, faces)

    ms.add_mesh(mesh1, "mesh1_compared")  # Index 0
    ms.add_mesh(mesh2, "mesh2_reference")  # Index 1

    try:
        # --- FIX HERE ---
        # Use the direct method found in your list
        hausdorff_dict = ms.get_hausdorff_distance(
            sampledmesh=0,
            targetmesh=1
        )
        # --- END OF FIX ---

        # The returned dictionary contains 'max', 'mean', 'rms'
        hd_max = hausdorff_dict['max']
        return hd_max

    except Exception as e:
        print(f"  PyMeshLab Hausdorff Error: {e}")
        return 0.0


def run_evaluation():
    """
    Runs the full distortion evaluation.
    """
    print(f"--- Starting QIM Distortion Evaluation (Hausdorff vs Delta) ---")
    os.makedirs(RESULTS_DIR, exist_ok=True)

    model_files = glob.glob(DATASET_PATH)
    if not model_files:
        print(f"Error: No .obj models found in {DATASET_PATH}")
        return

    ms = pymeshlab.MeshSet()
    all_results = {}
    plt.figure(figsize=(12, 8))

    # Loop 1: Iterate over each 3D model
    for model_file in model_files:
        model_name = os.path.basename(model_file)
        print(f"\nProcessing model: {model_name}")

        model_data = mesh_utils.load_3d_model(model_file)
        if not model_data:
            print(f"  -> Load failed. Skipping model.")
            continue

        original_vertices = model_data["vertices"]
        original_faces = model_data["faces"]
        quantized_vertices = quantize_vertices(original_vertices, QUANT_FACTOR)

        watermark_length = original_vertices.size

        if watermark_length == 0:
            print("  -> Model has no vertices. Skipping model.")
            continue

        model_hausdorff_scores = []

        # Loop 2: Iterate over each Delta (qim_step) value
        for delta in DELTAS_TO_TEST:
            qim = QIMClear(qim_step=delta)
            watermark = qim.generate_watermark(watermark_length)
            watermarked_q_vertices = qim.embed(quantized_vertices.copy(), watermark)

            hd_max = calculate_hausdorff_on_arrays(
                dequantize_vertices(watermarked_q_vertices, QUANT_FACTOR),  # Index 0 (sampledmesh) - De-quantized
                dequantize_vertices(quantized_vertices, QUANT_FACTOR),    # Index 1 (targetmesh) - De-quantized
                original_faces,
                ms
            )
            model_hausdorff_scores.append(hd_max)
            print(f"  -> Delta={delta}, Max Hausdorff Dist: {hd_max:.6f}") # Increased precision

        all_results[model_name] = model_hausdorff_scores
        plt.plot(DELTAS_TO_TEST, model_hausdorff_scores, marker='o', linestyle='-', label=model_name)

    print("\n--- Evaluation Finished ---")

    plt.xlabel("Delta (Quantization Step 'Delta')")
    plt.ylabel("Distortion (Max Hausdorff Distance)")
    plt.title("QIM Distortion vs. Quantization Step (Delta)")
    plt.legend(loc="best")
    plt.grid(True)

    plt.savefig(PLOT_FILENAME)
    print(f"Distortion graph saved to: {PLOT_FILENAME}")

    plt.show()


if __name__ == "__main__":
    run_evaluation()