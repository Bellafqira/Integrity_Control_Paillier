import os
import glob
import numpy as np
import matplotlib.pyplot as plt
from networkx.algorithms.bipartite.basic import color

from integrity_ctrl.util.watermark_util import tile_first_block, majority_vote_block
# Import your custom modules
from src.integrity_ctrl.io import mesh_utils
from src.integrity_ctrl.watermarking.qim import QIMClear  # Plaintext QIM test

# --- Evaluation Parameters ---

# 1. The Delta (quantization step) is FIXED
FIXED_DELTA = 4

# 2. The Noise (strength) range we will test
# We will test from 0 (no noise) to 50
# (Std dev 50 is > half of FIXED_DELTA, so BER should be high)
NOISE_LEVELS_TO_TEST =  [0, 0.5, 1, 1.5, 2, 2.5, 3] #  np.arange(0, 51, 5)  # Tests 0, 5, 10, 15, ..., 50

# 3. Watermarking Parameters
QUANT_FACTOR = 10 ** 6  # 6 decimal places of precision

# 4. Files
DATASET_PATH = "data/meshes/*.obj"  # The glob to find all your models
RESULTS_DIR = "outputs/figures"
PLOT_FILENAME = os.path.join(RESULTS_DIR, "robustness_ber_vs_noise.pdf")


# --- Functions ---

def calculate_ber(original_mark: list, extracted_mark: list) -> float:
    """Calculates the Bit Error Rate (BER) between two bit lists."""
    if len(original_mark) != len(extracted_mark):
        print("Warning: Watermark lengths do not match. Truncating BER.")
        min_len = min(len(original_mark), len(extracted_mark))
        original_mark = original_mark[:min_len]
        extracted_mark = extracted_mark[:min_len]

    if len(original_mark) == 0:
        return 0.0  # Avoid division by zero if watermark is empty

    original = np.array(original_mark)
    extracted = np.array(extracted_mark)

    return np.mean(original != extracted)


def run_evaluation():
    """
    Runs the full robustness evaluation (BER vs Noise).
    """
    print(f"--- Starting QIM Evaluation (BER vs Noise) ---")
    print(f"--- Fixed Delta = {FIXED_DELTA} ---")
    os.makedirs(RESULTS_DIR, exist_ok=True)

    model_files = glob.glob(DATASET_PATH)
    if not model_files:
        print(f"Error: No .obj models found in {DATASET_PATH}")
        return

    all_results = {}
    plt.figure(figsize=(12, 8))
    colors = ['red', 'black', 'blue', 'green', 'purple', 'purple']
    # Loop 1: Iterate over each 3D model
    for idx, model_file in enumerate(model_files):
        model_name = os.path.basename(model_file)
        print(f"\nProcessing model: {model_name}")

        # 1. Load and quantize the model
        model_data = mesh_utils.load_3d_model(model_file)
        if not model_data:
            print(f"  -> Load failed. Skipping model.")
            continue

        original_vertices = model_data["vertices"]

        # 2. Calculate watermark size (as requested)
        # We use the maximum capacity: number of coordinates
        watermark_length = original_vertices.flatten().size
        print("hhhhhhhhhhhhhheeeeeeeeeeeeere", original_vertices.shape)
        if watermark_length == 0:
            print("  -> Model has no vertices. Skipping.")
            continue

        print(f"  Model size: {original_vertices.shape}")
        print(f"  Watermark size: {watermark_length} bits")

        quantized_vertices = (original_vertices * QUANT_FACTOR).astype(np.int64)

        # 3. Initialize QIM and embed the watermark (once)
        qim = QIMClear(qim_step=FIXED_DELTA, watermark_length=watermark_length)

        print("  Generating and embedding watermark...")
        watermark = qim.generate_watermark()
        # duplicate only the first 256 bits
        watermark = tile_first_block(np.array(watermark), 256)

        watermarked_data = qim.embed(quantized_vertices.copy(), watermark)

        model_ber_scores = []
        model_ber_scores_MV = []

        # Loop 2: Iterate over each Noise level
        for noise_strength in NOISE_LEVELS_TO_TEST:

            # a. Attack the model
            if noise_strength == 0: # Corrected from -1
                attacked_data = watermarked_data.copy()
            else:
                noise = np.random.normal(
                    0,  # Mean
                    noise_strength,  # Standard deviation (strength)
                    watermarked_data.shape
                ).astype(np.int64)

                attacked_data = watermarked_data + noise

            # b. Extract the watermark
            extracted_mark = qim.extract(attacked_data)
            extracted_mark_MV = majority_vote_block(np.array(extracted_mark), 256)
            # c. Calculate the BER
            ber = calculate_ber(watermark, extracted_mark)
            ber_MV = calculate_ber(watermark[:256], extracted_mark_MV)

            model_ber_scores.append(ber)
            model_ber_scores_MV.append(ber_MV)

            print(f"    -> Noise={noise_strength}, BER: {ber * 100:.2f}%")

        # End of Noise loop
        all_results[model_name] = model_ber_scores

        # Plot the curve for this model
        plt.plot(NOISE_LEVELS_TO_TEST, model_ber_scores, marker='o', linestyle='-', label=model_name.removesuffix(".obj"), color=colors[idx])
        # Plot the curve for this model
        plt.plot(NOISE_LEVELS_TO_TEST, model_ber_scores_MV, marker='x', linestyle='--', label=model_name.removesuffix(".obj") + ' majority vote', color=colors[idx])

    # End of Model loop
    print("\n--- Evaluation Finished ---")

    # 3. Finalize and save the plot
    plt.xlabel("Noise Strength (Gaussian Std Dev)")
    plt.ylabel("Bit Error Rate (BER)")
    plt.title(f"QIM Robustness (Fixed Delta = {FIXED_DELTA})")
    plt.legend(loc="best")  # Show legend with model names
    plt.grid(True)
    plt.ylim(0, 0.55)  # BER should not exceed 0.5 (random)

    plt.savefig(PLOT_FILENAME)
    print(f"Robustness graph saved to: {PLOT_FILENAME}")

    # Show the plot
    plt.show()


# --- Script entry point ---
if __name__ == "__main__":
    run_evaluation()