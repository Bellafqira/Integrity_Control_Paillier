import os
import glob
import numpy as np
import matplotlib.pyplot as plt

# Import your custom modules
from src.integrity_ctrl.io import mesh_utils
from src.integrity_ctrl.watermarking.qim import QIMClear

# --- Evaluation Parameters ---

# 1. The "Delta" (quantization step) we will test
# We will test a range of 'qim_step'
DELTAS_TO_TEST = [10, 20, 50, 100, 150, 200, 300, 500]

# 2. Attack Parameters
# For a robustness test, we must simulate an "attack".
# Gaussian noise is the most common.
# This is the standard deviation of the noise added to the *quantized data*.
NOISE_STRENGTH = 25.0

# 3. Watermarking Parameters
QUANT_FACTOR = 10 ** 6  # 6 decimal places of precision
WATERMARK_LENGTH = 1000  # Watermark length (must be < number of coordinates)

# 4. Files
DATASET_PATH = "data/*.obj"  # The glob to find all your models
RESULTS_DIR = "../results/"
PLOT_FILENAME = os.path.join(RESULTS_DIR, "robustness_qim_vs_delta.png")


# --- Functions ---

def calculate_ber(original_mark: list, extracted_mark: list) -> float:
    """Calculates the Bit Error Rate (BER) between two bit lists."""
    if len(original_mark) != len(extracted_mark):
        print("Error: Watermark lengths do not match.")
        # Handle the error, perhaps by truncating, but equality is expected
        min_len = min(len(original_mark), len(extracted_mark))
        original_mark = original_mark[:min_len]
        extracted_mark = extracted_mark[:min_len]

    # Convert to np.array for vectorized comparison
    original = np.array(original_mark)
    extracted = np.array(extracted_mark)

    # np.mean(original != extracted) calculates the percentage of different bits
    return np.mean(original != extracted)


def run_evaluation():
    """
    Runs the full robustness evaluation.
    """
    print("--- Starting QIM Robustness Evaluation ---")
    os.makedirs(RESULTS_DIR, exist_ok=True)

    model_files = glob.glob(DATASET_PATH)
    if not model_files:
        print(f"Error: No .obj models found in {DATASET_PATH}")
        return

    # Dictionary to store results: {model_name: [ber_list]}
    all_results = {}

    # Prepare the figure for Matplotlib
    plt.figure(figsize=(12, 8))

    # Loop 1: Iterate over each 3D model
    for model_file in model_files:
        model_name = os.path.basename(model_file)
        print(f"\nProcessing model: {model_name}")

        # 1. Load and quantize the model (once)
        model_data = mesh_utils.load_3d_model(model_file)
        if not model_data:
            print(f"  -> Load failed. Skipping model.")
            continue

        original_vertices = model_data["vertices"]

        # Check if the model is large enough
        if original_vertices.size < WATERMARK_LENGTH:
            print(f"  -> Model too small ({original_vertices.size} coords). Skipping.")
            continue

        quantized_vertices = (original_vertices * QUANT_FACTOR).astype(np.int64)

        # List to store BER scores for THIS model
        model_ber_scores = []

        # Loop 2: Iterate over each Delta (qim_step) value
        for delta in DELTAS_TO_TEST:
            print(f"  Testing with Delta (q_step) = {delta}")

            # a. Initialize QIM and generate watermark
            qim = QIMClear(qim_step=delta, watermark_length=WATERMARK_LENGTH)
            watermark = qim.generate_watermark()

            # b. Embed the watermark
            watermarked_data = qim.embed(quantized_vertices.copy(), watermark)

            # c. ATTACK THE MODEL
            # Create Gaussian noise with the same shape as the data
            noise = np.random.normal(
                0,  # Mean
                NOISE_STRENGTH,  # Standard deviation (strength)
                watermarked_data.shape
            ).astype(np.int64)

            attacked_data = watermarked_data + noise

            # d. Extract the watermark
            extracted_mark = qim.extract(attacked_data)

            # e. Calculate the BER
            ber = calculate_ber(watermark, extracted_mark)
            model_ber_scores.append(ber)
            print(f"    -> BER: {ber * 100:.2f}%")

        # End of Delta loop
        all_results[model_name] = model_ber_scores

        # Plot the curve for this model
        # Matplotlib will automatically choose a new color
        plt.plot(DELTAS_TO_TEST, model_ber_scores, marker='o', linestyle='-', label=model_name)

    # End of Model loop
    print("\n--- Evaluation Finished ---")

    # 3. Finalize and save the plot
    plt.xlabel("Delta (Quantization Step 'Delta')")
    plt.ylabel("Bit Error Rate (BER)")
    plt.title(f"QIM Robustness to Gaussian Noise (Strength={NOISE_STRENGTH})")
    plt.legend(loc="best")
    plt.grid(True)
    plt.xscale('log')  # Often useful to see the effect of 'q'
    plt.yscale('linear')

    plt.savefig(PLOT_FILENAME)
    print(f"Robustness graph saved to: {PLOT_FILENAME}")

    # Show the plot
    plt.show()


# --- Script entry point ---
if __name__ == "__main__":
    run_evaluation()