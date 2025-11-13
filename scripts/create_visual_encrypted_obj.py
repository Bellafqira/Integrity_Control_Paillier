import numpy as np
from phe import paillier
from src.integrity_ctrl.io import mesh_utils # Updated import
import time

# --- Configuration ---
KEY_SIZE = 128  # Paillier key size
QUANT_FACTOR = 10 ** 6  # Precision for floats (6 decimal places)
INPUT_MODEL = "data/meshes/casting.obj"
OUTPUT_MODEL = "outputs/models/watermarked_enc/encrypted_visual_casting.obj"

# --- 1. Initialization ---
print(f"Loading model: {INPUT_MODEL}")
model_data = mesh_utils.load_3d_model(INPUT_MODEL)
if not model_data:
    raise ValueError("Could not load the input model.")

original_vertices = model_data["vertices"]
original_faces = model_data["faces"]

print(f"Generating Paillier keys ({KEY_SIZE}-bit), this may take a moment...")
start_key = time.time()
public_key, private_key = paillier.generate_paillier_keypair(n_length=KEY_SIZE)
print(f"Keys generated in {time.time() - start_key:.2f}s")

# --- 2. Quantization and Encryption ---
print("Quantizing vertices...")
quantized_vertices = (original_vertices * QUANT_FACTOR).astype(np.int64)

print("Encrypting vertices (this can be long)...")
start_enc = time.time()
# Flatten for faster encryption
flat_data = quantized_vertices.flatten()
encrypted_flat_data = [public_key.encrypt(int(c)) for c in flat_data]
print(f"Encryption finished in {time.time() - start_enc:.2f}s")

# --- 3. Creation of Visual Vertices (Your method) ---
print("Creating visual representation (mapping % 256)...")
visual_vertices = np.zeros_like(original_vertices, dtype=float)

# We need the PaillierEncryptedNumber object to get the ciphertext
# (x, y, z are EncryptedNumber objects)
encrypted_vertices = np.array(encrypted_flat_data, dtype=object).reshape(original_vertices.shape)

for i in range(len(encrypted_vertices)):
    v_enc = encrypted_vertices[i]  # [Enc(x), Enc(y), Enc(z)]

    # 1. Get the large integer (ciphertext)
    c_x = v_enc[0].ciphertext(be_secure=False)
    c_y = v_enc[1].ciphertext(be_secure=False)
    c_z = v_enc[2].ciphertext(be_secure=False)

    # 2. Apply your mapping to get a coordinate in [0, 1]
    # (Using 255.0 for perfect normalization)
    vis_x = (c_x % 256) / 255.0
    vis_y = (c_y % 256) / 255.0
    vis_z = (c_z % 256) / 255.0

    visual_vertices[i] = [vis_x, vis_y, vis_z]

# --- 4. Saving the visual mesh ---
print(f"Saving visual mesh to: {OUTPUT_MODEL}")
mesh_utils.save_3d_model(
    visual_vertices,  # The new visual vertices ([0, 1])
    original_faces,  # The original structure (faces)
    OUTPUT_MODEL
)

print("Done.")
print(f"You can now open '{OUTPUT_MODEL}' in a 3D viewer.")
print(f"Reminder: This file CANNOT be decrypted.")