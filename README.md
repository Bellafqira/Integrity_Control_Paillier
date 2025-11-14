# Integrity Control and Traceability for Paillier-Encrypted Data

This project provides a complete, and first solution for guaranteeing the integrity and authenticity of Paillier-encrypted data, without the need of metadata or impacting the plaintext data.
with a specific focus on 3D models.
## About The Project

Ensuring the integrity and authenticity of sensitive data (such as medical or industrial models) after encryption is a major challenge.  
This project implements a novel solution to solve this problem.

It is one of the first solutions to ensure the integrity of Paillier-encrypted data **without external metadata**, based on a new mechanism we have developed: **Deterministic Self-Blinding (DSB)**.

In addition to integrity (protection against tampering), we also ensure **traceability**:

- **QIM (Quantization Index Modulation)**: A watermark is first embedded into the plaintext 3D model.  
- **SQIM (Secured QIM)**: A second watermark is embedded securely in the encrypted domain using Paillier’s homomorphic properties.

This allows guaranteeing:
- authenticity **before decryption** (via DSB),  
- traceability **after decryption** (via QIM/SQIM).

## Features

- **Integrity Control (DSB)**: Signs and verifies an entire model in the encrypted domain using ECDSA + Deterministic Self-Blinding.
- **Traceability Watermarking (QIM/SQIM)**: Composite watermarking pipeline surviving encryption & decryption.
- **Probabilistic Watermarking (PSB)**: Includes a PSB-Parity embedding alternative.
- **CLI Interface**: A single entry point (`scripts/cli.py`) for all operations (key generation, encryption, signing, verifying).
- **Evaluation Tools**: Scripts (`scripts/eval_...`) to generate robustness (BER vs. Noise) and distortion (Hausdorff vs. Delta) graphs.

---

## Installation

This project uses **pip** and **venv** for dependency management.

### 1.  Clone the repository

```bash
git clone git@github.com:Bellafqira/Integrity_Control_Paillier.git
cd Integrity_Control_Paillier
```
### 2. Create a virtual environment
```bash
python -m venv venv
```
### 3. Activate the environment
```bash
source venv/bin/activate
```
### 4. Install the project in editable mode
```bash
pip install -e .
```
(💡 Don't forget the final dot . !)

This installs all dependencies (from pyproject.toml) and makes the src/integrity_ctrl package available globally.

## Quick Start

### 1.  Run Unit Tests
Before starting, you can verify that all cryptographic components and watermarking modules are working correctly on your machine.

**Command:**
```bash
python -m unittest discover -v tests
```
Description:
This command will automatically discover all test_*.py files in your tests/ directory. It will run each test function (like test_full_qim_cycle, test_dsb_signature_pipeline, etc.) and confirm that everything is working as expected.

### 2.  Using the CLI (cli.py)
The scripts/cli.py script is the main entry point for using the application.

Here is a complete workflow:

**Step 1: Generate Keys**

First, generate your Paillier (for encryption) and ECDSA (for signature) keys.
```bash
# Creates a 'my_keys' folder and saves the 4 key files inside it
 export PYTHONPATH="$PYTHONPATH:."; python scripts/cli.py generate-keys --key-dir "my_keys" --paillier-bits 2048
```
* `--key-dir "my_keys"`: (Optional) Specifies the folder to save the keys.
* `--paillier-bits 2048`: (Optional) Defines the Paillier key size (the larger, the more secure).

**Step 2: Watermark and Sign a Model (Embed)**
Next, take an `.obj` model, apply the full watermarking pipeline, and save the encrypted result.

`embed` **pipeline logic:**

1. Loads the `.obj` model.
2. Quantizes the vertices.
3. Applies a plaintext QIM pre-watermark (w=0).
4. Encrypts the model with the Paillier key.
5. Applies the SQIM watermark (w=mark) in the encrypted domain.
6. Applies the DSB integrity signature.

**Command:**
```bash
python scripts/cli.py embed --in-file "data/meshes/casting.obj" --out-file "outputs/models/casting_signed.pkl" --key-dir "my_keys" --delta 100 --quant 1000000 --sig-type dsb
```

* `--in-file`: The original `.obj` model to protect.
* `--out-file`: The output `.pkl` file that will contain the encrypted data.
* `--key-dir`: The folder containing your keys (from Step 1).
* `--delta`: The QIM quantization step.
* `--quant`: The quantization factor for floats.
* `--sig-type`: `dsb` (recommended) or `psb`.

**Step 3: Verify and Decrypt (Verify)**
Finally, take a protected `.pkl` file, check its integrity, and if it is authentic, decrypt it and extract the watermark.

`verify` **pipeline logic**:
1. Loads the `.pkl` file and keys.
2. Verifies the DSB signature.
3. **If the signature is invalid, the script stops.**
4. If the signature is valid, it decrypts the model with the Paillier private key.
5. It extracts the internal QIM watermark (for traceability).
6. It saves the final decrypted and watermarked `.obj` model.

**Command :**
```bash
python scripts/cli.py verify --in-file "outputs/models/casting_signed.pkl" --out-model "outputs/models/bunny_decrypted_verified.obj" --key-dir "my_keys"
```
* `--in-file`: The `.pkl` file you want to verify.
* `--out-model`: The output path for the decrypted `.obj` model if verification succeeds.
* `--key-dir`: The key directory (must contain the private key for decryption).

### 2.   Using the CLI (cli.py)
The `scripts/cli.py` script is the main entry point for using the application.

Here is a complete workflow:

**Step 1: Generate Keys**

First, generate your Paillier (for encryption) and ECDSA (for signature) keys.
```bash
# Creates a 'my_keys' folder and saves the 4 key files inside it
python scripts/cli.py generate-keys --key-dir "my_keys" --paillier-bits 2048
```
* `--key-dir "my_keys"`: (Optional) Specifies the folder to save the keys.
* `--paillier-bits 2048`: (Optional) Defines the Paillier key size (the larger, the more secure).

**Step 2: Watermark and Sign a Model (Embed)**

Next, take an `.obj` model, apply the full watermarking pipeline, and save the encrypted result.

`embed` **pipeline logic:**

1. Loads the `.obj` model.
2. Quantizes the vertices.
3. Applies a plaintext QIM pre-watermark (w=0).
4. Encrypts the model with the Paillier key.
5. Applies the SQIM watermark (w=mark) in the encrypted domain.
6. Applies the DSB integrity signature.
7. Saves everything into a secure `.pkl` file.
**Command:**
```bash
python scripts/cli.py embed --in-file "data/meshes/bunny.obj" --out-file "outputs/models/bunny_signed.pkl" --key-dir "my_keys" --delta 100 --quant 1000000 --sig-type dsb
```
* `--in-file`: The original `.obj` model to protect.
* `--out-file`: The output `.pkl` file that will contain the encrypted data.
* `--key-dir`: The folder containing your keys (from Step 1).
* `--delta`: The QIM quantization step.
* `--quant`: The quantization factor for floats.
* `--sig-type`: `dsb` (recommended) or `psb`.

**Step 3: Verify and Decrypt (Verify)**

Finally, take a protected `.pkl` file, check its integrity, and if it is authentic, decrypt it and extract the watermark.

`verify` **pipeline logic:**

1. Loads the `.pkl` file and keys.
2. Verifies the DSB signature.
3. If the signature is invalid, the script stops.
4. If the signature is valid, it decrypts the model with the Paillier private key.
5. It extracts the internal QIM watermark (for traceability).
6. It saves the final decrypted and watermarked `.obj` model.

**Command:**
```bash
python scripts/cli.py verify --in-file "outputs/models/bunny_signed.pkl" --out-model "outputs/models/bunny_decrypted_verified.obj" --key-dir "my_keys"
```
* `--in-file`: The `.pkl` file you want to verify.
* `--out-model`: The output path for the decrypted `.obj` model if verification succeeds.
* `--key-dir`: The key directory (must contain the private key for decryption).

### 3.   Run Evaluations
To reproduce the robustness and distortion analysis graphs:
```bash
# Generates the BER vs. Noise graph (robustness)
python scripts/eval_robustness_noise.py

# Generates the Distortion vs. Delta graph
python scripts/eval_distortion.py
```
The graphs will be saved in `outputs/figures/`.