# Integrity Control and Traceability for Paillier-Encrypted Data

This project provides a complete solution for guaranteeing the **integrity**, **authenticity**, and **traceability** of Paillier-encrypted data, with a particular focus on 3D models.

It introduces one of the first practical mechanisms for integrity verification **inside the encrypted domain**, without external metadata and without modifying the underlying plaintext.  
This is achieved through a new method we developed: **Deterministic Self-Blinding (DSB)**.

In addition to encrypted-domain integrity, the system offers **two-layer traceability**:

1. **Plaintext QIM (Quantization Index Modulation):**  
   A deterministic "pre-watermark" (e.g., all zeros) is embedded directly into the plaintext vertices.

2. **Encrypted-Domain SQIM (Secured QIM):**  
   A second, secret watermark is embedded using Paillier’s additively homomorphic properties.

Together, these techniques allow:

- **Authenticity before decryption** (via DSB integrity verification),  
- **Traceability after decryption** (via QIM/SQIM watermarking).

___
## Features

- **Encrypted-Domain Integrity (DSB)**  
  A novel technique enabling signature and verification entirely on encrypted data using Paillier + ECDSA.

- **Encrypted-Domain Traceability (SQIM)**  
  A watermarking scheme that remains detectable after encryption and decryption.

- **Probabilistic Self-Blinding (PSB)**  
  An LSB-parity watermarking method included for comparison.

- **Unified Command-Line Interface**  
  `scripts/cli.py` exposes key generation, encryption, watermarking, signing, verification.

- **Evaluation Suite**  
  Scripts for robustness (BER) and distortion (hausdorff) experiments.
---
## Project Structure
```rust
Integrity_Control_Paillier/
├── data/
│   └── meshes/             # .obj models
├── outputs/
│   ├── figures/            # Generated plots
│   └── models/             # Generated .obj and .pkl files
├── scripts/
│   ├── cli.py              # <--- MAIN USER INTERFACE
│   ├── eval_distortion.py
│   ├── eval_robustness_noise.py
│   ├── eval_robustness_qim_delta.py
│   └── visualize_mesh.py
├── src/
│   └── integrity_ctrl/     # The main Python package
│       ├── crypto/         # Paillier (PHE) helpers, ECDSA
│       ├── io/             # Mesh loading/saving (PyMeshLab)
│       └── watermarking/   # QIM, SQIM, DSB, PSB modules
├── tests/
│   ├── test_01_mesh_io.py
│   └── ...                 # Unit tests
├── .gitignore
├── pyproject.toml          # Project configuration
├── requirements.txt
└── run_all.sh

```
## Installation & Setup

This project uses **pip** and **venv** for dependency management.

### 1.  Clone the repository

```bash
git clone git@github.com:Bellafqira/Integrity_Control_Paillier.git
cd Integrity_Control_Paillier
```
### 2. Create a virtual environment
It is highly recommended to use a virtual environment (venv).
```bash
python -m venv venv
```

### 3. Activate the environment
- **Windows (PowerShell/CMD):**
```bash
.\venv\Scripts\activate
```
- **macOS / Linux::**
```bash
source venv/bin/activate
```
### 4. Install the project in editable mode
This project is set up as a Python package. This command installs all dependencies AND makes your `src/integrity_ctrl` package findable by all your scripts.

From the project root, run:
```bash
pip install -e .
```
_(Don't forget the . at the end! This means "install the project in the current directory in editable mode.")
This installs all dependencies (from pyproject.toml) and makes the src/integrity_ctrl package available globally._

## Usage
There are two ways to interact with the system:

* running the CLI (main functionality)
* running the unit tests (development)

### 1.  Run Unit Tests
Before starting, you can verify that all cryptographic components and watermarking modules are working correctly on your machine.

**Command:**
```bash
python -m unittest discover -v tests
```
This command will automatically discover all `test_*.py` files in your `tests/` directory. It will run each test function (like `test_full_qim_cycle`, `test_dsb_signature_pipeline`, etc.) and confirm that everything is working as expected.

### 2.  Using the Command-Line Interface (cli.py)
The `scripts/cli.py` script is the main entry point for using the application.

Here is a complete workflow:

**Step 1: Generate Keys**

First, generate your Paillier (for encryption) and ECDSA (for signature) keys.
```bash
# This will create a 'my_keys' folder and save 4 key files inside it
 # $env:PYTHONPATH = "."; for CMD or Windows shell
 export PYTHONPATH="$PYTHONPATH:."; # Linux
 python scripts/cli.py generate-keys --key-dir "my_keys_2048" --paillier-bits 2048
```

* `--key-dir "my_keys"`: (Optional) Specifies the folder to save the keys. Default is `keys`.
* `--paillier-bits 2048`: (Optional) Defines the Paillier key size (the larger, the more secure). Default is `1024`.

**Step 2: Watermark and Sign a Model (Embed)**

Next, take an `.obj` model, apply the full watermarking  and integrity pipeline, and save the encrypted result.

**The `embed` pipeline performs this full process:**

1. Loads the `.obj` model.
2. Quantizes the vertices.
3. Applies a plaintext QIM pre-watermark (`w=0`).
4. Encrypts the pre-watermarked model with the Paillier public key.
5. Applies the second (traceability) SQIM watermark in the encrypted domain.
6. Applies the final DSB integrity signature over the entire encrypted model.
7. Saves the final object (encrypted data, faces, metadata) into a secure `.pkl` file.

**Command:**
```bash
python scripts/cli.py embed --in-file "data/meshes/casting.obj" --out-file "outputs/models/casting_signed_2048_dsb.pkl" --key-dir "my_keys_2048" --delta 100 --quant 6 --sig-type dsb
```

* `--in-file`: (Required) The original `.obj` model to protect.
* `--out-file`:  (Required) The output `.pkl` file that will contain the encrypted data.
* `--key-dir`: The folder containing your keys (from Step 1).
* `--delta`: The QIM quantization step.
* `--quant`: The quantization factor for floats (e.g., `6` for 6 decimal places).
* `--sig-type`: `dsb` (recommended) or `psb`.

Example (PSB integrity):
```bash
python scripts/cli.py embed --in-file "data/meshes/casting.obj" --out-file "outputs/models/casting_signed_2048_psb.pkl" --key-dir "my_keys_2048" --delta 100 --quant 6 --sig-type psb
```


**Step 3: Verify and Decrypt (Verify)**
Finally, take a protected `.pkl` file, check its integrity, and if it is authentic, decrypt it and extract the watermark.

**The `verify` pipeline performs this full process:**

1. Loads the `.pkl` file and all necessary keys.
2. Verifies the DSB integrity signature (in the encrypted domain).
3. **If the signature is invalid, the script stops.**
4. If the signature is valid, it decrypts the model with the Paillier private key.
5. It extracts the internal QIM watermark (for traceability).
6. It saves the final decrypted and watermarked `.obj` model.

**Command :**
```bash
python scripts/cli.py verify --in-file "outputs/models/casting_signed_2048_dsb.pkl" --out-model "outputs/models/casting_verified_dsb.obj" --key-dir "my_keys_2048"
```
* `--in-file`: (Required) The `.pkl` file you want to verify (from Step 2).
* `--out-model`: (Required) The output path for the final decrypted `.obj` model.
* `--key-dir`: The key directory (must contain your private keys for decryption).

Verify PSB-protected model:
```bash
python scripts/cli.py verify --in-file "outputs/models/casting_signed_2048_psb.pkl" --out-model "outputs/models/casting_verified_psb.obj" --key-dir "my_keys_2048"
```
### 3.   Run Evaluations
To reproduce the analysis graphs for distortion and robustness, you can use the evaluation scripts:

```bash
# Generates the BER vs. Noise graph (robustness)
python scripts/eval_robustness_noise_majority_vote.py

# Generates the Distortion vs. Delta graph
python scripts/eval_distortion.py
```
The graphs will be saved in `outputs/figures/`.

 ## Automated Batch Pipeline (Optional)
You can automate the full workflow using the following script:

`run_all.sh` (Linux/macOS)
```bash
#!/bin/bash

LOGFILE="run_pipeline_output.log"
echo "=== Pipeline started at $(date) ===" | tee -a "$LOGFILE"

run() {
    echo "" | tee -a "$LOGFILE"
    echo "=== Running: $1 ===" | tee -a "$LOGFILE"
    bash -c "$1" 2>&1 | tee -a "$LOGFILE"
}

run "python scripts/cli.py generate-keys --key-dir 'my_keys_2048' --paillier-bits 2048"

run "python scripts/cli.py embed --in-file 'data/meshes/casting.obj' --out-file 'outputs/models/casting_signed_2048_dsb.pkl' --key-dir 'my_keys_2048' --delta 4 --quant 1000000 --sig-type dsb"

run 'python scripts/cli.py embed --in-file "data/meshes/casting.obj" --out-file "outputs/models/casting_signed_2048_psb.pkl" --key-dir "my_keys_2048" --delta 4 --quant 1000000 --sig-type psb'

run "python scripts/cli.py verify --in-file 'outputs/models/casting_signed_2048_psb.pkl' --out-model 'outputs/models/casting_verified_psb.obj' --key-dir 'my_keys_2048'"

run "python scripts/cli.py verify --in-file 'outputs/models/casting_signed_2048_dsb.pkl' --out-model 'outputs/models/casting_verified_dsb.obj' --key-dir 'my_keys_2048'"

echo "=== Pipeline finished at $(date) ===" | tee -a "$LOGFILE"

```
Make it executable:
```bash
chmod +x run_all.sh
./run_all.sh
```
The full log is saved to:
```lu
run_pipeline_output.log
```