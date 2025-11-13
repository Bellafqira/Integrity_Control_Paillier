import os
import argparse
import pickle
import numpy as np
from phe import paillier
import time

# --- Update imports for the new structure ---
# (Assumes you have run `pip install -e .` in the root)
from src.integrity_ctrl.io import mesh_utils as mesh
from src.integrity_ctrl.crypto import ecdsa_utils
from src.integrity_ctrl.watermarking.qim import QIMClear
from src.integrity_ctrl.watermarking.sqim import SQIM
from src.integrity_ctrl.watermarking.dsb_signature import DSB_Signature
from src.integrity_ctrl.watermarking.psb_watermarking import PSB_Parity


# --- Key Management Functions ---

def save_keys(keys: dict, key_dir: str):
    """Saves keys to separate files using pickle."""
    os.makedirs(key_dir, exist_ok=True)

    with open(os.path.join(key_dir, "paillier.pub"), 'wb') as f:
        pickle.dump(keys['paillier_pub'], f)
    with open(os.path.join(key_dir, "paillier.priv"), 'wb') as f:
        pickle.dump(keys['paillier_priv'], f)
    with open(os.path.join(key_dir, "ecdsa.pub"), 'wb') as f:
        pickle.dump(keys['ecdsa_vk'], f)
    with open(os.path.join(key_dir, "ecdsa.priv"), 'wb') as f:
        pickle.dump(keys['ecdsa_sk'], f)
    print(f"Keys saved in directory: {key_dir}")


def load_keys(key_dir: str, load_private=True) -> dict:
    """Loads the necessary keys from files."""
    keys = {}
    print(f"Loading keys from {key_dir}...")
    with open(os.path.join(key_dir, "paillier.pub"), 'rb') as f:
        keys['paillier_pub'] = pickle.load(f)
    with open(os.path.join(key_dir, "ecdsa.pub"), 'rb') as f:
        keys['ecdsa_vk'] = pickle.load(f)

    if load_private:
        with open(os.path.join(key_dir, "paillier.priv"), 'rb') as f:
            keys['paillier_priv'] = pickle.load(f)
        with open(os.path.join(key_dir, "ecdsa.priv"), 'rb') as f:
            keys['ecdsa_sk'] = pickle.load(f)

    print("Keys loaded successfully.")
    return keys


# --- Command Handlers ---

def handle_generate_keys(args):
    """Generates and saves all keys."""
    print(f"Generating Paillier keys ({args.paillier_bits} bits)...")
    start = time.time()
    paillier_pub, paillier_priv = paillier.generate_paillier_keypair(n_length=args.paillier_bits)
    print(f"Paillier keys generated in {time.time() - start:.2f}s")

    start = time.time()
    ecdsa_keys = ecdsa_utils.generate_signing_keys()
    print(f"ECDSA keys generated in {time.time() - start:.2f}s")

    keys = {
        "paillier_pub": paillier_pub,
        "paillier_priv": paillier_priv,
        "ecdsa_vk": ecdsa_keys['verification_key'],
        "ecdsa_sk": ecdsa_keys['signing_key']
    }
    save_keys(keys, args.key_dir)


def handle_embed(args):
    """Executes the full embedding (watermarking) pipeline."""
    print(f"--- Starting embedding pipeline for {args.in_file} ---")

    # 1. Load keys
    # (We need public keys and the private signing key)
    keys = load_keys(args.key_dir, load_private=True)
    paillier_pub = keys['paillier_pub']
    ecdsa_sk = keys['ecdsa_sk']
    ecdsa_vk = keys['ecdsa_vk']  # Required for the DSB object

    # 2. Load 3D model
    print(f"Loading model: {args.in_file}")
    model = mesh.load_3d_model(args.in_file)
    if not model:
        print(f"Error: Could not load model {args.in_file}")
        return

    # 3. Quantize
    print(f"Quantizing with factor = {args.quant}")
    quantized_verts = (model['vertices'] * args.quant).astype(np.int64)
    wm_length = quantized_verts.size  # Watermark all coordinates

    # 4. Pre-watermark (QIM w=0 in plaintext)
    print(f"Pre-watermarking (QIM w=0, Delta={args.delta}) in plaintext...")
    qim_clear = QIMClear(args.delta, wm_length)
    pre_watermarked_data = qim_clear.embed(quantized_verts, [0] * wm_length)

    # 5. Encrypt
    print(f"Encrypting {wm_length} coordinates...")
    start_enc = time.time()
    flat_data = pre_watermarked_data.flatten()
    encrypted_data = np.array(
        [paillier_pub.encrypt(int(c)) for c in flat_data],
        dtype=object
    ).reshape(pre_watermarked_data.shape)
    print(f"Encryption finished in {time.time() - start_enc:.2f}s")

    # 6. Embed the 2nd watermark (SQIM)
    print("Generating and embedding SQIM watermark (encrypted)...")
    sqim = SQIM(paillier_pub, args.delta, wm_length)
    qim_watermark = sqim.generate_watermark()
    sqim_embedded_data = sqim.embed(encrypted_data, qim_watermark)

    # 7. Apply the integrity layer (DSB or PSB)
    print(f"Applying final integrity layer: {args.sig_type}")
    payload_to_save = {
        "model_data": None,
        "faces": model['faces'],
        "qim_watermark": qim_watermark,
        "sig_type": args.sig_type,
        "quant_factor": args.quant,
        "qim_step": args.delta,
        "psb_watermark": None,  # Initialized to None
        "signature_length": None  # Initialized to None
    }

    if args.sig_type == 'dsb':
        sig_len = 512  # 512 bits for ECDSA 256
        if wm_length < sig_len:
            raise ValueError("Model is too small for the 512-bit DSB signature.")

        dsb_keys = {"signing_key": ecdsa_sk, "verification_key": ecdsa_vk}
        sig_scheme = DSB_Signature(paillier_pub, dsb_keys, sig_len)

        prepared_data = sig_scheme._prepare_data_for_signing(sqim_embedded_data)
        signature_bits, _ = sig_scheme.generate_watermark(prepared_data)
        final_data = sig_scheme.embed(prepared_data, signature_bits)

        payload_to_save["model_data"] = final_data
        payload_to_save["signature_length"] = sig_len

    elif args.sig_type == 'psb':
        # Use PSB to watermark the *remaining* coordinates
        # (e.g., DSB uses 0-511, PSB uses 512-end)
        psb_wm_length = wm_length
        if psb_wm_length <= 0:
            raise ValueError("Model is too small to combine DSB and PSB.")

        psb_scheme = PSB_Parity(paillier_pub, psb_wm_length)
        psb_watermark = psb_scheme.generate_watermark()

        # Watermark on the already SQIM-encrypted data
        final_data = sqim_embedded_data.copy()
        # Flatten, take the end, watermark, reshape
        flat_final = final_data.flatten()
        watermarked_part = psb_scheme.embed(flat_final, psb_watermark)
        flat_final = watermarked_part
        final_data = flat_final.reshape(final_data.shape)

        payload_to_save["model_data"] = final_data
        payload_to_save["psb_watermark"] = psb_watermark
        payload_to_save["signature_length"] = psb_wm_length  # Length of the PSB watermark

    # 8. Save the result
    os.makedirs(os.path.dirname(args.out_file), exist_ok=True)
    with open(args.out_file, 'wb') as f:
        pickle.dump(payload_to_save, f)

    print(f"--- Embedding pipeline finished. ---")
    print(f"Final model (encrypted, watermarked, signed) saved to: {args.out_file}")


def handle_verify(args):
    """Executes the full verification pipeline."""
    print(f"--- Starting verification pipeline for {args.in_file} ---")

    # 1. Load keys
    # (We need private keys to decrypt, and public keys to verify)
    keys = load_keys(args.key_dir, load_private=True)
    paillier_pub = keys['paillier_pub']
    paillier_priv = keys['paillier_priv']
    ecdsa_vk = keys['ecdsa_vk']
    ecdsa_sk = keys['ecdsa_sk']  # Required by the DSB object, even for verification

    # 2. Load the data file
    print(f"Loading data file: {args.in_file}")
    with open(args.in_file, 'rb') as f:
        payload = pickle.load(f)

    model_data = payload['model_data']
    sig_type = payload['sig_type']
    wm_length = model_data.size

    # 3. Verify the integrity layer (DSB or PSB)
    print(f"Verifying integrity layer ({sig_type})...")
    integrity_valid = False

    if sig_type == 'dsb':
        sig_len = payload['signature_length']
        dsb_keys = {"signing_key": ecdsa_sk, "verification_key": ecdsa_vk}
        sig_scheme = DSB_Signature(paillier_pub, dsb_keys, sig_len)
        integrity_valid = sig_scheme.verify(model_data)

    elif sig_type == 'psb':
        psb_wm_length = payload['signature_length']
        psb_scheme = PSB_Parity(paillier_pub, psb_wm_length)

        # Extract the PSB watermark from the end of the data
        flat_data = model_data.flatten()
        extracted_psb = psb_scheme.extract(flat_data)

        integrity_valid = (extracted_psb == payload['psb_watermark'])

    if not integrity_valid:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("! ERROR: INTEGRITY CHECK FAILED !")
        print("! The model is corrupt or has been tampered with.")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        return  # Stop the process

    print("Integrity check PASSED. The model is authentic.")

    # 4. Decrypt
    print(f"Decrypting {wm_length} coordinates...")
    start_dec = time.time()
    flat_data = model_data.flatten()
    decrypted_data = np.array(
        [paillier_priv.decrypt(c) for c in flat_data],
        dtype=np.int64
    ).reshape(model_data.shape)
    print(f"Decryption finished in {time.time() - start_dec:.2f}s")

    # 5. Extract internal QIM watermark
    print("Extracting internal QIM watermark (plaintext)...")
    qim_clear = QIMClear(payload['qim_step'], wm_length)
    extracted_qim = qim_clear.extract(decrypted_data)

    if np.array_equal(extracted_qim, payload['qim_watermark']):
        print("Internal QIM watermark VERIFIED.")
    else:
        print("WARNING: Internal QIM watermark does not match!")

    # 6. Save the decrypted model
    print(f"De-quantizing and saving decrypted model to {args.out_model}")
    final_vertices = decrypted_data.astype(float) / payload['quant_factor']

    mesh.save_3d_model(
        final_vertices,
        payload['faces'],
        args.out_model
    )

    print("--- Verification pipeline finished. ---")


# --- Argument Parser Configuration (argparse) ---

def main():
    parser = argparse.ArgumentParser(
        description="CLI tool for watermarking and signing encrypted 3D models."
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # --- Command 1: generate-keys ---
    parser_gen = subparsers.add_parser(
        'generate-keys',
        help="Generate and save new Paillier and ECDSA keys."
    )
    parser_gen.add_argument(
        '--key-dir',
        type=str,
        default="keys",
        help="Output directory for keys. (Default: 'keys')"
    )
    parser_gen.add_argument(
        '--paillier-bits',
        type=int,
        default=1024,
        help="Bit size for the Paillier key. (Default: 1024)"
    )
    parser_gen.set_defaults(func=handle_generate_keys)

    # --- Command 2: embed ---
    parser_embed = subparsers.add_parser(
        'embed',
        help="Run the full watermarking embedding pipeline."
    )
    parser_embed.add_argument(
        '--in-file',
        type=str,
        required=True,
        help="Path to the original .obj model."
    )
    parser_embed.add_argument(
        '--out-file',
        type=str,
        required=True,
        help="Output file path (.pkl) for the encrypted data."
    )
    parser_embed.add_argument(
        '--key-dir',
        type=str,
        default="keys",
        help="Directory where keys are stored."
    )
    parser_embed.add_argument(
        '--delta',
        type=int,
        default=100,
        help="QIM quantization step (Delta). (Default: 100)"
    )
    parser_embed.add_argument(
        '--quant',
        type=int,
        default=1000000,
        help="Quantization factor (10^6). (Default: 1000000)"
    )
    parser_embed.add_argument(
        '--sig-type',
        type=str,
        choices=['dsb', 'psb'],
        default='dsb',
        help="Type of integrity layer to apply. (Default: dsb)"
    )
    parser_embed.set_defaults(func=handle_embed)

    # --- Command 3: verify ---
    parser_verify = subparsers.add_parser(
        'verify',
        help="Verify, decrypt, and extract watermark from a file."
    )
    parser_verify.add_argument(
        '--in-file',
        type=str,
        required=True,
        help="Path to the encrypted data file (.pkl)."
    )
    parser_verify.add_argument(
        '--out-model',
        type=str,
        required=True,
        help="Output path for the decrypted .obj model."
    )
    parser_verify.add_argument(
        '--key-dir',
        type=str,
        default="keys",
        help="Directory where keys are stored."
    )
    parser_verify.set_defaults(func=handle_verify)

    # --- Execution ---
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    # This block allows the script to be run directly
    # It adds the project root to the path to find the 'src' package
    # This is a fallback in case `pip install -e .` wasn't used.
    import sys
    import os

    # Add project root to path
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from src.integrity_ctrl.io import mesh_utils as mesh
    from src.integrity_ctrl.crypto import ecdsa_utils
    from src.integrity_ctrl.watermarking.qim import QIMClear
    from src.integrity_ctrl.watermarking.sqim import SQIM
    from src.integrity_ctrl.watermarking.dsb_signature import DSB_Signature
    from src.integrity_ctrl.watermarking.psb_watermarking import PSB_Parity

    main()