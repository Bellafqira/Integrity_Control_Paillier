import ecdsa  # Ensure ecdsa is installed
import numpy as np

# --- Bit Conversion Functions ---

def bytes_to_bits(byte_data: bytes) -> np.ndarray:
    """Ultra-rapide avec NumPy"""
    # Convertir bytes en array numpy
    byte_array = np.frombuffer(byte_data, dtype=np.uint8)
    # Unpacker les bits efficacement
    return np.unpackbits(byte_array)

def bits_to_bytes(bit_array: list[int]) -> bytes:
    """Ultra-rapide avec NumPy"""
    # Padding si nécessaire
    remainder = len(bit_array) % 8
    if remainder:
        bit_array = np.pad(bit_array, (0, 8 - remainder), constant_values=0)
    # Packer les bits
    return np.packbits(bit_array).tobytes()


# --- ECDSA Signature Functions ---

def generate_signing_keys() -> dict:
    """ Generates an ECDSA key pair (256-bit curve). """
    print("Generating ECDSA signing keys...")
    # SECP256k1 is the Bitcoin curve, 256 bits
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    return {"signing_key": sk, "verification_key": vk}


def generate_signature(data_hash: bytes, sk: ecdsa.SigningKey) -> bytes:
    """ Signs a hash with the ECDSA private key. """
    # Returns a 64-byte signature (R+S)
    return sk.sign(data_hash)


def verify_signature(data_hash: bytes, signature_bytes: bytes, vk: ecdsa.VerifyingKey) -> bool:
    """ Verifies an ECDSA signature with the public key. """
    try:
        return vk.verify(signature_bytes, data_hash)
    except ecdsa.BadSignatureError:
        return False