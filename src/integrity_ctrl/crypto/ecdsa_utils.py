import ecdsa  # Ensure ecdsa is installed

# --- Bit Conversion Functions ---

def bytes_to_bits(byte_data: bytes) -> list:
    """ Converts bytes into a list of bits (0s and 1s). """
    bits = []
    for byte in byte_data:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits


def bits_to_bytes(bit_list: list) -> bytes:
    """ Converts a list of bits into bytes. """
    byte_array = bytearray()
    for i in range(0, len(bit_list), 8):
        byte_chunk = bit_list[i:i + 8]
        # Ensure the chunk is complete (pad with 0s if needed)
        if len(byte_chunk) < 8:
            byte_chunk += [0] * (8 - len(byte_chunk))

        byte = 0
        for bit in byte_chunk:
            byte = (byte << 1) | bit
        byte_array.append(byte)
    return bytes(byte_array)


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
    return sk.sign_digest(data_hash)


def verify_signature(data_hash: bytes, signature_bytes: bytes, vk: ecdsa.VerifyingKey) -> bool:
    """ Verifies an ECDSA signature with the public key. """
    try:
        return vk.verify_digest(signature_bytes, data_hash)
    except ecdsa.BadSignatureError:
        return False