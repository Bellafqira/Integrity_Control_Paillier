import numpy as np

def tile_first_block(w, block_size=256):
    """Repeat the first `block_size` values to reach the length of `w`."""
    assert w.size >= block_size, "The vector must have at least `block_size` values."
    base = w[:block_size]
    reps = int(np.ceil(w.size / block_size))
    return np.tile(base, reps)[:w.size]

def majority_vote_block(w, block_size=256, codebook=(0, 1), threshold=None):
    """
    Perform majority voting per position modulo `block_size`.
    - codebook=(0,1): output bits {0,1}, threshold defaults to 0.5
    - codebook=(-1,1): output bits {-1,1}, threshold defaults to 0
    Returns an array of `block_size` bits.
    """
    if codebook == (0, 1):
        thr = 0.5 if threshold is None else threshold
        means = np.array([w[i::block_size].mean() for i in range(block_size)])
        voted = (means >= thr).astype(int)
    elif codebook == (-1, 1):
        thr = 0.0 if threshold is None else threshold
        means = np.array([w[i::block_size].mean() for i in range(block_size)])
        voted = np.where(means >= thr, 1, -1)
    else:
        raise ValueError("codebook must be (0,1) or (-1,1).")
    return voted

def binarize_first_block(w, block_size=256, codebook=(0,1), threshold=None):
    """
    Binarize the first `block_size` values to obtain the 'ground truth'
    bits using the same codebook/threshold as the majority vote.
    """
    first = w[:block_size]
    if codebook == (0, 1):
        thr = 0.5 if threshold is None else threshold
        return (first >= thr).astype(int)
    elif codebook == (-1, 1):
        thr = 0.0 if threshold is None else threshold
        return np.where(first >= thr, 1, -1)
    else:
        raise ValueError("codebook must be (0,1) or (-1,1).")

def compare_bits(bits_ref, bits_est):
    """Return Hamming distance and accuracy."""
    assert bits_ref.shape == bits_est.shape, "Vectors must have the same shape."
    hamming = np.sum(bits_ref != bits_est)
    acc = 1.0 - hamming / bits_ref.size
    return hamming, acc

def quantize_vertices(vertices: np.ndarray, quant_factor: int) -> np.ndarray:
    """
    Quantizes floating-point vertices to positive integers.

    This process scales the vertices and then shifts them by the
    quantization factor to ensure all values are positive.

    Formula: Q = int(V * F) + F

    Args:
        vertices (np.ndarray): The original (N, 3) array of float vertices.
        quant_factor (int): The quantization factor (e.g., 10**6).

    Returns:
        np.ndarray: The (N, 3) array of quantized int64 vertices.
    """
    print(f"Quantizing vertices with factor {quant_factor}...")
    # (vertices * quant_factor) -> scales floats
    # .astype(np.int64) -> truncates to integer
    # + quant_factor -> shifts all values to be positive
    quantized_data = (vertices * quant_factor).astype(np.int64)
    return quantized_data

def dequantize_vertices(quantized_vertices: np.ndarray, quant_factor: int) -> np.ndarray:
    """
    De-quantizes integer vertices back to their original floating-point representation.
    This is the exact inverse of the quantize_vertices function.

    Formula: V = (Q - F) / F

    Args:
        quantized_vertices (np.ndarray): The (N, 3) array of quantized int64 vertices.
        quant_factor (int): The same quantization factor used during quantization.

    Returns:
        np.ndarray: The (N, 3) array of de-quantized float vertices.
    """
    print(f"De-quantizing vertices with factor {quant_factor}...")
    # (quantized_vertices - quant_factor) -> shifts values back (can be negative)
    # .astype(float) -> ensures float division
    # / quant_factor -> scales values back to original range
    dequantized_data = quantized_vertices.astype(float) / quant_factor
    return dequantized_data