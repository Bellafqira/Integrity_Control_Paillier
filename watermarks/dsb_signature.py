import numpy as np
import hashlib
from src.watermarking.abstract_scheme import AbstractWatermarkingScheme
from src.utils.paillier_context import PaillierContext
from src.utils import util  # Assuming 'util' has signature and bit conversion functions


class DSBSignature(AbstractWatermarkingScheme):
    """
    Implements the Deterministic Self-Blinding (DSB) Signature scheme.

    This corresponds to the user's 'PSB' (Probabilistic Self-Blinding)
    and 'DSB' (Deterministic Self-Blinding) classes.

    - All operations (embed, extract, verify) are done in the
      ENCRYPTED domain.
    """

    def __init__(self, paillier_context: PaillierContext, signing_keys: dict, signature_length: int):
        """
        Initializes the DSB scheme.

        Args:
            paillier_context (PaillierContext): The crypto engine.
            signing_keys (dict): Dict containing 'signing' (private)
                                 and 'verification' (public) keys.
            signature_length (int): The bit length of the signature.
        """
        super().__init__(paillier_context)
        self.secret_key = signing_keys  # Store both signing and verification keys
        self.signature_length = signature_length

    def _prepare_data_for_signing(self, host_data: np.array) -> np.array:
        """
        Prepares the data by 'zeroing' the signature space.
        This corresponds to '_embed_0_in_first_vertices'.

        It iterates over the first 'signature_length' coefficients and
        ensures they all represent a '0' bit (i.e., they are 'positive'
        ciphertexts) by flipping any 'negative' ones.

        Args:
            host_data (np.array): The encrypted data.

        Returns:
            np.array: The "cleaned" encrypted data, ready for signing.
        """
        print("DSB: Preparing data for signing (zeroing signature space)...")
        prepared_data = host_data.copy()
        N2 = self.paillier.N2
        # Threshold for 'negative' numbers in mod N^2
        threshold = (N2 + 1) // 2

        for j in range(0, self.signature_length):
            idx_v = j // 3
            idx_c = j % 3
            val = prepared_data[idx_v][idx_c]

            # If val is "negative" (represents a '1' bit)
            if threshold <= val <= N2 - 1:
                # Flip it back to "positive" (a '0' bit)
                prepared_data[idx_v][idx_c] = self.paillier.deterministic_self_blind(val)

        return prepared_data

    def generate_watermark(self, data_to_sign: np.array) -> list:
        """
        Generates the signature, which serves as the watermark.
        (User's 'calcule de la signature').

        Args:
            data_to_sign (np.array): The data to be signed (must be
                                     the "prepared" data).

        Returns:
            list: The signature as a list of bits.
        """
        print("DSB: Generating signature (hash + sign)...")

        # 1. Hash the prepared data
        # Note: np.array2string might be slow. Consider a more robust hash.
        mesh_hash = hashlib.sha256(np.array2string(data_to_sign).encode('utf-8')).digest()

        # 2. Sign the hash
        signing_key_private = self.secret_key["signing"]
        mesh_signature_bytes = util.generate_signature(mesh_hash, signing_key_private)

        # 3. Convert to bits
        signature_bits = util.bytes_to_bits(mesh_signature_bytes)

        # Ensure consistent length
        return signature_bits[:self.signature_length]

    def embed(self, host_data: np.array, signature_bits: list) -> np.array:
        """
        Embeds the signature in the ENCRYPTED domain using self-blinding.
        (User's 'insertion dans le chiffré').

        Logic: If signature_bit[i] is 1, apply self-blinding (negation)
               to the corresponding ciphertext.
               E(m) -> -E(m) % N^2  <==> E(-m)

        Args:
            host_data (np.array): The *prepared* (zeroed) encrypted data.
            signature_bits (list): The signature bit list to embed.

        Returns:
            np.array: The signed encrypted data.
        """
        print("DSB: Embedding signature via self-blinding...")
        self.host_data = host_data  # This should be the "prepared" data
        signed_data = self.host_data.copy()

        for i in range(0, len(signature_bits)):
            if signature_bits[i] == 1:
                idx_v = i // 3
                idx_c = i % 3

                # Flip the '0' bit to a '1' bit
                signed_data[idx_v][idx_c] = self.paillier.deterministic_self_blind(
                    signed_data[idx_v][idx_c]
                )

        self.watermarked_data = signed_data
        return self.watermarked_data

    def extract(self, watermarked_data: np.array) -> list:
        """
        Extracts the signature bit list from the ENCRYPTED domain.
        (User's 'extraction de la signature').

        Logic: Checks if a ciphertext is 'negative' or 'positive'.
               If 'negative' (in upper half of Z_N2) -> bit is 1.
               If 'positive' (in lower half of Z_N2) -> bit is 0.

        Args:
            watermarked_data (np.array): The signed encrypted data.

        Returns:
            list: The extracted signature bit list.
        """
        print("DSB: Extracting signature bits from encrypted domain...")
        extracted_bits = []
        N2 = self.paillier.N2
        threshold = (N2 + 1) // 2

        # This logic needs to be implemented based on your 'extracting.py'
        print(f"DSB: Extraction logic is a placeholder. Implement based on 'extracting.py'.")
        for i in range(self.signature_length):
            idx_v = i // 3
            idx_c = i % 3

            # --- TODO: Implement your DSB extraction logic here ---
            # val = watermarked_data[idx_v][idx_c]
            # if val >= threshold:
            #    recovered_bit = 1
            # else:
            #    recovered_bit = 0
            recovered_bit = 0  # Placeholder
            # --- End of TODO ---

            extracted_bits.append(recovered_bit)

        return extracted_bits

    def verify(self, watermarked_data: np.array) -> bool:
        """
        Performs full verification of the signature in the ENCRYPTED domain.
        (User's 'extraction... et la vérification').

        Args:
            watermarked_data (np.array): The signed data to verify.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        print("DSB: Starting full verification...")

        # 1. Extract the embedded signature
        extracted_signature_bits = self.extract(watermarked_data)

        # 2. "Clean" the data to get the original data that was hashed.
        #    This re-runs the preparation step to "zero-out" all
        #    embedded signature bits.
        prepared_data_for_hash = self._prepare_data_for_signing(watermarked_data)

        # 3. Re-calculate the expected signature from the "cleaned" data.
        #    This uses the public verification key.
        #    (We re-use generate_watermark, but in a real scenario
        #     this would use a separate 'verify_signature' function
        #     with the public key).

        # --- This part needs 'util.verify_signature' ---
        # print("DSB: Verification logic is a placeholder.")
        # verification_key_public = self.secret_key["verification"]
        # mesh_hash = ... (hash prepared_data_for_hash) ...
        # is_valid = util.verify_signature(mesh_hash,
        #                                  extracted_signature_bytes,
        #                                  verification_key_public)

        # --- Simple comparison method (if generate_watermark is deterministic) ---
        print("DSB: Re-generating expected signature for comparison...")
        expected_signature_bits = self.generate_watermark(prepared_data_for_hash)

        # 4. Compare
        is_valid = (extracted_signature_bits == expected_signature_bits)

        print(f"DSB: Verification complete. Signature is valid: {is_valid}")
        return is_valid