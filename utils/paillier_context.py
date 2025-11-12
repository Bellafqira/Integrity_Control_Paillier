import gmpy2
import time
from gmpy2 import mpz, powmod, invert, gcd, mpz_random, random_state, mpz_urandomb, next_prime


class PaillierContext:
    """
    Encapsulates the Paillier cryptosystem logic using gmpy2.

    This class provides the low-level, deterministic crypto operations
    required by the FDSB scheme. These operations (deterministic
    encryption with r=1, and arithmetic self-blinding via negation)
    are not available in high-level libraries like 'phe'.
    """

    def __init__(self, key_size=1024):
        """
        Initializes the context and generates Paillier keys.

        Args:
            key_size (int): The bit length for the Paillier key (e.g., 1024, 2048).
        """
        print(f"Generating {key_size}-bit Paillier keys...")
        self._generate_keys(key_size)
        self.N2 = self.N ** 2
        print("PaillierContext initialized.")

    def _get_prime(self, size):
        """Helper function to generate a random prime of 'size' bits."""
        seed = random_state(int(time.time() * 1000000))
        p = mpz_urandomb(seed, size)
        p = p.bit_set(size - 1)  # Ensure MSB is 1 for correct bit size
        return next_prime(p)

    def _generate_keys(self, size):
        """
        Generates Paillier public and private key components.
        Uses the g = 1 + N optimization for faster encryption.
        """
        p = self._get_prime(size // 2)
        while True:
            q = self._get_prime(size // 2)
            self.N = p * q
            self.phi = (p - 1) * (q - 1)
            # Ensure N and phi are coprime, and p != q
            if gcd(self.N, self.phi) == 1 and p != q:
                break

        # g = 1 + N optimization
        self.g = 1 + self.N

        # Pre-calculate phi_inv for fast decryption (L-function)
        self.phi_inv = invert(self.phi, self.N)

    # --- Public Crypto API ---

    def encrypt_deterministic(self, message):
        """
        Performs deterministic Paillier encryption by fixing r=1.

        This is essential for the FDSB scheme.
        Uses the optimization: E(m, r=1) = (g^m * r^N) mod N^2
                                        = ((1+N)^m * 1^N) mod N^2
                                        = (1 + m*N) mod N^2

        Args:
            message (int or mpz): The plaintext message to encrypt.

        Returns:
            mpz: The deterministic ciphertext.
        """
        return (1 + mpz(message) * self.N) % self.N2

    def decrypt(self, ciphertext):
        """
        Performs fast Paillier decryption.

        Uses the L-function optimization:
        m = L(c^phi mod N^2) * phi_inv mod N
        where L(x) = (x - 1) // N

        Args:
            ciphertext (mpz): The ciphertext to decrypt.

        Returns:
            mpz: The decrypted plaintext message.
        """
        m = powmod(ciphertext, self.phi, self.N2)
        m = (m - 1) // self.N
        m = (m * self.phi_inv) % self.N
        return m % self.N

    # --- API for Watermarking Schemes ---

    def homomorphic_add(self, c1, c2):
        """
        Performs homomorphic addition of two ciphertexts.
        E(m1) * E(m2) = E(m1 + m2)

        Args:
            c1 (mpz): First ciphertext.
            c2 (mpz): Second ciphertext.

        Returns:
            mpz: The resulting ciphertext E(m1 + m2).
        """
        return (c1 * c2) % self.N2

    def deterministic_self_blind(self, c):
        """
        Performs the deterministic self-blinding operation (negation).
        -E(m) mod N^2 = E(-m) mod N^2

        This is the core operation for embedding the DSB signature bits.

        Args:
            c (mpz): The ciphertext to "flip".

        Returns:
            mpz: The resulting "flipped" ciphertext.
        """
        return (-c) % self.N2