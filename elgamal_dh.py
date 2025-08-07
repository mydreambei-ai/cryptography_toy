import secrets
from typing import Tuple, Union, Optional

from common import (
    bytes_to_int,
    find_primitive_root,
    int_to_bytes,
    miller_rabin_prime_test,
)
from galois import GF, GFItem

"""
ElGamal Diffie-Hellman Implementation

Key Structure:
- Secret Key (sk): A random integer within the range [2, p-1]
- Public Key (pk): A tuple (p, g, y) where:
  - p: Large prime number
  - g: Primitive root modulo p
  - y: g^sk mod p

Encryption:
- Message m must be in the prime field space [0, p-1]
- Random ephemeral key k is chosen in range [2, p-1]
- Ciphertext: (a, b) where:
  - a = g^k mod p
  - b = y^k * m mod p

Decryption:
- Recover message: m = b * (a^sk)^(-1) mod p
- This works because: a^sk = (g^k)^sk = g^(k*sk) = y^k
- Therefore: b * (a^sk)^(-1) = y^k * m * (y^k)^(-1) = m
"""


class ElGamalDH:
    """ElGamal Diffie-Hellman cryptosystem implementation."""

    def __init__(self, p: Optional[int] = None, g: Optional[int] = None):
        """
        Initialize an ElGamal instance with optional parameters.

        Args:
            p: Optional prime modulus. If None, must be set later.
            g: Optional primitive root. If None, must be set later.
        """
        self.p = p
        self.g = g
        self.sk = None
        self.y = None

    @classmethod
    def generate(cls, bit_length: int = 256) -> 'ElGamalDH':
        """
        Create a new ElGamal instance with freshly generated parameters.

        Args:
            bit_length: Bit length for the prime number (default: 256)

        Returns:
            A new ElGamal instance with generated parameters
        """
        # Start with a random number with the desired bit length
        n = secrets.randbits(bit_length)
        # Ensure n is odd
        if n % 2 == 0:
            n += 1

        # Find a prime by decrementing from the initial value
        p = None
        while True:
            if miller_rabin_prime_test(n):
                p = n
                break
            n -= 2  # Skip even numbers to improve efficiency

        # Find a primitive root modulo p
        g = find_primitive_root(p)

        # Create and return the instance
        instance = cls(p, g)
        return instance

    def generate_keys(self) -> Tuple[int, Tuple[int, int, int]]:
        """
        Generate a key pair (secret key, public key).

        Returns:
            Tuple of (secret_key, public_key) where public_key is (p, g, y)
        """
        if self.p is None or self.g is None:
            raise ValueError("Prime modulus p and primitive root g must be set")

        # Generate a random secret key in the range [2, p-2]
        self.sk = secrets.randbelow(self.p - 2) + 2

        # Calculate public key component y = g^sk mod p
        self.y = pow(self.g, self.sk, self.p)

        # Return the key pair
        return self.sk, (self.p, self.g, self.y)

    def encrypt(self, message: Union[bytes, int],
                public_key: Optional[Tuple[int, int, int]] = None) -> Tuple[int, int]:
        """
        Encrypt a message using ElGamal.

        Args:
            message: The message to encrypt, either as bytes or an integer
            public_key: Optional public key tuple (p, g, y). If None, uses self parameters.

        Returns:
            Tuple (a, b) representing the ciphertext
        """
        # Convert message to integer if it's in bytes
        if isinstance(message, bytes):
            m = bytes_to_int(message)
        else:
            m = message

        # Use provided public key or instance parameters
        if public_key:
            p, g, y = public_key
        else:
            if None in (self.p, self.g, self.y):
                raise ValueError("Public key parameters not available")
            p, g, y = self.p, self.g, self.y

        # Ensure message is in the correct range
        if m >= p:
            raise ValueError(f"Message too large for prime field (must be < {p})")

        # Generate a random ephemeral key
        k = secrets.randbelow(p - 2) + 2

        # Compute ciphertext components
        a = pow(g, k, p)
        b = (pow(y, k, p) * m) % p

        return (a, b)

    def decrypt(self, ciphertext: Tuple[int, int],
                secret_key: Optional[int] = None,
                prime: Optional[int] = None) -> bytes:
        """
        Decrypt a ciphertext using ElGamal.

        Args:
            ciphertext: Tuple (a, b) representing the ciphertext
            secret_key: Optional secret key. If None, uses self.sk
            prime: Optional prime modulus. If None, uses self.p

        Returns:
            Decrypted message as bytes
        """
        a, b = ciphertext

        # Use provided secret key or instance parameters
        sk = secret_key if secret_key is not None else self.sk
        p = prime if prime is not None else self.p

        if sk is None or p is None:
            raise ValueError("Secret key and prime modulus must be available")

        # Create Galois Field for modular arithmetic
        F = GF(p)

        # Compute shared secret s = a^sk mod p
        s = pow(a, sk, p)

        # Compute s^(-1) * b mod p to recover the message
        m: GFItem = F(b) / F(s)

        return int_to_bytes(m.item)


def generate_keys(n: int) -> Tuple[int, Tuple[int, int, int]]:
    """
    Legacy function to generate ElGamal keys starting from a number.

    Args:
        n: Starting point for prime search

    Returns:
        Tuple of (secret_key, public_key) where public_key is (p, g, y)
    """
    p = None
    while True:
        if miller_rabin_prime_test(n):
            p = n
            break
        n -= 1

    g = find_primitive_root(p)
    sk = secrets.randbelow(p - 2) + 2
    pk = (p, g, pow(g, sk, p))

    return sk, pk


def encrypt(m: bytes, pk: Tuple[int, int, int]) -> Tuple[int, int]:
    """
    Legacy function to encrypt a message using ElGamal.

    Args:
        m: Message to encrypt
        pk: Public key tuple (p, g, y)

    Returns:
        Tuple (a, b) representing the ciphertext
    """
    m_int = bytes_to_int(m)
    p, g, y = pk

    k = secrets.randbelow(p - 2) + 2
    return (pow(g, k, p), (pow(y, k, p) * m_int) % p)


def decrypt(ciphertext: Tuple[int, int], sk: int, pk: Tuple[int, int, int]) -> bytes:
    """
    Legacy function to decrypt a ciphertext using ElGamal.

    Args:
        ciphertext: Tuple (a, b) representing the ciphertext
        sk: Secret key
        pk: Public key tuple (p, g, y)

    Returns:
        Decrypted message as bytes
    """
    a, b = ciphertext
    p = pk[0]

    F = GF(p)
    m: GFItem = F(b) / F(pow(a, sk, p))

    return int_to_bytes(m.item)


if __name__ == "__main__":
    # Example using the modern class interface
    print("Testing ElGamal DH implementation...")

    # Test with small parameters for demonstration
    test_message = b"hello,world"

    # Class-based API
    print("\nUsing class-based API:")
    elgamal = ElGamalDH.generate(bit_length=256)
    sk, pk = elgamal.generate_keys()
    ciphertext = elgamal.encrypt(test_message)
    decrypted = elgamal.decrypt(ciphertext)
    print(f"Original: {test_message}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_message == decrypted}")

    # Legacy API for backwards compatibility
    print("\nUsing legacy API:")
    sk, pk = generate_keys(2**256)
    ciphertext = encrypt(test_message, pk)
    decrypted = decrypt(ciphertext, sk, pk)
    print(f"Original: {test_message}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_message == decrypted}")
