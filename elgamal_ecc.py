import secrets
from typing import Tuple, Optional, Dict

from hash_elliptic_curve import message_to_point, point_to_message
from standard_curves import StandardCurve, get_curve, CURVES


"""
ElGamal ECC Cryptosystem Implementation

This module implements the ElGamal cryptosystem using elliptic curve cryptography (ECC),
with support for various standard curves including Ed25519 and NIST curves.

Key Structure:
- Secret Key (sk): A random integer within the range [2, n-1] where n is the order of the base point
- Public Key (pk): The point pk = sk·G where G is the base point of the curve

Encryption:
- Message m is mapped to a point M on the curve
- Random ephemeral key k is chosen in range [2, n-1]
- Ciphertext: (A, B) where:
  - B = k·G (a point on the curve)
  - A = M + k·pk (a point on the curve)

Decryption:
- Recover message point: M = A - sk·B
- This works because: A - sk·B = M + k·pk - sk·(k·G) = M + k·(sk·G) - sk·(k·G) = M
- Then convert the message point back to the original message bytes

Security Notes:
- The security of this implementation relies on the Elliptic Curve Discrete Logarithm Problem (ECDLP)
- Message encoding to curve points must be done carefully to avoid information leakage
- Use cryptographically secure random number generation for all secret values
"""


class ElGamalECC:
    """
    ElGamal cryptosystem implementation using Elliptic Curve Cryptography.

    This class supports standard curves like NIST P-256, secp256k1, and Ed25519.
    """

    def __init__(self, curve_name):
        """
        Initialize the ElGamal ECC instance with a specified curve.

        Args:
            curve_name: Name of the standard curve to use (default: "Ed25519")
                        Supported curves include NIST curves (P-256, P-384, etc.),
                        secp256k1, and Brainpool curves.
        """
        self.debug_mode = False
        self.secret_key = None
        self.public_key = None


        # Use StandardCurve from standard_curves module
        self.std_curve = get_curve(curve_name)
        self.curve = self.std_curve.curve
        self.base_point = self.std_curve.G
        self.curve_name = curve_name

    def set_debug(self, enable: bool = True) -> None:
        """
        Enable or disable debug output.

        Args:
            enable: True to enable debugging output, False to disable
        """
        self.debug_mode = enable

    def _debug_print(self, *args, **kwargs) -> None:
        """Print debug information if debug mode is enabled."""
        if self.debug_mode:
            print(*args, **kwargs)

    @classmethod
    def list_available_curves(cls) -> Dict[str, str]:
        """
        List all available standard curves that can be used with this class.

        Returns:
            Dictionary mapping curve names to their descriptions
        """
        result = {}

        # Add special Ed25519 case

        # Add all standard curves
        for name, curve in CURVES.items():
            # Skip aliases to avoid duplication
            if name in {'NIST P-192', 'NIST P-224', 'NIST P-256', 'NIST P-384', 'NIST P-521',
                        'secp192r1', 'secp224r1', 'secp256r1', 'secp384r1', 'secp521r1'}:
                continue

            bits = curve.p.bit_length()
            result[name] = f"{bits}-bit standard curve"

        return result

    def generate_keys(self) -> Tuple[int, Tuple[int, int]]:
        """
        Generate a key pair (secret key, public key).

        Returns:
            Tuple of (secret_key, public_key) where public_key is a point on the curve
        """
        # For standard curves, use the order of the base point (n)
        # For Ed25519, use the prime field order (p)
        if self.std_curve:
            order = self.std_curve.n
        else:
            order = self.curve.p

        # Generate a cryptographically secure random secret key
        self.secret_key = secrets.randbelow(order - 2) + 2

        # Calculate the public key as sk·G
        self.public_key = self.curve.mul_point(self.base_point, self.secret_key)

        return self.secret_key, self.public_key

    def encrypt(self, message: bytes,
                public_key: Optional[Tuple[int, int]] = None) -> bytes:
        """
        Encrypt a message using ElGamal ECC.

        Args:
            message: The message to encrypt as bytes
            public_key: Optional public key point. If None, uses self.public_key.

        Returns:
            Compressed ciphertext bytes (concatenation of compressed points A and B)

        Raises:
            ValueError: If no public key is available or message is too large
        """
        # Use provided public key or instance public key
        pk = public_key if public_key is not None else self.public_key
        if pk is None:
            raise ValueError("Public key not provided and not available in instance")

        # Convert message to a point on the curve
        try:
            message_point = message_to_point(message, self.std_curve)
            self._debug_print(f"message_to_point: {message_point}")
        except Exception as e:
            raise ValueError(f"Failed to convert message to curve point: {e}")

        # Generate a random ephemeral key using appropriate order
        if self.std_curve:
            order = self.std_curve.n
        else:
            order = self.curve.p

        k = secrets.randbelow(order - 2) + 2

        # Calculate ciphertext components
        # B = k·G
        B = self.curve.mul_point(self.base_point, k)

        # A = M + k·pk
        A = self.curve.add_point(self.curve.mul_point(pk, k), message_point)

        self._debug_print(f"A: {A}")
        self._debug_print(f"B: {B}")

        # Use the curve's native point compression
        return (self.curve.compress_point(A), self.curve.compress_point(B))

    def decrypt(self, ciphertext: tuple,
                secret_key: Optional[int] = None) -> bytes:
        """
        Decrypt a ciphertext using ElGamal ECC.

        Args:
            ciphertext: The compressed ciphertext bytes (A||B)
            secret_key: Optional secret key. If None, uses self.secret_key.

        Returns:
            Decrypted message as bytes

        Raises:
            ValueError: If ciphertext is invalid or no secret key is available
        """
        if len(ciphertext) != 2:
            raise ValueError(f"Invalid ciphertext length: {len(ciphertext)}")

        # Use provided secret key or instance secret key
        sk = secret_key if secret_key is not None else self.secret_key
        if sk is None:
            raise ValueError("Secret key not provided and not available in instance")

        try:

            # For other curves, use curve's native decompression
            A_compressed, B_compressed= ciphertext

            # Extract x-coordinate and parity bit
            A_x  = A_compressed[0]
            A_y = A_compressed[1]

            B_x = B_compressed[0]
            B_y = B_compressed[1]

            # Recover y-coordinates
            A = self.curve.y_recover(A_x, A_y)
            B = self.curve.y_recover(B_x, B_y)


            self._debug_print(f"A: {A}")
            self._debug_print(f"B: {B}")

            # Recover the message point: M = A - sk·B
            sk_times_B = self.curve.mul_point(B, sk)
            message_point = self.curve.sub_point(A, sk_times_B)

            self._debug_print(f"decrypt message point: {message_point}")

            # Convert the message point back to the original message
            return point_to_message(message_point, self.std_curve)

        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

    def sign(self, message: bytes,
             secret_key: Optional[int] = None) -> Tuple[int, int]:
        """
        Sign a message using ElGamal signature scheme.

        Note: This is a basic implementation and should not be used for
        security-critical applications. Consider using established
        signature schemes like ECDSA or EdDSA instead.

        Args:
            message: Message to sign
            secret_key: Optional secret key. If None, uses self.secret_key.

        Returns:
            Tuple (r, s) representing the signature
        """
        # Use provided secret key or instance secret key
        sk = secret_key if secret_key is not None else self.secret_key
        if sk is None:
            raise ValueError("Secret key not provided and not available in instance")

        # Get appropriate order
        if self.std_curve:
            order = self.std_curve.n
        else:
            order = self.curve.p

        # Hash the message to an integer modulo order
        hash_bytes = message_to_point(message)
        h = int.from_bytes(hash_bytes[:32], byteorder='big') % order

        # Generate ephemeral key
        while True:
            k = secrets.randbelow(order - 2) + 2
            # Check if gcd(k, order) = 1
            if pow(k, order - 2, order) * k % order == 1:
                break

        # Calculate r = (k·G).x mod order
        R = self.curve.mul_point(self.base_point, k)
        r = R[0] % order

        # Calculate s = k^(-1) * (h + r*sk) mod order
        k_inv = pow(k, order - 2, order)  # Fermat's little theorem for modular inverse
        s = (k_inv * (h + r * sk)) % order

        return (r, s)

    def verify_signature(self, message: bytes, signature: Tuple[int, int],
                         public_key: Optional[Tuple[int, int]] = None) -> bool:
        """
        Verify an ElGamal signature.

        Args:
            message: Original message
            signature: Tuple (r, s) representing the signature
            public_key: Optional public key. If None, uses self.public_key.

        Returns:
            True if signature is valid, False otherwise
        """
        # Use provided public key or instance public key
        pk = public_key if public_key is not None else self.public_key
        if pk is None:
            raise ValueError("Public key not provided and not available in instance")

        r, s = signature

        # Get appropriate order
        if self.std_curve:
            order = self.std_curve.n
        else:
            order = self.curve.p

        # Validate signature components
        if not (0 < r < order and 0 < s < order):
            return False

        # Hash the message to an integer modulo order
        hash_bytes = message_to_point(message)
        h = int.from_bytes(hash_bytes[:32], byteorder='big') % order

        # Calculate s^(-1) mod order
        s_inv = pow(s, order - 2, order)

        # Calculate u1 = h * s^(-1) mod order and u2 = r * s^(-1) mod order
        u1 = (h * s_inv) % order
        u2 = (r * s_inv) % order

        # Calculate P = u1*G + u2*pk
        P1 = self.curve.mul_point(self.base_point, u1)
        P2 = self.curve.mul_point(pk, u2)
        P = self.curve.add_point(P1, P2)

        # Signature is valid if P.x mod order == r
        return P[0] % order == r

    @staticmethod
    def verify_decryption(original: bytes, decrypted: bytes) -> bool:
        """
        Verify if decryption was successful by comparing original and decrypted messages.

        Args:
            original: Original message
            decrypted: Decrypted message

        Returns:
            True if messages match, False otherwise
        """
        return original == decrypted






if __name__ == "__main__":
    # Test message
    message = b"Hellox, world!"

    # List available curves
    print("\n=== Available Curves ===")
    curves = ElGamalECC.list_available_curves()
    for curve_name, description in curves.items():
        print(f"- {curve_name}: {description}")

    # Test with Ed25519 (default)
    print("\n=== Testing with Ed25519 Curve ===")
    elgamal_ed25519 = ElGamalECC("P-192")  # Default is Ed25519
    elgamal_ed25519.set_debug(True)
    sk, pk = elgamal_ed25519.generate_keys()

    # Encrypt and decrypt
    ciphertext = elgamal_ed25519.encrypt(message)
    print(f"Ciphertext length: {len(ciphertext)} bytes")

    decrypted = elgamal_ed25519.decrypt(ciphertext)
    print(f"Original:  {message}")
    print(f"Decrypted: {decrypted}")
    print(f"Success: {elgamal_ed25519.verify_decryption(message, decrypted)}")

    # Test signature
