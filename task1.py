import secrets
import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# -----------------------------
# Helpers
# -----------------------------

def hex_to_int(s):
    """Turn a multi-line hex string (with spaces/newlines) into an integer."""
    oneline = "".join(s.split())
    return int(oneline, 16)


def sha256_trunc16_from_int(x):
    """
    Compute SHA256(x_as_bytes) and truncate to 16 bytes for AES-128 key.
    """
    x_bytes = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    return hashlib.sha256(x_bytes).digest()[:16]


def aes_cbc_encrypt(key16, iv16, plaintext_bytes):
    """
    AES-CBC encrypt with PKCS#7 padding.
    """
    cipher = AES.new(key16, AES.MODE_CBC, iv=iv16)
    return cipher.encrypt(pad(plaintext_bytes, AES.block_size))


def aes_cbc_decrypt(key16, iv16, ciphertext_bytes):
    """
    AES-CBC decrypt and remove PKCS#7 padding.
    """
    cipher = AES.new(key16, AES.MODE_CBC, iv=iv16)
    return unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)


def validate_dh_public(y, q):
    """
    Basic DH public value validation.
    Rejects obvious bad values.
    """
    if not (1 < y < q - 1):
        raise ValueError("Invalid DH public value (must satisfy 1 < y < q-1).")


# -----------------------------
# Plain Party class (no dataclass)
# -----------------------------

class Party:
    def __init__(self, name, q, a):
        self.name = name
        self.q = q
        self.a = a

        self.x_priv = None       # private exponent X
        self.y_pub = None        # public value Y = a^X mod q
        self.shared = None       # shared secret s
        self.key16 = None        # AES key (16 bytes)

    def pick_private(self):
        # Pick random X in [2, q-2]
        self.x_priv = secrets.randbelow(self.q - 3) + 2

    def compute_public(self):
        if self.x_priv is None:
            raise RuntimeError(self.name + ": private exponent not set")
        self.y_pub = pow(self.a, self.x_priv, self.q)

    def compute_shared_and_key(self, other_y):
        if self.x_priv is None:
            raise RuntimeError(self.name + ": private exponent not set")
        validate_dh_public(other_y, self.q)

        # s = (other_y)^x_priv mod q
        self.shared = pow(other_y, self.x_priv, self.q)

        # k = SHA256(s) truncated to 16 bytes
        self.key16 = sha256_trunc16_from_int(self.shared)


# -----------------------------
# Task 1: run DH + AES messages
# -----------------------------

def run_task1(q, a, label):
    print("\n" + "=" * 70)
    print("Task 1:", label)
    print("=" * 70)

    # Assignment says you may assume Alice and Bob use the same IV.
    # Real systems use random IVs (new per message).
    iv = b"\x00" * 16

    alice = Party("Alice", q, a)
    bob = Party("Bob", q, a)

    # Alice/Bob pick private exponents
    alice.pick_private()
    bob.pick_private()

    # Alice/Bob compute public values
    alice.compute_public()
    bob.compute_public()

    print("Alice sends Y_A =", alice.y_pub)
    print("Bob   sends Y_B =", bob.y_pub)

    # Compute shared secrets + AES keys
    alice.compute_shared_and_key(bob.y_pub)
    bob.compute_shared_and_key(alice.y_pub)

    print("Alice key (hex) =", alice.key16.hex())
    print("Bob   key (hex) =", bob.key16.hex())

    if alice.key16 != bob.key16:
        raise RuntimeError("ERROR: keys do not match!")

    # Exchange encrypted messages
    m0 = b"Hi Bob!"
    c0 = aes_cbc_encrypt(alice.key16, iv, m0)
    print("\nAlice -> Bob: c0 =", c0.hex())

    m0_dec = aes_cbc_decrypt(bob.key16, iv, c0)
    print("Bob decrypted m0:", m0_dec)

    m1 = b"Hi Alice!"
    c1 = aes_cbc_encrypt(bob.key16, iv, m1)
    print("\nBob -> Alice: c1 =", c1.hex())

    m1_dec = aes_cbc_decrypt(alice.key16, iv, c1)
    print("Alice decrypted m1:", m1_dec)

    print("\n✅ Success\n")


def main():
    # ---- Toy group ----
    run_task1(q=37, a=5, label="Toy parameters (q=37, a=5)")

    # ---- IETF 1024-bit parameters from the assignment ----
    q_hex = """
    B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
    9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
    13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
    98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
    A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
    DF1FB2BC 2E4A4371
    """

    a_hex = """
    A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
    D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
    160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
    909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
    D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
    855E6EEB 22B3B2E5
    """

    q = hex_to_int(q_hex)
    a = hex_to_int(a_hex)

    run_task1(q=q, a=a, label="IETF 1024-bit parameters (from assignment)")


if __name__ == "__main__":
    main()
