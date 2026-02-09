import secrets
import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def hex_to_int(s):
    oneline = "".join(s.split())                                        # remove whitespace and concat
    return int(oneline, 16)                                             # parse as hex

def sha256_trunc16(x):
    x_bytes = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")         # convert int to bytes
    return hashlib.sha256(x_bytes).digest()[:16]                        # hash and truncate

def aes_cbc_encrypt(key16, iv16, plaintext_bytes):
    cipher = AES.new(key16, AES.MODE_CBC, iv=iv16)                      # encrypt
    return cipher.encrypt(pad(plaintext_bytes, AES.block_size))         # add padding

def aes_cbc_decrypt(key16, iv16, ciphertext_bytes):
    cipher = AES.new(key16, AES.MODE_CBC, iv=iv16)                      # decrypt
    return unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)      # remove padding

class Party:
    def __init__(self, q, a):
        self.q = q
        self.a = a

        self.x_priv = None       # private exponent X
        self.y_pub = None        # public value Y = a^X mod q
        self.shared = None       # shared secret s
        self.key16 = None        # AES key (16 bytes)

    def pick_private(self):
        self.x_priv = secrets.randbelow(self.q - 1)      # Pick random X in [0, q-1]

    def compute_public(self):
        self.y_pub = pow(self.a, self.x_priv, self.q)

def run_task2(q, a, label):
    print("\n" + "=" * 70)
    print("Task 2:", label)
    print("=" * 70)

    iv = b"\x00" * 16 # same IV

    alice = Party(q, 1)
    bob = Party(q, 1)
    mallory = Party(q, 1)

    # private exponents x
    alice.pick_private()
    bob.pick_private()
    mallory.pick_private()

    # public values y
    alice.compute_public()
    bob.compute_public()
    mallory.compute_public()

    print("\nY_A =", alice.y_pub)
    print("Y_B =", bob.y_pub)

    # Compute shared secrets + AES keys
    alice.shared = pow(bob.y_pub, alice.x_priv, alice.q)
    alice.key16 = sha256_trunc16(alice.shared)

    bob.shared = pow(alice.y_pub, bob.x_priv, bob.q)
    bob.key16 = sha256_trunc16(bob.shared)

    mallory.shared = pow(mallory.y_pub, mallory.x_priv, mallory.q)
    mallory.key16 = sha256_trunc16(mallory.shared)
    
    print("\nAlice key (hex) =", alice.key16.hex())
    print("Bob   key (hex) =", bob.key16.hex())
    print("Mallory key (hex) =", mallory.key16.hex())

    # Exchange encrypted messages
    m0 = b"Hi Bob!"
    c0 = aes_cbc_encrypt(alice.key16, iv, m0)
    print("\nAlice -> Bob: c0 =", c0.hex())

    m0_dec = aes_cbc_decrypt(bob.key16, iv, c0)
    print("Bob decrypted c0:", m0_dec)

    m1 = b"Hi Alice!"
    c1 = aes_cbc_encrypt(bob.key16, iv, m1)
    print("\nBob -> Alice: c1 =", c1.hex())

    m1_dec = aes_cbc_decrypt(alice.key16, iv, c1)
    print("Alice decrypted c1:", m1_dec)

    # Mallory can also decrypt both messages since she knows the shared secret
    mal_dec_c0 = aes_cbc_decrypt(mallory.key16, iv, c0)
    print("\nMallory decrypted c0:", mal_dec_c0)

    mal_dec_c1 = aes_cbc_decrypt(mallory.key16, iv, c1)
    print("Mallory decrypted c1:", mal_dec_c1)

def main():
    # ---- small group ----
    run_task2(q=37, a=5, label="q=37, a=5")

    # ---- real number group ----
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

    run_task2(q=q, a=a, label="IETF 1024-bit parameters")


if __name__ == "__main__":
    main()
