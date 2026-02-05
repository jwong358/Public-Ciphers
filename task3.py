import hashlib
import secrets

from task2 import sha256_trunc16, aes_cbc_encrypt, aes_cbc_decrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number

e = 65537                                                       # Common choice for e

def generate_rand_prime():
    return number.getPrime(2048, randfunc=secrets.token_bytes)  # Generate random 2048-bit prime``

def generate_rand_int(n):
    while True:
        s = secrets.randbelow(n - 2) + 1                        # Pick random s in [1, n-1]
        if number.GCD(s, n) == 1:                               # Ensure s is coprime to n
            return s
        
def rsa_encrypt(m, e, n):
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

def ascii_to_hex_to_int(s):
    hex_str = s.encode().hex()
    return int(hex_str, 16)

class Party:
    def __init__(self, name):
        self.name = name
        self.p = None          # prime p
        self.q = None          # prime q
        self.n = None          # modulus n = p * q
        self.phi_n = None      # totient φ(n) = (p-1)(q-1)
        self.d = None          # private exponent d
        self.s = None          # secret s
        self.c = None          # ciphertext c
        self.r = None          # decrypted secret r
        self.k = None          # derived key k

    def generate_rsa_values(self):
        while True:
            self.p = generate_rand_prime()
            self.q = generate_rand_prime()

            if self.p == self.q:
                continue                                        # Try again if p and q are the same

            self.n = self.p * self.q
            self.phi_n = (self.p - 1) * (self.q - 1)

            if number.GCD(self.n, self.phi_n) != 1:
                continue                                        # Try again if e and phi_n are not coprime

            self.d = pow(e, -1, self.phi_n)                     # Modular inverse of e mod phi_n
            return self.p, self.q, self.n, self.phi_n, self.d

def run_task3():
    print("\n" + "=" * 70)
    print("Task 3: RSA Key Generation and Encryption/Decryption")
    print("=" * 70)

    # # Generate RSA values
    # p, q, n, phi_n, d = compute_rsa_values()
    # print(f"\nPrime p: {p}")
    # print(f"\nPrime q: {q}")
    # print(f"\nModulus n: {n}")
    # print(f"\nTotient φ(n): {phi_n}")
    # print(f"\nPrivate exponent d: {d}")

    Alice = Party("Alice")
    Bob = Party("Bob")
    Mallory = Party("Mallory")

    Alice.generate_rsa_values()
    Bob.n = Alice.n
    Mallory.n = Alice.n

    Bob.s = generate_rand_int(Bob.n)
    Bob.c = rsa_encrypt(Bob.s, e, Bob.n)

    Mallory.r = generate_rand_int(Mallory.n)
    Mallory.c = Bob.c * rsa_encrypt(Mallory.r, e, Mallory.n)

    Alice.c = Mallory.c
    Alice.s = rsa_decrypt(Alice.c, Alice.d, Alice.n)

    Alice.k = sha256_trunc16(Alice.s)

    # Message to encrypt
    message = "The quick brown fox jumps over the lazy dog"
    m = ascii_to_hex_to_int(message)

    print(f"\nOriginal message: {message}")
    print(f"\nMessage as integer m: {m}")

    # Encrypt the message
    c = aes_cbc_encrypt(Alice.k, b"\x00" * 16, message.encode())
    print(f"\nEncrypted ciphertext c using Alice's key: {c}")

    # Decrypt the message
    alice_decrypted = aes_cbc_decrypt(Alice.k, b"\x00" * 16, c)
    print(f"\nDecrypted message using Alice's key: {alice_decrypted}")

    # Decrypt the message using Mallory's key
    Mallory.s = rsa_decrypt(Mallory.c, Alice.d, Mallory.n)


    # # Convert decrypted integer back to string
    # hex_decrypted = hex(m_decrypted)[2:]  # Remove '0x' prefix
    # if len(hex_decrypted) % 2 != 0:
    #     hex_decrypted = '0' + hex_decrypted  # Ensure even length for bytes conversion
    # decrypted_message = bytes.fromhex(hex_decrypted).decode()
    # print(f"\nDecrypted message: {decrypted_message}")

if __name__ == "__main__":
    run_task3()