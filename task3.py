import secrets

from task2_1 import sha256_trunc16, aes_cbc_encrypt, aes_cbc_decrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number

e = 65537                                                       # Common choice for e

def generate_rand_prime():
    return number.getPrime(2048, randfunc=secrets.token_bytes)  # Generate random 2048-bit prime``

def generate_rand_int(n):
    while True:
        s = secrets.randbelow(n - 1) + 1                        # Pick random s in [1, n-1]
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

            if number.GCD(e, self.phi_n) != 1:
                continue                                        # Try again if e and phi_n are not coprime

            self.d = pow(e, -1, self.phi_n)                     # Modular inverse of e mod phi_n
            return self.p, self.q, self.n, self.phi_n, self.d
        
    def sign(self, message):
        m = ascii_to_hex_to_int(message)
        return rsa_encrypt(m, self.d, self.n)

def run_task3():
    print("\n" + "=" * 70)
    print("Task 3: RSA Key Generation and Encryption/Decryption")
    print("=" * 70)

    Alice = Party("Alice")
    Bob = Party("Bob")
    Mallory = Party("Mallory")

    # Alice generates RSA values and sends n to Bob and Mallory
    Alice.generate_rsa_values()
    Bob.n = Alice.n
    Mallory.n = Alice.n

    # Bob generates s and computes c
    Bob.s = generate_rand_int(Bob.n)
    Bob.c = rsa_encrypt(Bob.s, e, Bob.n)

    # Mallory generates r and computes c' 
    Mallory.r = generate_rand_int(Mallory.n)
    # Mallory.c = (Bob.c * rsa_encrypt(Mallory.r, e, Mallory.n)) % Mallory.n # Mallory computes c' = c_Bob * c_Mallory mod n
    Mallory.c = 1

    # Mallory sends c' to Alice, Alice decrypts to get s'
    Alice.c = Mallory.c
    Alice.s = rsa_decrypt(Alice.c, Alice.d, Alice.n)


    Alice.k = sha256_trunc16(Alice.s)
    print(f"\nAlice's computed s: {Alice.s}")
    print(f"\nAlice's derived key (hex): {Alice.k.hex()}")

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
    # Mallory.s = Bob.s * Mallory.r % Mallory.n                                   # Mallory can compute s = s_Bob * r mod n
    Mallory.s = 1
    Mallory.k = sha256_trunc16(Mallory.s)
    print(f"\nMallory's computed s: {Mallory.s}")
    print(f"\nMallory's derived key (hex): {Mallory.k.hex()}")
    mallory_decrypted = aes_cbc_decrypt(Mallory.k, b"\x00" * 16, c)
    print(f"\nDecrypted message using Mallory's key: {mallory_decrypted}")

    # Alice signatures
    m1 = "Poop butt"
    m2 = "Butt poop"
    sig1 = Alice.sign(m1)
    sig2 = Alice.sign(m2)
    print(f"\nAlice's signature on m1: {sig1}")
    print(f"\nAlice's signature on m2: {sig2}")

    # Mallory signature forgery
    sig3 = (sig1 * sig2) % Mallory.n                                    # Mallory computes sig3 = sig1 * sig2 mod n
    m3 = ascii_to_hex_to_int(m1) * ascii_to_hex_to_int(m2)              # Mallory computes m3 = m1 * m2 as integer
    verifty_sig3 = rsa_encrypt(sig3, e, Mallory.n)                      # Verify sig3 by encrypting it with e
    print(f"\nMallory's forged signature sig3: {sig3}")
    print(f"\nMessage m3 as integer: {m3}")
    print(f"\nVerification of sig3: {verifty_sig3}")

if __name__ == "__main__":
    run_task3()