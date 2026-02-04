import secrets
from Crypto.Util import number

e = 65537  # Common choice for e

def generate_rand_prime():
    """Generate a random prime number of specified bit length."""
    return number.getPrime(2048, randfunc=secrets.token_bytes)

def compute_rsa_values():
    p = generate_rand_prime()
    q = generate_rand_prime()
    n = p * q
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)  # Modular inverse of e mod phi_n
    return p, q, n, phi_n, d

def ascii_to_hex_to_int(s):
    hex_str = s.encode().hex()
    return int(hex_str, 16)

def rsa_encrypt(m, e, n):
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

def run_task3():
    print("\n" + "=" * 70)
    print("Task 3: RSA Key Generation and Encryption/Decryption")
    print("=" * 70)

    # Generate RSA values
    p, q, n, phi_n, d = compute_rsa_values()
    print(f"\nPrime p: {p}")
    print(f"\nPrime q: {q}")
    print(f"\nModulus n: {n}")
    print(f"\nTotient φ(n): {phi_n}")
    print(f"\nPrivate exponent d: {d}")

    # Message to encrypt
    message = "The quick brown fox jumps over the lazy dog"
    m = ascii_to_hex_to_int(message)
    print(f"\nOriginal message: {message}")
    print(f"\nMessage as integer m: {m}")

    # Encrypt the message
    c = rsa_encrypt(m, e, n)
    print(f"\nEncrypted ciphertext c: {c}")

    # Decrypt the message
    m_decrypted = rsa_decrypt(c, d, n)
    print(f"\nDecrypted message as integer m: {m_decrypted}")

    # Convert decrypted integer back to string
    hex_decrypted = hex(m_decrypted)[2:]  # Remove '0x' prefix
    if len(hex_decrypted) % 2 != 0:
        hex_decrypted = '0' + hex_decrypted  # Ensure even length for bytes conversion
    decrypted_message = bytes.fromhex(hex_decrypted).decode()
    print(f"\nDecrypted message: {decrypted_message}")

if __name__ == "__main__":
    run_task3()