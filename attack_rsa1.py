import argparse
import sys
from Crypto.Util.number import long_to_bytes
import libnum
from math import gcd


def modinv(a, m):
    return pow(a, -1, m)

def perform_crt_attack(n_values, e_values, c_values):
    if len(n_values) < 2:
        print("CRT attack requires at least two moduli.")
        return

    if len(set(e_values)) != 1:
        print("All public exponents (e) must be the same for CRT attack.")
        return

    result = libnum.solve_crt(c_values, n_values)
    e = e_values[0]
    val = libnum.nroot(result, e)
    print("Message: ", val)
    print("Recovered plaintext:", long_to_bytes(val).decode())

def perform_common_modulus_attack(n_values, e_values, c_values):
    if len(set(n_values)) != 1:
        print("All the moduli must be the same for Common Modulus attack.")
        return
    
    if len(e_values) < 2:
        print("Common modulus attack requires at least two different public exponents (e).")
        return

    n = n_values[0]
    e1, e2 = e_values[0], e_values[1]
    c1, c2 = c_values[0], c_values[1]

    g = gcd(e1, e2)
    if g != 1:
        print("Exponents e1 and e2 must be coprime!", file=sys.stderr)
        sys.exit(1)

    s1 = modinv(e1, e2)
    s2 = (g - e1 * s1) // e2

    temp = modinv(c2, n)
    m1 = pow(c1, s1, n)
    m2 = pow(temp, -s2, n)
    r1 = (m1 * m2) % n

    
    print("Message: ", r1)
    byte_length = (r1.bit_length() + 7) // 8  
    byte_representation = r1.to_bytes(byte_length, byteorder='big')
    ascii_string = byte_representation.decode()
    print("Plain Text message" , ascii_string)
    

def main():
    parser = argparse.ArgumentParser(description="RSA Attack Tool")
    parser.add_argument("-n", "--moduli", nargs='+', type=int, required=True, help="List of RSA moduli (at least one)")
    parser.add_argument("-e", "--exponents", nargs='+', type=int, required=True, help="List of RSA public exponents (at least one)")
    parser.add_argument("-c", "--ciphertexts", nargs='+', type=int, required=True, help="List of RSA ciphertexts (at least two)")

    args = parser.parse_args()

    if not args.moduli or not args.exponents or len(args.ciphertexts) < 2:
        print("Please provide a modulus (-n), exponents (-e) and ciphertexts (-c).")
        return

    n_values = args.moduli
    e_values = args.exponents
    c_values = args.ciphertexts

    if len(n_values) == 1:
        n_values *= len(c_values)
    if len(e_values) == 1:
        e_values *= len(c_values)

    if len(n_values) != len(c_values) or len(e_values) != len(c_values):
        print("The number of moduli, exponents, and ciphertexts must match.")
        return

    print("RSA Moduli:", n_values)
    print("Public Exponents:", e_values)
    print("Ciphertexts:", c_values)

    print("\n")
    print("Choose attack type: ")
    sys.stdout.write('[1] Chinese Remainder Theorem Attack\n')
    sys.stdout.write('[2] Common Modulo Attack\n\n')
    attack_choice = input("-Enter your choice: ").strip()

    if attack_choice == "1":
        perform_crt_attack(n_values, e_values, c_values)
    elif attack_choice == "2":
        perform_common_modulus_attack(n_values, e_values, c_values)
    else:
        print("Invalid choice. Please choose either '1' for CRT Attack or '2' for Common Modulus Attack.")

if __name__ == "__main__":
    main()