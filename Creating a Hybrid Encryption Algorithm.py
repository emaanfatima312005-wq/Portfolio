# =======================================================
# Classical Cipher Toolkit - Complete Interactive Version
# Includes:
# Additive, Multiplicative, Affine, Monoalphabetic,
# Autokey, Playfair, Vigenère,
# Keyless Transposition, Keyed Transposition,
# Combination (Keyless + Keyed), Double Transposition
# =======================================================

import sys
import string

# ---------- Helper Functions ----------
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(key, mod=26):
    for i in range(1, mod):
        if (key * i) % mod == 1:
            return i
    return None


# =======================================================
# Additive Cipher
# =======================================================
def additive_encrypt(plaintext, key):
    result = ""
    for ch in plaintext:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            result += chr(((ord(ch) - base + key) % 26) + base)
        else:
            result += ch
    return result


def additive_decrypt(ciphertext, key):
    result = ""
    for ch in ciphertext:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            result += chr(((ord(ch) - base - key) % 26) + base)
        else:
            result += ch
    return result


# =======================================================
# Multiplicative Cipher
# =======================================================
def multiplicative_encrypt(plaintext, key):
    if gcd(key, 26) != 1:
        raise ValueError("Key must be coprime with 26.")
    result = ""
    for ch in plaintext:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            result += chr(((ord(ch) - base) * key % 26) + base)
        else:
            result += ch
    return result


def multiplicative_decrypt(ciphertext, key):
    key_inv = mod_inverse(key, 26)
    if key_inv is None:
        raise ValueError("Invalid key — must be coprime with 26.")
    result = ""
    for ch in ciphertext:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            result += chr(((ord(ch) - base) * key_inv % 26) + base)
        else:
            result += ch
    return result


# =======================================================
# Affine Cipher
# =======================================================
def affine_encrypt(plaintext, a, b):
    if gcd(a, 26) != 1:
        raise ValueError("Key 'a' must be coprime with 26.")
    result = ""
    for ch in plaintext:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            result += chr(((a * (ord(ch) - base) + b) % 26) + base)
        else:
            result += ch
    return result


def affine_decrypt(ciphertext, a, b):
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        raise ValueError("Key 'a' must be coprime with 26.")
    result = ""
    for ch in ciphertext:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            result += chr(((a_inv * ((ord(ch) - base - b)) % 26) + base))
        else:
            result += ch
    return result


# =======================================================
# Monoalphabetic Substitution Cipher
# - preserves case and non-letters
# - accepts key as 26-letter string OR as comma/space-separated mappings A=Q,B=W...
# =======================================================
def parse_substitution_key(user_input):
    """
    Accepts:
    - 26-letter mapping string (e.g. QWERTY...),
    - or mappings like 'A=Q,B=W,C=E,...' (commas or spaces)
    Returns dict mapping uppercase A-Z -> uppercase mapped letter.
    """
    user_input = user_input.strip().upper()
    if not user_input:
        # default mapping
        return dict(zip(string.ascii_uppercase, "QWERTYUIOPASDFGHJKLZXCVBNM"))

    # If it's 26 letters long, treat as direct mapping
    letters_only = "".join(ch for ch in user_input if ch.isalpha())
    if len(letters_only) == 26 and len(user_input) in (26, 26):  # user entered 26 letters
        mapping = {}
        for i, ch in enumerate(string.ascii_uppercase):
            mapping[ch] = letters_only[i]
        if len(set(mapping.values())) != 26:
            raise ValueError("Substitution mapping must map to 26 unique letters.")
        return mapping

    # Otherwise, attempt to parse pairs like A=Q,B=W or "A Q B W ..."
    pairs = []
    # split on commas first, then spaces
    for part in user_input.replace(",", " ").split():
        if "=" in part:
            left, right = part.split("=", 1)
            pairs.append((left.strip(), right.strip()))
        elif len(part) == 2 and part[0].isalpha() and part[1].isalpha():
            pairs.append((part[0], part[1]))
        else:
            # ignore unknown tokens
            pass

    mapping = {}
    for a, b in pairs:
        a = a.strip().upper()
        b = b.strip().upper()
        if len(a) != 1 or len(b) != 1 or not a.isalpha() or not b.isalpha():
            raise ValueError(f"Invalid pair '{a}={b}' in mapping.")
        mapping[a] = b

    # If mapping incomplete, raise error
    if len(mapping) != 26:
        # If user provided some pairs but not all, we can't proceed
        raise ValueError("Incomplete mapping. Provide a full 26-letter mapping.")
    if len(set(mapping.values())) != 26:
        raise ValueError("Mapped letters must be unique (no duplicates).")
    return mapping


def monoalphabetic_encrypt(plaintext, key_map):
    """
    key_map: dict 'A'->'Q' ...
    preserves case and non-letters
    """
    result = []
    for ch in plaintext:
        if ch.isalpha():
            is_upper = ch.isupper()
            mapped = key_map.get(ch.upper(), ch.upper())
            result.append(mapped if is_upper else mapped.lower())
        else:
            result.append(ch)
    return "".join(result)


def monoalphabetic_decrypt(ciphertext, key_map):
    inverse_map = {v: k for k, v in key_map.items()}
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            is_upper = ch.isupper()
            mapped = inverse_map.get(ch.upper(), ch.upper())
            result.append(mapped if is_upper else mapped.lower())
        else:
            result.append(ch)
    return "".join(result)


# =======================================================
# Autokey Cipher
# =======================================================
def autokey_encrypt(plaintext, keyword):
    # preserve non-letters and case: operate on letters-only but reconstruct
    letters = [c for c in plaintext if c.isalpha()]
    letters_upper = "".join(c.upper() for c in letters)
    key_extended = (keyword.upper() + letters_upper)[:len(letters_upper)]
    enc_letters = []
    for p, k in zip(letters_upper, key_extended):
        enc_letters.append(chr(((ord(p) + ord(k) - 2 * 65) % 26) + 65))
    # reconstruct
    res = []
    li = 0
    for ch in plaintext:
        if ch.isalpha():
            enc_ch = enc_letters[li]
            res.append(enc_ch if ch.isupper() else enc_ch.lower())
            li += 1
        else:
            res.append(ch)
    return "".join(res)


def autokey_decrypt(ciphertext, keyword):
    letters = [c for c in ciphertext if c.isalpha()]
    letters_upper = "".join(c.upper() for c in letters)
    key = keyword.upper()
    plaintext_letters = []
    for i, c in enumerate(letters_upper):
        k = key[i]
        p = chr(((ord(c) - ord(k) + 26) % 26) + 65)
        plaintext_letters.append(p)
        key += p
    # reconstruct
    res = []
    li = 0
    for ch in ciphertext:
        if ch.isalpha():
            p = plaintext_letters[li]
            res.append(p if ch.isupper() else p.lower())
            li += 1
        else:
            res.append(ch)
    return "".join(res)


# =======================================================
# Playfair Cipher
# =======================================================
def generate_playfair_matrix(key):
    seen = set()
    key_upper = "".join(ch for ch in key.upper().replace("J", "I") if ch.isalpha())
    matrix = ""
    for ch in key_upper:
        if ch not in seen:
            seen.add(ch)
            matrix += ch
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for ch in alphabet:
        if ch not in seen:
            matrix += ch
    return [list(matrix[i:i + 5]) for i in range(0, 25, 5)]


def find_position(matrix, ch):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == ch:
                return i, j
    return None


def playfair_prepare(text):
    txt = "".join(c for c in text.upper() if c.isalpha()).replace("J", "I")
    prepared = ""
    i = 0
    while i < len(txt):
        a = txt[i]
        b = txt[i + 1] if i + 1 < len(txt) else "X"
        if a == b:
            prepared += a + "X"
            i += 1
        else:
            prepared += a + b
            i += 2
    if len(prepared) % 2 != 0:
        prepared += "X"
    return prepared


def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_matrix(key)
    prepared = playfair_prepare(plaintext)
    result_letters = []
    for i in range(0, len(prepared), 2):
        a, b = prepared[i], prepared[i + 1]
        row_a, col_a = find_position(matrix, a)
        row_b, col_b = find_position(matrix, b)
        if row_a == row_b:
            result_letters.append(matrix[row_a][(col_a + 1) % 5])
            result_letters.append(matrix[row_b][(col_b + 1) % 5])
        elif col_a == col_b:
            result_letters.append(matrix[(row_a + 1) % 5][col_a])
            result_letters.append(matrix[(row_b + 1) % 5][col_b])
        else:
            result_letters.append(matrix[row_a][col_b])
            result_letters.append(matrix[row_b][col_a])
    return "".join(result_letters)


def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    text = "".join(c for c in ciphertext.upper() if c.isalpha())
    result_letters = []
    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        row_a, col_a = find_position(matrix, a)
        row_b, col_b = find_position(matrix, b)
        if row_a == row_b:
            result_letters.append(matrix[row_a][(col_a - 1) % 5])
            result_letters.append(matrix[row_b][(col_b - 1) % 5])
        elif col_a == col_b:
            result_letters.append(matrix[(row_a - 1) % 5][col_a])
            result_letters.append(matrix[(row_b - 1) % 5][col_b])
        else:
            result_letters.append(matrix[row_a][col_b])
            result_letters.append(matrix[row_b][col_a])
    return "".join(result_letters)


# =======================================================
# Vigenère Cipher
# =======================================================
def vigenere_encrypt(plaintext, keyword):
    keyword = keyword.upper()
    res = []
    ki = 0
    keylen = len(keyword)
    for ch in plaintext:
        if ch.isalpha():
            k = ord(keyword[ki % keylen]) - 65
            base = 65 if ch.isupper() else 97
            res.append(chr(((ord(ch) - base + k) % 26) + base))
            ki += 1
        else:
            res.append(ch)
    return "".join(res)


def vigenere_decrypt(ciphertext, keyword):
    keyword = keyword.upper()
    res = []
    ki = 0
    keylen = len(keyword)
    for ch in ciphertext:
        if ch.isalpha():
            k = ord(keyword[ki % keylen]) - 65
            base = 65 if ch.isupper() else 97
            res.append(chr(((ord(ch) - base - k) % 26) + base))
            ki += 1
        else:
            res.append(ch)
    return "".join(res)


# =======================================================
# Keyless Transposition Cipher
# =======================================================
def keyless_transposition_encrypt(plaintext):
    text = plaintext.replace(" ", "")
    result = ""
    for i in range(0, len(text) - 1, 2):
        result += text[i + 1] + text[i]
    if len(text) % 2 != 0:
        result += text[-1]
    return result


def keyless_transposition_decrypt(ciphertext):
    text = ciphertext.replace(" ", "")
    result = ""
    for i in range(0, len(text) - 1, 2):
        result += text[i + 1] + text[i]
    if len(text) % 2 != 0:
        result += text[-1]
    return result


# =======================================================
# Keyed Transposition Cipher
# =======================================================
def keyed_transposition_encrypt(plaintext, key, padchar="X"):
    num_cols = len(key)
    if num_cols == 0:
        raise ValueError("Key must be non-empty.")
    num_rows = -(-len(plaintext) // num_cols)
    padded_text = plaintext.ljust(num_rows * num_cols, padchar)
    grid = [list(padded_text[i:i + num_cols]) for i in range(0, len(padded_text), num_cols)]
    key_order = sorted(list(enumerate(key)), key=lambda x: (x[1], x[0]))
    ciphertext = ""
    for idx, _ in key_order:
        for r in range(num_rows):
            ciphertext += grid[r][idx]
    return ciphertext


def keyed_transposition_decrypt(ciphertext, key, padchar="X"):
    num_cols = len(key)
    if num_cols == 0:
        raise ValueError("Key must be non-empty.")
    num_rows = -(-len(ciphertext) // num_cols)
    grid = [[''] * num_cols for _ in range(num_rows)]
    key_order = sorted(list(enumerate(key)), key=lambda x: (x[1], x[0]))
    index = 0
    for idx, _ in key_order:
        for r in range(num_rows):
            if index < len(ciphertext):
                grid[r][idx] = ciphertext[index]
                index += 1
            else:
                grid[r][idx] = padchar
    plaintext_padded = "".join("".join(row) for row in grid)
    plaintext = plaintext_padded.rstrip(padchar)
    return plaintext


# =======================================================
# Combination + Double Transposition
# =======================================================
def combined_transposition_encrypt(plaintext, key):
    return keyed_transposition_encrypt(keyless_transposition_encrypt(plaintext), key)


def combined_transposition_decrypt(ciphertext, key):
    return keyless_transposition_decrypt(keyed_transposition_decrypt(ciphertext, key))


def double_transposition_encrypt(plaintext, key1, key2):
    return keyed_transposition_encrypt(keyed_transposition_encrypt(plaintext, key1), key2)


def double_transposition_decrypt(ciphertext, key1, key2):
    return keyed_transposition_decrypt(keyed_transposition_decrypt(ciphertext, key2), key1)


# =======================================================
# Validation Helpers
# =======================================================
def validate_text(text):
    if text is None or not text.strip():
        raise ValueError("Input text cannot be empty.")
    return text


def validate_keyword(key):
    if not key or not key.isalpha():
        raise ValueError("Keyword/key must contain only alphabetic characters.")
    return key


def validate_numeric_key_int_in_range(val_str, lo=0, hi=25):
    try:
        val = int(val_str)
    except Exception:
        raise ValueError("Numeric key must be an integer.")
    if not (lo <= val <= hi):
        raise ValueError(f"Numeric key must be between {lo} and {hi}.")
    return val


# =======================================================
# CLI Interface
# =======================================================
def main():
    print("\n===== Classical Cipher Toolkit =====")
    print("Select a Cipher:")
    print("1. Additive Cipher (key: 0–25)")
    print("2. Multiplicative Cipher (key: coprime with 26)")
    print("3. Affine Cipher (a,b) where a is coprime with 26")
    print("4. Monoalphabetic Substitution Cipher (provide mapping)")
    print("5. Autokey Cipher (keyword in alphabets)")
    print("6. Playfair Cipher (keyword in alphabets)")
    print("7. Vigenère Cipher (keyword in alphabets)")
    print("8. Keyless Transposition Cipher")
    print("9. Keyed Transposition Cipher (keyword in alphabets)")
    print("10. Combined Transposition Cipher (keyword in alphabets)")
    print("11. Double Transposition Cipher (two keywords in alphabets)")
    print("0. Exit")

    choice = input("Enter your choice (0-11): ").strip()

    if choice == "0":
        print("Exiting program.")
        sys.exit(0)

    plaintext = validate_text(input("Enter your text: "))
    mode = input("Encrypt or Decrypt? (E/D): ").strip().upper()

    try:
        if choice == "1":
            key = validate_numeric_key_int_in_range(input("Enter numeric key (0-25): "))
            result = additive_encrypt(plaintext, key) if mode == "E" else additive_decrypt(plaintext, key)

        elif choice == "2":
            key = int(input("Enter numeric key (coprime with 26, 0-25): "))
            result = multiplicative_encrypt(plaintext, key) if mode == "E" else multiplicative_decrypt(plaintext, key)

        elif choice == "3":
            a = int(input("Enter key 'a' (coprime with 26, 0-25): "))
            b = validate_numeric_key_int_in_range(input("Enter key 'b' (0-25): "))
            result = affine_encrypt(plaintext, a, b) if mode == "E" else affine_decrypt(plaintext, a, b)

        elif choice == "4":
            print("\nMonoalphabetic Cipher selected.")
            print("Provide mapping as either:")
            print(" - A 26-letter string (e.g. QWERTYUIOPASDFGHJKLZXCVBNM),")
            print(" - or pairs like A=Q,B=W,C=E,... (commas or spaces).")
            key_input = input("Enter mapping (leave blank for default): ").strip()
            key_map = parse_substitution_key(key_input)
            result = monoalphabetic_encrypt(plaintext, key_map) if mode == "E" else monoalphabetic_decrypt(plaintext, key_map)

        elif choice == "5":
            key = validate_keyword(input("Enter keyword (in alphabets): "))
            result = autokey_encrypt(plaintext, key) if mode == "E" else autokey_decrypt(plaintext, key)

        elif choice == "6":
            key = validate_keyword(input("Enter keyword (in alphabets): "))
            result = playfair_encrypt(plaintext, key) if mode == "E" else playfair_decrypt(plaintext, key)

        elif choice == "7":
            key = validate_keyword(input("Enter keyword (in alphabets): "))
            result = vigenere_encrypt(plaintext, key) if mode == "E" else vigenere_decrypt(plaintext, key)

        elif choice == "8":
            result = keyless_transposition_encrypt(plaintext) if mode == "E" else keyless_transposition_decrypt(plaintext)

        elif choice == "9":
            key = validate_keyword(input("Enter keyword (in alphabets): "))
            result = keyed_transposition_encrypt(plaintext, key) if mode == "E" else keyed_transposition_decrypt(plaintext, key)

        elif choice == "10":
            key = validate_keyword(input("Enter keyword (in alphabets): "))
            result = combined_transposition_encrypt(plaintext, key) if mode == "E" else combined_transposition_decrypt(plaintext, key)

        elif choice == "11":
            key1 = validate_keyword(input("Enter first key (in alphabets): "))
            key2 = validate_keyword(input("Enter second key (in alphabets): "))
            result = double_transposition_encrypt(plaintext, key1, key2) if mode == "E" else double_transposition_decrypt(plaintext, key1, key2)

        else:
            print("Invalid choice.")
            return

        print(f"\nResult:\n{result}")

    except Exception as e:
        print(f"Error: {e}")


# =======================================================
# Automated Cipher Test Suite
# =======================================================
def run_tests():
    print("\n=== Running Cipher Test Suite ===")
    try:
        # Additive
        text, key = "Hello, World!", 5
        assert additive_decrypt(additive_encrypt(text, key), key) == text

        # Multiplicative
        text, key = "World", 7
        assert multiplicative_decrypt(multiplicative_encrypt(text, key), key) == text

        # Affine
        text, a, b = "Python", 5, 8
        assert affine_decrypt(affine_encrypt(text, a, b), a, b) == text

        # Monoalphabetic
        text = "HelloWorld"
        key_map = dict(zip(string.ascii_uppercase, "QWERTYUIOPASDFGHJKLZXCVBNM"))
        assert monoalphabetic_decrypt(monoalphabetic_encrypt(text, key_map), key_map) == text

        # Autokey
        text, key = "Hello World", "KEY"
        assert autokey_decrypt(autokey_encrypt(text, key), key).upper() == text.upper()

        # Playfair
        text, key = "MONARCHY", "BALLOON"
        pf_enc = playfair_encrypt(text, key)
        pf_dec = playfair_decrypt(pf_enc, key)
        assert pf_dec.startswith("MONARCHY")

        # Vigenere
        text, key = "Attack at dawn!", "LEMON"
        assert vigenere_decrypt(vigenere_encrypt(text, key), key).upper() == text.upper()

        # Transpositions
        text, key = "HELLO WORLD", "KEY"
        assert keyless_transposition_decrypt(keyless_transposition_encrypt(text)) == text.replace(" ", "")
        kt_enc = keyed_transposition_encrypt(text, key)
        assert keyed_transposition_decrypt(kt_enc, key) == text.rstrip("X")
        assert combined_transposition_decrypt(combined_transposition_encrypt(text, key), key) == text.replace(" ", "")

        # Double transposition
        text, k1, k2 = "SECURE MESSAGE", "KEYONE", "KEYTWO"
        dt = double_transposition_encrypt(text, k1, k2)
        assert double_transposition_decrypt(dt, k1, k2) == text.rstrip("X")

        print("✅ All tests passed successfully!\n")
    except AssertionError:
        print("❌ One or more tests failed!")
    except Exception as e:
        print(f"⚠️ Test error: {e}")


# =======================================================
# Entry Point
# =======================================================
if __name__ == "__main__":
    run_tests()
    # loop CLI
    while True:
        main()
        again = input("\nDo you want to run again? (Y/N): ").strip().upper()
        if again != "Y":
            print("Program terminated.")
            break