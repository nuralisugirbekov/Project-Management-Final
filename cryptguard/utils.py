import base64
import hashlib
from Crypto.Cipher import AES, DES, Blowfish
from Crypto.Util.Padding import unpad
BLOCK_SIZE = 32

def caesar_decrypt(cipher_text, shift):
    decrypted_text = ''
    for char in cipher_text:
        if char.isalpha():
            shift_amount = 65 if char.isupper() else 97
            # print(f"Decrypting char: {char}, Shift: {shift}, Shift Amount: {shift_amount}")
            decrypted_text += chr((ord(char) - shift_amount - shift + 26) % 26 + shift_amount)
        else:
            decrypted_text += char
    return decrypted_text


def atbash_decrypt(cipher_text):
    decrypted_text = ''
    for char in cipher_text:
        if char.isalpha():
            if char.isupper():
                decrypted_text += chr(90 - (ord(char) - 65))
            else:
                decrypted_text += chr(122 - (ord(char) - 97))
        else:
            decrypted_text += char
    return decrypted_text

def vigenere_decrypt(cipher_text, key):
    if not key:
        return None
    key = key.lower()
    decrypted_text = ''
    key_index = 0
    for char in cipher_text:
        if char.isalpha():
            shift_amount = 65 if char.isupper() else 97
            shift = ord(key[key_index % len(key)]) - 97
            decrypted_text += chr((ord(char) - shift_amount - shift + 26) % 26 + shift_amount)
            key_index += 1
        else:
            decrypted_text += char
    return decrypted_text

def base64_decrypt(cipher_text):
    try:
        return base64.b64decode(cipher_text).decode('utf-8')
    except Exception:
        return None


# def des_decrypt(cipher_text, key):
#     try:
#         cipher = DES.new(key, DES.MODE_ECB)
#         decrypted_text = unpad(cipher.decrypt(cipher_text), DES.block_size)
#         return decrypted_text.decode('utf-8')
#     except Exception:
#         return None
#
# def blowfish_decrypt(cipher_text, key):
#     try:
#         cipher = Blowfish.new(key, Blowfish.MODE_ECB)
#         decrypted_text = unpad(cipher.decrypt(cipher_text), Blowfish.block_size)
#         return decrypted_text.decode('utf-8')
#     except Exception:
#         return None

def xor_decrypt(cipher_text, key):
    if isinstance(cipher_text, bytes):
        cipher_text = cipher_text.decode('utf-8')
    if isinstance(key, bytes):
        key = key.decode('utf-8')
    if isinstance(key, int) or isinstance(cipher_text, int):
        return
    decrypted_text = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(cipher_text))
    return decrypted_text

def rail_fence_decrypt(cipher_text, key):
    if key <= 1:
        return cipher_text

    rail = [['\n' for _ in range(len(cipher_text))]
            for _ in range(key)]

    dir_down = None
    row, col = 0, 0

    for i in range(len(cipher_text)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False

        rail[row][col] = '*'
        col += 1

        if dir_down:
            row += 1
        else:
            row -= 1

    index = 0
    for i in range(key):
        for j in range(len(cipher_text)):
            if rail[i][j] == '*' and index < len(cipher_text):
                rail[i][j] = cipher_text[index]
                index += 1

    result = []
    row, col = 0, 0
    for i in range(len(cipher_text)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False

        if rail[row][col] != '*':
            result.append(rail[row][col])
            col += 1

        if dir_down:
            row += 1
        else:
            row -= 1
    return "".join(result)


def rot13_decrypt(cipher_text):
    decrypted_text = ''
    for char in cipher_text:
        if char.isalpha():
            shift = 13
            shift_amount = 65 if char.isupper() else 97
            decrypted_text += chr((ord(char) - shift_amount + shift) % 26 + shift_amount)
        else:
            decrypted_text += char
    return decrypted_text

def reverse_decrypt(cipher_text):
    return cipher_text[::-1]

def scytale_decrypt(cipher_text, num_cols):
    num_rows = len(cipher_text) // num_cols
    decrypted_text = [''] * num_rows
    for i in range(len(cipher_text)):
        row = i % num_rows
        decrypted_text[row] += cipher_text[i]
    return ' '.join(decrypted_text)

def beaufort_decrypt(cipher_text, key):
    decrypted_text = ''
    key = key.lower()
    key_index = 0

    for char in cipher_text:
        if char.isalpha():
            shift_amount = 65 if char.isupper() else 97
            shift = (ord(char.lower()) - ord(key[key_index % len(key)])) % 26
            decrypted_text += chr(shift_amount + shift)
            key_index += 1
        else:
            decrypted_text += char

    return decrypted_text