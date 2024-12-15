from utils import (
    caesar_decrypt,
    vigenere_decrypt,
    base64_decrypt,
    atbash_decrypt,
    # des_decrypt,
    # blowfish_decrypt,
    xor_decrypt,
    rail_fence_decrypt,
    rot13_decrypt,
    scytale_decrypt,
    reverse_decrypt,
    beaufort_decrypt
)
from text_check import is_human_readable


def detect_encryption_method(text, key=None):
    if isinstance(text, bytes):
        text = text.decode('utf-8', errors='ignore')

    print(f"Original text: {text}")

    # Case when key is None
    if key is None:
        base64_result = base64_decrypt(text)
        if base64_result and is_human_readable(base64_result):
            print(f"Base64 decryption successful: {base64_result}")
            return "Base64", base64_result

        atbash_result = atbash_decrypt(text)
        print(f"Atbash decryption: {atbash_result}")
        if is_human_readable(atbash_result):
            return "Atbash", atbash_result

        rot13_result = rot13_decrypt(text)
        print(f"Rot13 decryption: {rot13_result}")
        if is_human_readable(rot13_result):
            return "Rot13", rot13_result

        reverse_result = reverse_decrypt(text)
        print(f"Reverse decryption: {reverse_result}")
        if is_human_readable(reverse_result):
            return "Reverse", reverse_result

    # Case when key is an integer
    elif isinstance(key, int):
        rail_fence_result = rail_fence_decrypt(text, key)
        print(f"Rail Fence decryption with key {key}: {rail_fence_result}")
        if is_human_readable(rail_fence_result):
            return "Rail_fence", rail_fence_result

        scytale_result = scytale_decrypt(text, key)
        print(f"Scytale decryption with key {key}: {scytale_result}")
        if is_human_readable(scytale_result):
            return "Scytale", scytale_result

        caesar_result = caesar_decrypt(text, key)
        print(f"Caesar decryption with key {key}: {caesar_result}")
        if is_human_readable(caesar_result):
            return "Caesar", caesar_result

    # Case when key is a string
    elif isinstance(key, str):
        vigenere_result = vigenere_decrypt(text, key)
        print(f"Vigenere decryption with key {key}: {vigenere_result}")
        if is_human_readable(vigenere_result):
            return "Vigenere", vigenere_result

        beaufort_result = beaufort_decrypt(text, key)
        print(f"Beaufort decryption with key {key}: {beaufort_result}")
        if is_human_readable(beaufort_result):
            return "Beaufort", beaufort_result

    # Case when key is provided (either string or integer) and is to be used for XOR decryption
    if key:
        key_bytes = key.encode() if isinstance(key, str) else key
        text_bytes = text.encode() if isinstance(text, str) else text

        xor_result = xor_decrypt(text_bytes, key_bytes)
        print(f"Xor decryption with key {key}: {xor_result}")
        if is_human_readable(xor_result):
            return "Xor", xor_result

    return "Unsupported encryption method or incorrect key.", None


class DecryptionModule:
    def __init__(self):
        self.status_code = None

    def decode(self, input_text, key=None):
        method, result = detect_encryption_method(input_text, key)
        if result is None:
            return result, method
        return result, method

