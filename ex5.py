import json
import os

# defines we will use:
MODULO = 26
SMALL_LETTERS = "abcdefghijklmnopqrstuvwxyz"
CAPITAL_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALL_LETTERS = SMALL_LETTERS + CAPITAL_LETTERS


# ------------------THIS IS A CAESAR CIPHER CLASS-----------------
class CaesarCipher:

    # C'tor for CaesarCipher class
    #
    # @param key - the key we will use for the encryption and decryption
    #
    # @result
    #     an instance of CaesarCipher
    #
    def __init__(self, key: int):
        self.key = key

    # Encrypt a string
    #
    # @param plaintext - the string we want to encrypt using the key
    #
    # @return
    #     encrypted string
    #
    def encrypt(self, plaintext: str) -> str:
        encrypted_message = ""
        for letter in plaintext:
            if letter.islower():
                encrypted_letter = SMALL_LETTERS[(SMALL_LETTERS.find(letter) + self.key) % MODULO]
            elif letter.isupper():
                encrypted_letter = CAPITAL_LETTERS[(CAPITAL_LETTERS.find(letter) + self.key) % MODULO]
            else:
                encrypted_letter = letter
            encrypted_message += encrypted_letter

        return encrypted_message

    # Decrypt a string
    #
    # @param ciphertext - the string we want to decrypt
    #
    # @return
    #     decrypted string
    #
    def decrypt(self, ciphertext: str) -> str:
        self.key = -self.key
        decrypted_str = self.encrypt(ciphertext)
        self.key = -self.key

        return decrypted_str


# ------------------THIS IS A VIGENERE CIPHER CLASS-----------------
class VigenereCipher:

    # C'tor for VigenereCipher class
    #
    # @param key_list - the list of keys we will use for the encryption and decryption
    #
    # @result
    #     an instance of VigenereCipher
    #
    def __init__(self, key_list: list):
        self.key_list = key_list.copy()

    # Encrypt a string
    #
    # @param plaintext - the string we want to encrypt using the list of keys
    #
    # @return
    #     encrypted string
    #
    def encrypt(self, plaintext: str) -> str:
        key_length = len(self.key_list)
        current_index_in_key = 0
        encrypted_message = []

        for letter in plaintext:
            if letter.isalpha():
                ceaser_cipher = CaesarCipher(self.key_list[current_index_in_key])
                encrypted_letter = ceaser_cipher.encrypt(letter)
                current_index_in_key += 1
                if current_index_in_key == key_length:
                    current_index_in_key = 0
            else:
                encrypted_letter = letter

            encrypted_message.append(encrypted_letter)

        return "".join(encrypted_message)

    # Decrypt a string
    #
    # @param ciphertext - the string we want to decrypt
    #
    # @return
    #     decrypted string
    #
    def decrypt(self, ciphertext: str) -> str:
        self.key_list = [-elem for elem in self.key_list]
        decrypted_str = self.encrypt(ciphertext)
        self.key_list = [-elem for elem in self.key_list]
        return decrypted_str


# Create a VigenereCipher with a string representing the key
#
# @param  KeyString - the string representing the key
#
# @return
#     An instance of VigenereCipher
#
def getVigenereFromStr(KeyString: str) -> VigenereCipher:
    key = []
    for letter in KeyString:
        if letter.isalpha():
            key.append(ALL_LETTERS.find(letter))
    return VigenereCipher(key)


# A system that encrypting/decrypting files in a given path based on the information in the json file in the path
#
# @param  dir_path - the path of the dir we want to handle
#
# @result
#     encrypted/decrypted files in txt/enc format based on a given operation, a cipher type and a key
#
#
def processDirectory(dir_path: str) -> None:
    json_path = os.path.join(dir_path, 'config.json')
    with open(json_path, 'r') as file:
        loaded_dict = json.load(file)
    cipher_type = loaded_dict["type"]
    mode = loaded_dict["mode"]
    key = loaded_dict["key"]

    if cipher_type == "Caesar":
        cipher = CaesarCipher(key)
    else:
        if type(key) is str:
            cipher = getVigenereFromStr(key)
        else:
            cipher = VigenereCipher(key)

    for file in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file)
        if os.path.isfile(file_path):
            if mode == "encrypt" and file_path.endswith(".txt"):
                processTheFile(file_path, ".txt", ".enc", cipher.encrypt)

            if mode == "decrypt" and file_path.endswith(".enc"):
                processTheFile(file_path, ".enc", ".txt", cipher.decrypt)


# Create encrypted\decrypted file based on given data
#
# @param  in_path - the path of the file we want to handle
#         in_extension - the file's original extension
#         out_extension- desired extension for the new file
#         action- a function pointer to encrypt or decrypt functions
#
# @result
#     A new file with new format and encrypted/decrypted message
#
def processTheFile(in_path: str, in_extension: str, out_extension: str, action) -> None:
    output_path = in_path.replace(in_extension, out_extension)
    with open(in_path, 'r') as input_to_change:
        input_list = input_to_change.readlines()
    with open(output_path, 'w') as out_file:
        for line in input_list:
            output = action(line)
            out_file.write(output)
