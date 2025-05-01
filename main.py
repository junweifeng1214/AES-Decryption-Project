from Crypto.Cipher import AES#importing the AES module from the Crypto library
from Crypto.Util.Padding import unpad#importing the unpad function from the Crypto library
def read_binary_file(filename):#function to read the binary file
    """Reads and returns the content of a binary file."""#function to read the binary file
    with open(filename, "rb") as f:#opens the file in binary mode
        return f.read()#returns the content of the file
def decrypt_aes_cbc(ciphertext, key, iv):#function to decrypt the AES CBC mode
    """Decrypts ciphertext using AES-256 in CBC mode."""#function to decrypt the AES CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)#creates a new AES cipher object with the given key and IV
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)#decrypts the ciphertext using the cipher object and unpads the result
    return plaintext#returns the decrypted plaintext
def main():
    ciphertext = read_binary_file("ciphertext.bin")#reads the binary file "ciphertext.bin"
    key = read_binary_file("key.bin")#reads the binary file "key.bin"
    iv = read_binary_file("iv.bin")#reads the binary file "iv.bin"
    plaintext = decrypt_aes_cbc(ciphertext, key, iv)#decrypts the ciphertext using the decrypt_aes_cbc function
    with open("paragraph.txt", "w", encoding="utf-8") as f:#opens the file "paragraph.txt" in write mode and sets the encoding to utf-8
        f.write(plaintext.decode("utf-8"))#writes the decrypted plaintext to the file "paragraph.txt"
if __name__ == "__main__":#checks if the script is being run as the main program
    main()#calls the main function