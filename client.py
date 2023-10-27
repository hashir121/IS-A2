import socket
import hashlib
import DiffieHellman
from binascii import hexlify
import RSA
import AES
import pickle
import tkinter as tk

HOST = 'localhost'
PORT = 5000


def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    # Receive the challenge from the server
    challenge = client_socket.recv(1024).decode()

    def check_password():
        password.set(password_entry.get())
        root.destroy()

    root = tk.Tk()
    root.title("Password Verification")

    password_label = tk.Label(root, text="Enter Password:")
    password_label.pack()

    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    password = tk.StringVar()  # Use a tkinter StringVar to store the password

    check_button = tk.Button(
        root, text="Check Password", command=check_password)
    check_button.pack()

    root.mainloop()

    password = password.get()
    print("Entered Password:", password)
    # Concatenate the challenge and the entered password, then hash it using SHA256
    concatenated = challenge + password
    hashed_password = hashlib.sha256(concatenated.encode()).hexdigest()

    # Send the hashed password back to the server
    client_socket.sendall(hashed_password.encode())

    # Receive the authentication result from the server
    auth_result = client_socket.recv(1024).decode()
    # print("Conneci")

    flag = 1
    if auth_result == 'False':
        flag = 0
        print('Authentication failed. Closing connection...')
        return

    print('Authentication Successfull!!!!')
    client = DiffieHellman.DiffieHellman()

    serverpublickey = client_socket.recv(1024)
    client_socket.send(client.publicKey.to_bytes(1024, byteorder='big'))

    # creating shared key
    client.genKey(int.from_bytes(serverpublickey, byteorder='big'))

    private_key = hexlify(client.getKey()).decode()
    # print(private_key)

    # crearting AES cypher using private_key
    aes_cipher = AES.AESCipher(private_key)

    # private and public key for RSA
    p = 17
    q = 29
    # public = (383, 493)
    # private = (255, 493)

    # generating public and private keys
    public, private = RSA.generate_key_pair(p, q)

    # print("Public Key: ", public)
    # print("Private Key: ", private)

    # sending public key to server
    Sendingkey = pickle.dumps(public)
    client_socket.send(Sendingkey)

    while flag:
        # Now, you can send as many messages as you want to the server------------------------------

        def send_text():
            user_input = text_entry.get()
            if user_input == 'quit':
                client_socket.sendall(user_input.encode())
                client_socket.close()
                root2.destroy()
                return

            # hashing
            hashed_input = hashlib.sha256(user_input.encode()).hexdigest()

            # print("Hashed Input: ", hashed_input)
            # encrypting the hash with private key
            RSA_Hash = RSA.encrypt(private, hashed_input)

            # print("RSA Hash: ", RSA_Hash)
            # print("RSA hash type: ", type(RSA_Hash))
            # decripting RSA hash
            # hashed = RSA.decrypt(public, RSA_Hash)
            # print("RSA Hash: ", hashed)

            # Calculate the length of RSA_HASH and convert it to a 10-character string
            rsa_length_str = str(len(RSA_Hash)).zfill(10)

            # Concatenating the length of RSA_HASH, RSA_HASH, and user_input
            concatenated = f'{rsa_length_str}{RSA_Hash}{user_input}'

            # print("Concatenated: ", concatenated)

            # encrypting the concatenated message with AES
            encrypted_message = aes_cipher.encrypt(concatenated)

            client_socket.sendall(encrypted_message.encode('utf-8'))

# --------------------------------------------------------------------
        root2 = tk.Tk()
        root2.title("Text Input")

        text_label = tk.Label(root2, text="Enter Text:")
        text_label.pack()

        text_entry = tk.Entry(root2)
        text_entry.pack()

        send_button = tk.Button(root2, text="Send", command=send_text)
        send_button.pack()

        root2.mainloop()

        root2.destroy()


if __name__ == '__main__':
    main()
