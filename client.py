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

    challenge = client_socket.recv(1024).decode()

    def check_password():
        password.set(password_entry.get())
        root.destroy()

    root = tk.Tk()
    root.title("Password Verification")
    # Increase the window size (width x height)
    root.geometry("400x200")

    password_label = tk.Label(root, text="Enter Password:")
    password_label.pack()

    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    password = tk.StringVar()

    check_button = tk.Button(
        root, text="Check Password", command=check_password)
    check_button.pack()

    root.mainloop()

    password = password.get()

    concatenated = challenge + password
    hashed_password = hashlib.sha256(concatenated.encode()).hexdigest()

    client_socket.sendall(hashed_password.encode())

    auth_result = client_socket.recv(1024).decode()

    flag = 1
    if auth_result == 'False':
        flag = 0
        print('Authentication failed. Closing connection...')
        return

    print('Authentication Successful!')
    client = DiffieHellman.DiffieHellman()

    serverpublickey = client_socket.recv(1024)
    client_socket.send(client.publicKey.to_bytes(1024, byteorder='big'))

    client.genKey(int.from_bytes(serverpublickey, byteorder='big'))

    private_key = hexlify(client.getKey()).decode()
    aes_cipher = AES.AESCipher(private_key)

    p = 17
    q = 29

    public, private = RSA.generate_key_pair(p, q)

    Sendingkey = pickle.dumps(public)
    client_socket.send(Sendingkey)

    while flag:
        def send_text():
            user_input = text_entry.get()
            if user_input == 'quit':
                client_socket.sendall(user_input.encode())
                client_socket.close()
                root2.destroy()
                return

            hashed_input = hashlib.sha256(user_input.encode()).hexdigest()

            RSA_Hash = RSA.encrypt(private, hashed_input)
            rsa_length_str = str(len(RSA_Hash)).zfill(10)
            concatenated = f'{rsa_length_str}{RSA_Hash}{user_input}'

            encrypted_message = aes_cipher.encrypt(concatenated)

            client_socket.sendall(encrypted_message.encode('utf-8'))

        root2 = tk.Tk()
        root2.title("Text Input")
        # Increase the window size (width x height)
        root2.geometry("400x200")

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
