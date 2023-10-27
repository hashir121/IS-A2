import socket
import hashlib
import secrets
import DiffieHellman
from binascii import hexlify
import RSA
import AES
import re
import pickle

HOST = 'localhost'
PORT = 5000
PASSWORD = 'mypassword123'  # Change this to your desired password


def generate_challenge():
    return secrets.token_hex(16)


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))

    # Listen for incoming connections
    server_socket.listen(1)

    # Accept an incoming connection
    client_socket, client_address = server_socket.accept()

    # Generate and send a challenge to the client
    challenge = generate_challenge()
    client_socket.send(challenge.encode())

    # Receive the hashed password from the client
    hashed_password = client_socket.recv(1024).decode()

    # Concatenate the challenge and the server's password, then hash it using SHA256
    concatenated = challenge + PASSWORD
    hashed_server_password = hashlib.sha256(concatenated.encode()).hexdigest()

    # Compare the hash strings for authentication
    if hashed_password == hashed_server_password:
        client_socket.send("Authentication done".encode())
    else:
        client_socket.send("False".encode())
        client_socket.close()  # Close the client connection
        server_socket.close()  # Close the server socket
        return  # quit the program

    serverobject = DiffieHellman.DiffieHellman()
    # sending public key of server
    client_socket.send(serverobject.publicKey.to_bytes(1024, byteorder='big'))

    # receiving public key of client
    clientpublickey = client_socket.recv(1024)

    # creating shared key
    serverobject.genKey(int.from_bytes(clientpublickey, byteorder='big'))

    private_key = hexlify(serverobject.getKey()).decode()
    # print(private_key)

    # crearting AES cypher using private_key
    aes_cipher = AES.AESCipher(private_key)

    # private and public key for RSA
    p = 17
    q = 29

    # recieving public and private key of client and decrypt it usin aes

    # recieving public key of client
    public = client_socket.recv(1024)

    public = pickle.loads(public)
    # print("Public Key: ", public)

    while True:
        data = client_socket.recv(1024).decode()
        if data == 'quit':
            break  # Break out of the loop to close the connection

        # print(f'Encrypted Message recieved from the client: {data}')

        AES_decripted = aes_cipher.decrypt(data)

        # print(f'Decrypted Message: {AES_decripted}')

        start_index = AES_decripted.find("[")
        end_index = AES_decripted.find("]")

        # Extract text inside the square brackets
        inside_brackets = AES_decripted[start_index + 1:end_index]

        # Extract text after the closing bracket
        PlainText = AES_decripted[end_index + 1:]

        inside_brackets = inside_brackets.split(', ')
        RSA_Hash = [int(item) for item in inside_brackets]

        # print("RSA Hash: ", RSA_Hash)
        # print('RSA Hash type: ', type(RSA_Hash))
        # print("PlainText: ", PlainText)
        # print('PlainText type: ', type(PlainText))
        # print('plain text length: ', len(PlainText))

        Hash = RSA.decrypt(public, RSA_Hash)

        # hashing the Plaintext
        hashed_PlainText = hashlib.sha256(PlainText.encode()).hexdigest()

        # print('Hashed Message: ' + Hash)
        # print('Hashed Plaintext: ' + hashed_PlainText)

        # printing plain text
        print("Plain Text: ", PlainText)

        if Hash == hashed_PlainText:
            print("Message is not tampered")
        else:
            print("Message is tampered")
    # Close the client socket
    client_socket.close()

    # Close the server socket
    server_socket.close()


if __name__ == '__main__':
    main()
