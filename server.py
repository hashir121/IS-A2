import socket
import hashlib
import secrets
import DiffieHellman
from binascii import hexlify

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
        return  # Exit the program

    serverobject = DiffieHellman.DiffieHellman()
    # sending public key of server
    client_socket.send(serverobject.publicKey.to_bytes(1024, byteorder='big'))

    # receiving public key of client
    clientpublickey = client_socket.recv(1024)

    # creating shared key
    serverobject.genKey(int.from_bytes(clientpublickey, byteorder='big'))

    private_key = hexlify(serverobject.getKey()).decode()
    # print(private_key)

    return

    while True:
        data = client_socket.recv(1024).decode()
        if data == 'exit':
            break  # Break out of the loop to close the connection

        print(f'Received message from client: {data}')

    # Close the client socket
    client_socket.close()

    # Close the server socket (this will only happen if the server is manually terminated)
    server_socket.close()


if __name__ == '__main__':
    main()
