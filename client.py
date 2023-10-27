import socket
import hashlib
import DiffieHellman
from binascii import hexlify

HOST = 'localhost'
PORT = 5000


def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    # Receive the challenge from the server
    challenge = client_socket.recv(1024).decode()

    # Get the password from the user
    password = input('Enter your password: ')

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

    client = DiffieHellman.DiffieHellman()

    serverpublickey = client_socket.recv(1024)
    client_socket.send(client.publicKey.to_bytes(1024, byteorder='big'))

    # creating shared key
    client.genKey(int.from_bytes(serverpublickey, byteorder='big'))

    private_key = hexlify(client.getKey()).decode()
    # print(private_key)
    return

    while flag:
        # Now, you can send as many messages as you want to the server
        user_input = input(
            'Enter a message to send to the server (or `exit` to quit): ')

        if user_input == 'exit':
            client_socket.sendall(user_input.encode())
            client_socket.close()
            break

        client_socket.sendall(user_input.encode())


if __name__ == '__main__':
    main()
