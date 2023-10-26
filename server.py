import socket
import AES

HOST = 'localhost'
PORT = 5000

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))


    aes_cipher = AES.AESCipher('my_secret_key')

    # Listen for incoming connections
    server_socket.listen(1)

    # Accept an incoming connection
    client_socket, client_address = server_socket.accept()

    while True:
        # Receive data from the client
        data = client_socket.recv(1024)

        # If the client has closed the connection, break out of the loop
        if not data:
            break

        # Decrypt the received data
        decrypted_data = aes_cipher.decrypt(data.decode())
        
        print(f'Encrypted Data from client: {data}')
        
        # Display the decrypted data to the user
        print(f'Received message from client: {decrypted_data}')

        # Encrypt the data to send back to the client
        SendClient = 'Confirmation message being sent to client'
        encrypted_data = aes_cipher.encrypt(SendClient)

        # Send the data back to the client
        client_socket.sendall(encrypted_data.encode())

    # Close the client socket
    client_socket.close()

if __name__ == '__main__':
    main()