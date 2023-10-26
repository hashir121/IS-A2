import socket
import AES

HOST = 'localhost'
PORT = 5000

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    # Create a new AESCipher object with a secret key of your choice.
    aes_cipher = AES.AESCipher('my_secret_key')

    while True:
        # Get input from the user
        user_input = input('Enter a message to send to the server (or `exit` to quit): ')

        # If the user types `exit`, quit both the programs
        if user_input == 'exit':
            client_socket.close()
            break


        # Encrypt the user input
        encrypted_user_input = aes_cipher.encrypt(user_input)


        # Send the input to the server
        client_socket.sendall(encrypted_user_input.encode('utf-8'))

        # Receive the response from the server
        response = client_socket.recv(1024)

        # Decrypt the response from the server
        decrypted_response = aes_cipher.decrypt(response.decode())

        print(f'Encrypted message from server: {response}')
        # Display the decrypted response to the user
        print('Received response from the server:', decrypted_response)

    # Close the client socket
    client_socket.close()

if __name__ == '__main__':
    main()