import socket

HOST = 'localhost'
PORT = 5000

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    while True:
        # Get input from the user
        user_input = input('Enter a message to send to the server (or `exit` to quit): ')

        # If the user types `exit`, quit both the programs
        if user_input == 'exit':
            client_socket.close()
            break

        # Send the input to the server
        client_socket.sendall(user_input.encode())

        # Receive the response from the server
        response = client_socket.recv(1024)

        # Display the response to the user
        print('Received response from the server:', response.decode())

    # Close the client socket
    client_socket.close()

if __name__ == '__main__':
    main()
