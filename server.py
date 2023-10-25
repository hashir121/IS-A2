import socket

HOST = 'localhost'
PORT = 5000

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))

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

        # Display the data to the user
        print(f'Received message from client: {data.decode()}')

        # Send the data back to the client
        client_socket.sendall(data)

    # Close the client socket
    client_socket.close()

if __name__ == '__main__':
    main()
