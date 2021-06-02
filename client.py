# ./inputer.py
#   Sends commands to server

import os
import io
import sys
import time
import random
import socket

import tqdm
import numpy


from crypto import crypto

host = 'localhost'
server_port = 6060
buffer_size = 2048
client_socket = socket.socket()
separator = "<!NEXT!>"

def start_program():
    global client_socket

    establish_connection()

    if sys.argv[1:]:
        internal_logic(sys.argv[1:])
    else:
        while True:
            command = input('[I] > ')
            command = command.split(' ')
            internal_logic(command)

    client_socket.close()


def establish_connection():
    global host
    global server_port
    global client_socket

    while True:
        client_socket.connect((host, server_port))
        print(f"[W] Waiting for handshake from server [{host}:{server_port}]")
        data = client_socket.recv(buffer_size)
        msg = data.decode('utf-8')

        if msg == "hello_client":
            client_socket.send("hello_server".encode('utf-8'))
            print("[+] Handshake succesful")
            break
        else:
            print("[!] Handshake failed, restarting the connection")
            time.sleep(2)


def internal_logic(args:list):
    if args[0] == "--read" or args[0] == "-r":
        if os.path.isfile(args[1]):
            print("[+] File exists. Reading files contents....")
            msg = str
            with open(args[1], 'r') as file:
                msg = file.read()
            messanger(msg)
        else:
            print(f"[X] File {args[1]} not found")

    if args[0] == "--send" or args[0] == "-s":
        messanger(str(args[1:]))

    if args[0] == "--recv" or args[0] == "-d":
        listener()

    else:
        print(f"[X] Command: {args[0]} not recognised")

def listener():
    print("Confirming connection with server...")
    client_socket.send("retrv".encode('utf-8'))
    response = client_socket.recv(buffer_size).decode('utf-8')
    if response != 'retrv':
        raise Exception("Wrong response to header send")
# Send message : message, Kpub, s
def messanger(message:str):
    global client_socket
    global separator

    print(f"\n================================[ MESSAGE START\n\
        \n{message}\
        \n================================[ MESSAGE END\n")

    Kpub, Kpvt = crypto.calculate_keys(crypto.FIRST_PRIME_LIST[random.randint(0, 99)].item(), crypto.FIRST_PRIME_LIST[random.randint(0, 99)].item())

    #E
    signature = crypto.encrypt(message, Kpvt)

    print(f"\n================================[ SIGNATURE START\n\
        \n{signature}\
        \n================================[ SIGNATURE END\n")

    print("Confirming connection with server...")
    client_socket.send("store".encode('utf-8'))
    response = client_socket.recv(buffer_size).decode('utf-8')
    if response != 'store':
        raise Exception("Wrong response to header send")

    with io.BytesIO() as s_message:
        with io.BytesIO() as s_signature:
            print("Packaging message for sending...")
            s_message.write(message.encode('utf-8'))
            print("Packaging signature for sending...")
            s_signature.write(signature.tobytes())

            print("Sending header...")
            client_socket.send(f"\
            {s_message.getbuffer().nbytes}\
            {separator}\
            {s_signature.getbuffer().nbytes}\
            {separator}\
            {Kpub[0]}\
            {separator}\
            {Kpub[1]}".encode('utf-8')
            )

            response = client_socket.recv(buffer_size).decode('utf-8')
            if response != 'down':
                raise Exception("Wrong response to message send")

            print("Sending data...")
            client_socket.sendall(s_message.getvalue())
            response = client_socket.recv(buffer_size).decode('utf-8')
            if response != 'down':
                raise Exception("Wrong response to message send")

            client_socket.sendall(s_signature.getvalue())
            response = client_socket.recv(buffer_size).decode('utf-8')
            if response != 'down':
                raise Exception("Wrong response to signature send")
            #rcv = numpy.frombuffer(bytes_stream.getvalue(), dtype=numpy.int64)


        
if __name__ == '__main__':
    start_program()

