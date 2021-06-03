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

    elif args[0] == "--send" or args[0] == "-s":
        message_str=""
        for arg in args[1:]:
            message_str+=arg+' '
        messanger(message_str)

    elif args[0] == "--validate" or args[0] == "-v":
        listener()

    elif args[0] == "--clear" or args[0] == "-c":
        print("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")

    elif args[0] == 'quit':
        print("[~] Goodbye!")
        client_socket.close()
        os._exit(0)

    elif args[0] == "--help" or args[0] == "-h" or args[0] == 'help':
        print("\n\
        --help\t\t-h\t \t=> show this\n\
        --read\t\t-r\t path\t=> read and send file from _path_\n\
        --send\t\t-s\t msg\t=> send message\n\
        --validate\t-v\t\t=> requests/validates RSA signature from server \n\
        quit\t\t \t=> quits client\n\
        ")
    else:
        print(f"[X] Command: {args[0]} not recognised")

def listener():
    global client_socket
    global separator
    global buffer_size

    print("[*] Confirming connection with server...")
    client_socket.send("retrv".encode('utf-8'))
    response = client_socket.recv(buffer_size).decode('utf-8')
    if response != 'retrv':
        raise Exception("Wrong response to header send")
    # HEADER
    header = client_socket.recv(buffer_size).decode('utf-8')
    header = header.split(separator)

    message_size = int(header[0])
    signature_size = int(header[1])
    kpub = (int(header[2]), int(header[3]))
    client_socket.send("down".encode('utf-8'))
    # FILES
    message = recieve_file(client_socket, message_size, "message").decode('utf-8')
    client_socket.send("down".encode('utf-8'))

    signature = numpy.frombuffer(recieve_file(client_socket, signature_size, "signature"), dtype=numpy.int64)
    client_socket.send("down".encode('utf-8'))

    print(f"\n[#] Public key: {kpub}\n")

    print(f"\n================================[ MESSAGE START\n\
        \n{message}\
        \n================================[ MESSAGE END\n")

    print(f"\n================================[ SIGNATURE START\n\
        \n{signature}\
        \n================================[ SIGNATURE END\n")

    print("[*] Doing validation...")
    validation_msg = crypto.decrypt(signature, kpub)
    if(validation_msg == message):
        print("[O] Signature is valid!")
    else:
        print("[X] Signature is invalid!")
        diff = numpy.array([], dtype=numpy.int64)
        for i in range(len(message)):
            if message[i] != validation_msg[i]:
                diff = numpy.append(diff, signature[i] * -1)
            else:
                diff = numpy.append(diff, signature[i])
        print(f"\n================================[ SIGNATURE DIFFERENCE START\n\
            \n{diff}\
            \n================================[ SIGNATURE DIFFERENCE END\n")


def recieve_file(connection, filesize:int, desc:str='new data'):
    global buffer_size
    global recv_lock


    downloaded = 0
    with io.BytesIO() as msg_stream:
        with tqdm.tqdm(range(filesize), f'Receiving {desc}', unit="B", unit_scale=True, unit_divisor=1024) as progress:
            while downloaded < filesize:
                r_buffer = connection.recv(buffer_size)
                msg_stream.write(r_buffer)
                progress.update(len(r_buffer))
                downloaded += len(r_buffer)

        return msg_stream.getvalue()


# Send message : message, Kpub, s
def messanger(message:str):
    global client_socket
    global separator

    print(f"\n================================[ MESSAGE START\n\
        \n{message}\
        \n================================[ MESSAGE END\n")

    Kpub, Kpvt = crypto.calculate_keys(crypto.FIRST_PRIME_LIST[random.randint(0, 99)].item(), crypto.FIRST_PRIME_LIST[random.randint(0, 99)].item())

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

