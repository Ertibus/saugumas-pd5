# ./server.py
#   Server file. Handles clients, processes requests
import os
import time
import socket
import threading
import io
import random

import tqdm
import numpy

from crypto import crypto

host = 'localhost'
server_port = 6060
buffer_size = 4096
max_retries = 5
separator = "<!NEXT!>"

recv_lock = threading.Lock() 
print_lock = threading.Lock() 

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_sockets = []

saved_message = "Message was not set"
saved_signature = numpy.array([])
saved_kpub = (1, 1)

def bind_socket(attempt = 0):
    global host
    global server_port
    global max_retries
    global server_socket

    try:
        server_socket.bind((host, server_port))
        server_socket.listen(5)
    except socket.error as err:
        if max_retries > attempt:
            print("Socket binding error: " + str(err) + ", retrying...")
            time.sleep(2)
            bind_socket(attempt+1)
        else:
            raise Exception("Socket binding error: " + str(err) + ", max tries reached. :(")
    else:
        th_listener = threading.Thread(target=accept_connections)
        th_listener.start()


def client_logic(connection_info):
    global buffer_size
    global separator
    global print_lock
    global saved_message
    global saved_signature
    global saved_kpub

    connection = connection_info['connection']
    address = connection_info['address']

    while True:
        mesg = connection.recv(buffer_size).decode('utf-8')
        if not mesg:
            break
        elif mesg == 'retrv':
            if not saved_message:
                print("Server doesn't have a message")
                connection.send("fail".encode('utf-8'))
                continue
            connection.send("retrv".encode('utf-8'))
            with io.BytesIO() as s_message:
                with io.BytesIO() as s_signature:
                    print("Packaging message for sending...")
                    s_message.write(saved_message.encode('utf-8'))
                    print("Packaging signature for sending...")
                    s_signature.write(saved_signature.tobytes())

                    print("Sending header...")
                    connection.send(f"\
                    {s_message.getbuffer().nbytes}\
                    {separator}\
                    {s_signature.getbuffer().nbytes}\
                    {separator}\
                    {saved_kpub[0]}\
                    {separator}\
                    {saved_kpub[1]}".encode('utf-8')
                    )

                    response = connection.recv(buffer_size).decode('utf-8')
                    if response != 'down':
                        raise Exception("Wrong response to message send")

                    print("Sending data...")
                    connection.sendall(s_message.getvalue())
                    response = connection.recv(buffer_size).decode('utf-8')
                    if response != 'down':
                        raise Exception("Wrong response to message send")

                    connection.sendall(s_signature.getvalue())
                    response = connection.recv(buffer_size).decode('utf-8')
                    if response != 'down':
                        raise Exception("Wrong response to signature send")

        elif mesg == 'store':
            connection.send("store".encode('utf-8'))
            # HEADER
            header = connection.recv(buffer_size).decode('utf-8')
            header = header.split(separator)

            message_size = int(header[0])
            signature_size = int(header[1])
            kpub = (int(header[2]), int(header[3]))
            connection.send("down".encode('utf-8'))
            # FILES
            message = recieve_file(connection, message_size, "new message").decode('utf-8')
            connection.send("down".encode('utf-8'))

            signature = numpy.frombuffer(recieve_file(connection, signature_size, "new signature"), dtype=numpy.int64)
            connection.send("down".encode('utf-8'))

            print_lock.acquire()

            saved_kpub = kpub
            saved_message = message
            saved_signature = signature

            print(f"\n[#] Public key: {kpub}\n")

            print(f"\n================================[ MESSAGE START\n\
                \n{message}\
                \n================================[ MESSAGE END\n")

            print(f"\n================================[ SIGNATURE START\n\
                \n{signature}\
                \n================================[ SIGNATURE END\n")

            print_lock.release()
        else:
            print(f"Unknown Message: {mesg}")

def recieve_file(connection, filesize:int, desc:str='new data'):
    global buffer_size
    global recv_lock

    recv_lock.acquire() 

    downloaded = 0
    with io.BytesIO() as msg_stream:
        print_lock.acquire()
        with tqdm.tqdm(range(filesize), f'Receiving {desc}', unit="B", unit_scale=True, unit_divisor=1024) as progress:
            while downloaded < filesize:
                r_buffer = connection.recv(buffer_size)
                msg_stream.write(r_buffer)
                progress.update(len(r_buffer))
                downloaded += len(r_buffer)

        recv_lock.release() 
        print_lock.release()
        return msg_stream.getvalue()


def accept_connections():
    global buffer_size
    global server_socket
    global client_sockets

    while True:
        connection, address = server_socket.accept()

        new_connection = dict()
        new_connection['connection'] = connection
        new_connection['address'] = address

        th_client = threading.Thread(target=client_logic, args=(new_connection, ))

        print("Connection established with: [ {}:{} ]\n".format(address[0], address[1]))

        connection.send("hello_client".encode('utf-8'))
        data = connection.recv(buffer_size)

        if data.decode('utf-8') == 'hello_server':
            print("Succesful handshake with: [ {}:{} ]\n".format(address[0], address[1]))
            client_sockets.append(connection)
            th_client.start()

if __name__ == '__main__':
    try:
        bind_socket()
    except Exception as err:
        print(err)

    while True:
        ipt = input("server <>> ")
        if ipt == 'quit':
            print("[~] Goodbye!")
            for connection in client_sockets:
                connection.close()
            server_socket.close()
            if recv_lock.locked():
                recv_lock = threading.Lock() 
            if print_lock.locked():
                print_lock = threading.Lock() 
            os._exit(0)
            break
        elif ipt == 'restart':
            try:
                if recv_lock.locked():
                    recv_lock = threading.Lock() 
                if print_lock.locked():
                    print_lock = threading.Lock() 
                bind_socket()

            except Exception as err:
                print(err)
        elif ipt == 'show':
            print_lock.acquire()

            print(f"\n[#] Public key: {saved_kpub}\n")

            print(f"\n================================[ MESSAGE START\n\
                \n{saved_message}\
                \n================================[ MESSAGE END\n")

            print(f"\n================================[ SIGNATURE START\n\
                \n{saved_signature}\
                \n================================[ SIGNATURE END\n")

            print_lock.release()
        elif ipt.split(' ')[0] == 'echo':
            print(ipt.split(' ',1)[1:])

        elif ipt.split(' ')[0] == 'allrng':
            saved_signature = numpy.random.randint(65525, size=len(saved_signature))

        elif ipt.split(' ')[0] == 'rng':
            arr = numpy.copy(saved_signature)
            for y in range(int(ipt.split(' ')[1])):
                arr[random.randint(0, len(saved_signature))] = random.randint(0, 65525)
            saved_signature = arr
