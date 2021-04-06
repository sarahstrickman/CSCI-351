"""
Project 2 for CSCI-351. This contains functionality for the RIP 2 implementation.

Due date:   Oct 23. 2020

filename:   router_process.py
author:     Sarah Strickman     sxs4599@rit.edu
"""

import socket
import sys
import traceback
import time
from datetime import datetime
import threading
from proj2_utilities import *
import json

mutex = threading.Lock()

comm_threads = []
update_threads = []
prev_message = ""

recent_communications = dict()  # key = IP addr |   value = time of most recent signal
routing_table = dict()      # key = ip addr |   value = [subnet mask, cost, next_hop]
routing_table_json = ""     # routing table as a string representation (used for string comparison)
subnet = "255.255.255.0"    # default subnet
cost = 10                   # default cost


def send_update(serversocket, host, port, message=routing_table_json):
    """
    send your routing table information to your neighbors
    :param serversocket: socket you're using
    :param host: your addr
    :param port: your port
    :param message: message you're receiving
    :return: nothing
    """
    if len(message) == 0:
        message = "Hello from message sender at " + host + "!"

    for neighbor in get_neighbors(host):
        n_pair = (neighbor, port)
        # print("sending message {", message, "} to: \t", n_pair)
        # print("\tMessage = " + message)
        serversocket.sendto(str.encode(message), n_pair)
    print("sending....")
    print_routing_table(host, routing_table)

def send_periodic_updates(serversocket, host, port, message=routing_table_json):
    """
    every 5 seconds, send your routing table information to your neighbors
    :param serversocket: socket you're using
    :param host: your addr
    :param port: your port
    :param message: message you're receiving
    :return: nothing
    """
    while (len(update_threads) == 1) and (update_threads[0] == threading.current_thread()):
        try:
            send_update(serversocket=serversocket, host=host, port=port, message=message)
            time.sleep(10)

        except Exception as e:
            print("Exception in send_periodic_updates\n", traceback.print_exc())
            return


def handle_message(serversocket, host, port, message=routing_table_json):
    """
    update your routing_table information with what you get from your neighbor.
    Then send this update out to your neighbors

    :param serversocket: socket you're using
    :param host: your addr
    :param port: your port
    :param message: message you're receiving
    :return: nothing
    """
    try:
        msg_dict = json.loads(message)  # convert json to a dictionary

        with mutex:
            # update your routing table
            global routing_table
            global routing_table_json

            routing_table = dict()  #msg_dict
            routing_table_json = message

        # notify all neighbors
        send_update(serversocket, host, port, message)

    except Exception as e:
        print("Error occurred in handle_message\n", traceback.print_exc())

    finally:
        pass  # if you are using a mutex, release it here


def check_recent_communications(serversocket, host, port):
    """
    if you haven't heard anything from someone for 60 seconds, remove them from your routing table.

    check everyone you have communicated with. For each neighbor, if that neighbor hasn't sent you anything within the
    last 60 seconds:
        - remove them from recent_communications table
        - remove them from routing table
        - update routing table json to match routing table
        - send out an updated routing table to all neighbors
    :param UDPserversocket: socket
    :param host: your host ip addr
    :param port: port
    :return: nothing
    """
    with mutex:
        global recent_communications
        global routing_table_json
        global routing_table
        for addr in recent_communications:
            elapsed = datetime.now() - recent_communications[addr]
            if elapsed.total_seconds() >= 60:
                recent_communications.pop(addr)
                routing_table.pop(addr)
                routing_table_json = json.dumps(routing_table)
                send_update(serversocket, host, port, routing_table_json)


def periodically_check_recent_communications(serversocket, host, port):
    """
    periodically check the communications table to see if anything needs to get removed.

    :param serversocket: socket for communication
    :param host:    your host ip addr
    :param port:    port
    :return:        nothing
    """
    while (len(comm_threads) == 1) and (comm_threads[0] == threading.current_thread()):
        check_recent_communications(serversocket, host, port)
        time.sleep(5)


def update_recent_communications(addr):
    """
    update the addr with the most recent time it was communicated to you
    :param addr: addr of sender
    :return: nothing
    """
    with mutex:
        global recent_communications
        recent_communications[addr] = datetime.now()


def start_server(host="", port=8000):
    try:  # make socket and bind to user inputs (should be self)
        UDPserversocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print("Socket created")
        UDPserversocket.bind((host, port))
    except Exception as e:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()

    print("UDP Server Socket now listening")

    with mutex:
        global routing_table
        global routing_table_json
        for n in get_neighbors(host):
            routing_table[n] = [subnet, get_costs(n), n]
        routing_table_json = json.dumps(routing_table)

    send_update(UDPserversocket, host, port, routing_table_json)

    global update_threads
    t_update = threading.Thread(target=send_periodic_updates, args=(UDPserversocket, host, port, ""))
    update_threads.append(t_update)
    t_update.start()

    global comm_threads
    t_comm = threading.Thread(target=send_periodic_updates, args=(UDPserversocket, host, port))
    comm_threads.append(t_comm)
    t_comm.start()


    # infinite loop- do not reset for every requests
    while True:
        try:
            pkt = UDPserversocket.recvfrom(MAX_BUFFER_SIZE)
            # print("packet received: \t", pkt)

            message = pkt[0]
            address = pkt[1]

            clientMsg = "Message from Client:{}".format(message.decode('utf-8'))
            clientIP = "\tClient IP Address:{}\n".format(address)

            # print(message, "\n", address[0], "\n\n")

            update_recent_communications(address[0])

            with mutex:
                if address[0] not in routing_table:
                    routing_table[address[0]] = get_costs(host)
                    routing_table_json = json.dumps(routing_table)
                print_routing_table(host, routing_table)

            # if clientMsg != routing_table_json:  # only update your routing table if needed
            #     print(clientMsg)
            #     print(clientIP)
            #
            #     handle_message(UDPserversocket, host, port, clientMsg)


        except Exception as e:
            print("Failure in message send/receive. Error : \n", traceback.print_exc())
            break

    UDPserversocket.close()


def main():
    if "-b" in sys.argv:
        # start server
        start_server()
    elif len(sys.argv) == 3:
        try:
            start_server(sys.argv[1], int(sys.argv[2]))
        except Exception as e:
            print("Usage: python3 router_process.py ip_addr port_no")
            print("To run with default IP address and port, run with '-b'.")
    else:
        print("Usage: python3 router_process.py ip_addr port_no")
        print("To run with default IP address and port, run with '-b'.")


if __name__ == "__main__":
    main()
