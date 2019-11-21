import argparse
import socket
import threading

from packet import Packet
from commons_server import *

# global vars for receiving
rcv_window_start = 0
rcv_window_size = 8
rcv_window_end = rcv_window_start + rcv_window_size
delivered = [None] * rcv_window_size
SYN_received = False
expected_data_packets_num = 0
received_pkt_count = 0
received_all = False
establishConnection = False

# global vars for sending
expected_acks_list = []
un_acked_packets_list = []
send_window_size = 8
send_window_start = 0
window_sent = send_window_start - 1
send_window_end = send_window_start + send_window_size


def run_udp_server(port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        conn.bind(('', port))
        print('Echo server is listening at', port)
        while True:
            data, sender = conn.recvfrom(1024)
            handle_udp_client(conn, data, sender)
            # threading.Thread(target=handle_udp_client, args=(conn, data, sender)).start()
    finally:
        conn.close()


def handle_udp_client(conn, data, sender):
    try:
        p = Packet.from_bytes(data)

        global establishConnection, SYN_received, expected_data_packets_num, received_pkt_count, received_all
        if p.packet_type == 0 and p.seq_num == 0 and establishConnection is False:
            # rcv SYN
            SYN_received = True
            expected_data_packets_num = int(p.payload.decode('utf-8'))
            # send back SYN-ACK
            p.packet_type = 1
            conn.sendto(p.to_bytes(), sender)
        elif p.packet_type == 2 and p.seq_num == 1 and SYN_received is True and establishConnection is False:
            # rcv ACK
            print('Server side connection established.')
            establishConnection = True
        elif p.packet_type == 3 and establishConnection is True:
            # receiving data, # re-construct the packet
            global delivered, rcv_window_start, rcv_window_end
            if p.seq_num == rcv_window_start:
                print('Accept packet {}'.format(p.seq_num))
                if delivered[p.seq_num] is None:
                    received_pkt_count = received_pkt_count + 1
                delivered[p.seq_num] = p

                i = rcv_window_start
                while i < len(delivered) and delivered[i] is not None:
                    i = i + 1
                shift = i - rcv_window_start

                print('Shift the window by {}'.format(shift))
                rcv_window_start = rcv_window_start + shift
                rcv_window_end = rcv_window_end + shift

                print('Extend the delivered list by {}'.format(shift))
                extension = [None] * shift
                delivered.extend(extension)

            elif rcv_window_start < p.seq_num < rcv_window_end:
                print('Accept packet {}'.format(p.seq_num))
                if delivered[p.seq_num] is None:
                    received_pkt_count = received_pkt_count + 1
                delivered[p.seq_num] = p
            else:
                print('Discard packet {}'.format(p.seq_num))

            # send ACK
            p.packet_type = 2
            conn.sendto(p.to_bytes(), sender)

            if received_pkt_count == expected_data_packets_num and received_all is False:
                received_all = True
                # concatenate the data of all received packets
                i = 0
                decoded_request = ''
                while i < expected_data_packets_num:
                    decoded_request = decoded_request + delivered[i].payload.decode('utf-8')
                    i = i + 1

                # get response
                server_ip = socket.gethostbyname(socket.gethostname())
                encoded_response = get_response(decoded_request, server_ip)
                print(encoded_response)

                # send response back

            # process payload
            # replace the payload in the sent back packet with the new response
            # send the packets back

            # How to send a reply.
            # The peer address of the packet p is the address of the client already.
            # We will send the same payload of p. Thus we can re-use either `data` or `p`.

    except Exception as e:
        print("Error: ", e)


def send_to_client(router_addr, router_port, client_ip, client_port, packet_list):
    # send all response packets
    global window_sent
    packets_num = len(packet_list)
    while window_sent < len(packet_list) - 1:
        i = window_sent + 1
        while i < send_window_end:
            global expected_acks_list, un_acked_packets_list
            expected_acks_list.append(packet_list[i].seq_num)
            un_acked_packets_list.append(packet_list[i])
            threading.Thread(target=send_single_udp_packet, args=(router_addr, router_port, packet_list[i], packets_num)).start()
            i = i + 1
            window_sent = window_sent + 1


def send_single_udp_packet(router_addr, router_port, packet, packets_num):
    try:
        timeout = 2
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.sendto(packet.to_bytes(), (router_addr, router_port))
        print('Send packet "{}" to router.'.format(packet.seq_num))

        conn.settimeout(timeout)
        print('Waiting for packet {} ack.'.format(packet.seq_num))

        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)

        if p.seq_num == un_acked_packets_list[0].seq_num:
            expected_acks_list[0] = -1

            # count the num of acked packets
            acked_count = 0
            while acked_count < len(expected_acks_list) and expected_acks_list[acked_count] == -1:
                acked_count = acked_count + 1

            # update the expected_acks_list and unacked_packets_list
            counter = acked_count
            while counter > 0:
                expected_acks_list.pop(0)
                un_acked_packets_list.pop(0)
                counter = counter - 1
            print('Packet {} ~ {} correctly acked.'.format(p.seq_num, (p.seq_num + acked_count - 1) % send_window_size))

            # shift window
            global send_window_start, send_window_end
            send_window_start = send_window_start + acked_count
            send_window_end = min(send_window_end + acked_count, packets_num)
            print('Window shifts to [{}, {})'.format(send_window_start, send_window_end))

        elif p.seq_num != un_acked_packets_list[0].seq_num:
            # update the un_acked
            pos = expected_acks_list.index(p.seq_num)
            expected_acks_list[pos] = -1
            # print('Packet {} acked'.format(p.seq_num))

    except socket.timeout:
        print('Packet {} no response after {}s.'.format(packet.seq_num, timeout))
        send_single_udp_packet(router_addr, router_port, packet, packets_num)
    finally:
        print('Packet {} Connection closed.\n'.format(packet.seq_num))
        conn.close()


# def run_server(host, port):
#     listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#
#     try:
#         listener.bind((host, port))
#         listener.listen(5)
#         server_ip = socket.gethostbyname(socket.gethostname())
#         print('Lan\'s Server(' + server_ip + ') is listening httpc/httpfs request at port', port)
#
#         server_ip = socket.gethostbyname(socket.gethostname())
#
#         while True:
#             conn, addr = listener.accept()
#             threading.Thread(target=handle_client, args=(conn, addr, server_ip)).start()
#     finally:
#         listener.close()
#
#
# def handle_client(conn, addr, ip):
#     """handling httpfs request from port 8080"""
#     print('New httpfs client from', addr)
#     try:
#         client_request = conn.recv(4096)
#         if client_request:
#             # process the request according to client types
#             client_type = get_client_type(client_request)
#             if client_type == "httpfs":
#                 response = get_file_response(client_request, ip)
#             elif client_type == "httpc":
#                 response = get_response(client_request, ip)
#             # encode the response
#             response = response.encode("utf-8")
#     except:
#         response = get_error_respose()
#         response = response.encode("utf-8")
#     finally:
#         # send it
#         conn.sendall(response)
#         conn.close()


parser = argparse.ArgumentParser()
parser.add_argument("--port", help="echo server port", type=int, default=8007)
args = parser.parse_args()
run_udp_server(args.port)

# port = 8080
# run_server('', port)
