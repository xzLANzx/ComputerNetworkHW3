import logging
import socket
import sys
import threading
from urllib.parse import urlparse
from packet import Packet

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

# global vars for receiving
rcv_window_start = 0
rcv_window_size = 8
rcv_window_end = rcv_window_start + rcv_window_size
delivered = [None] * rcv_window_size
expected_data_packets_num = 0
received_pkt_count = 0
received_all = False
established_connection = False
to_be_closed = False
to_be_closed_confirmed = False

# global vars for sending
expected_acks_list = []
un_acked_packets_list = []
send_window_size = 8
send_window_start = 0
window_sent = send_window_start - 1
send_window_end = send_window_start + send_window_size


def reset_all_global():
    global rcv_window_start, rcv_window_end, delivered, expected_data_packets_num,\
    received_pkt_count, received_all, established_connection, to_be_closed,\
    to_be_closed_confirmed,expected_acks_list,un_acked_packets_list, send_window_start,\
    window_sent, send_window_end

    # global vars for receiving
    rcv_window_start = 0
    rcv_window_end = rcv_window_start + rcv_window_size
    delivered = [None] * rcv_window_size
    expected_data_packets_num = 0
    received_pkt_count = 0
    received_all = False
    established_connection = False
    to_be_closed = False
    to_be_closed_confirmed = False

    # global vars for sending
    expected_acks_list = []
    un_acked_packets_list = []
    send_window_start = 0
    window_sent = send_window_start - 1
    send_window_end = send_window_start + send_window_size


def get_client_type(command_line):
    command_components = command_line.split()
    return command_components[0]


def parse_httpfs_command(command_line):
    command_components = command_line.split()

    request_type = command_components[1]
    verbosity = False
    if "-v" in command_components:
        verbosity = True

    header = ""
    if "-h" in command_components:
        index = command_components.index("-h")
        header = command_components[index + 1]

    port = 8007
    if "-p" in command_components:
        index = command_components.index("-p")
        port = int(command_components[index + 1])

    path = ""
    if "-d" in command_components:
        index = command_components.index("-d")
        path = command_components[index + 1]
    return request_type, verbosity, header, port, path


def parse_httpc_command(command_line):
    """extract request_type, verbosity, header, data, output_file_name, url"""
    command_components = command_line.split()

    # get request type
    request_type = command_components[1]
    # get options'''
    verbosity = False
    if "-v" in command_components:
        verbosity = True
    # get header
    header = ""
    if "-h" in command_components:
        # concatenate all headers
        indices = [i for i, component in enumerate(command_components) if component == "-h"]
        i = 0
        for index in indices:
            if i == len(indices) - 1:
                header = header + command_components[index + 1]
            else:
                header = header + command_components[index + 1] + "\r\n"
            i = i + 1
    # get data
    data = ""
    if "-d" in command_components:
        # get all inline data
        data_start_index = command_line.find("'{")
        data_end_index = command_line.find("}'") + 2
        data = command_line[data_start_index: data_end_index]
    elif "-f" in command_components:
        # get the input file name
        index = command_components.index("-f")
        input_file_name = command_components[index + 1]
        # get the data in file
        with open(input_file_name, 'r') as data_file:
            data = data_file.read()
    # get output file name
    output_file_name = ""
    if "-o" in command_components:
        # get the output file's name
        index = command_components.index("-o")
        output_file_name = command_components[index + 1]
    # get url
    url = ""
    for component in command_components[1:]:
        if component.startswith("http") or component.startswith("\'http") or component.startswith('\"http'):
            url = component
            break
    url = eval(url)  # strip the double quote or apostrophe

    return request_type, verbosity, header, data, output_file_name, url


def parse_url(url):
    """extract host, port, path, and query from url"""
    url_components = urlparse(url)
    host = url_components.hostname
    port = 80
    if url_components.port:
        port = url_components.port
    path = url_components.path
    query = url_components.query
    return host, port, path, query


def construct_file_request(request_type, header, directory_path):
    if header:
        request = request_type.upper() + " " + directory_path + " HTTPFS/1.0\r\n" + header + "\r\n"
    else:
        request = request_type.upper() + " " + directory_path + " HTTPFS/1.0\r\n"

    request = request.encode("utf-8")
    return request


def construct_request(request_type, header, data, host, path, query):
    if request_type.lower() == "get":
        if header:
            request = request_type.upper() + " " + path + "?" + query + " HTTP/1.0\r\n" + \
                      "Host: " + host + "\r\n" \
                      + header + "\r\n\r\n"
        else:
            request = request_type.upper() + " " + path + "?" + query + " HTTP/1.0\r\n" + \
                      "Host: " + host + "\r\n\r\n" \

    elif request_type.lower() == "post":
        if header:
            request = request_type.upper() + " " + path + " HTTP/1.0\r\n" \
                      + "Host: " + host + "\r\n" \
                      + header + "\r\n" \
                      + "Content-Length: " + str(len(data)) + "\r\n\r\n" \
                      + data + "\r\n"
        else:
            request = request_type.upper() + " " + path + " HTTP/1.0\r\n" \
                      + "Host: " + host + "\r\n"\
                      + "Content-Length: " + str(len(data)) + "\r\n\r\n" \
                      + data + "\r\n"

    request = request.encode("utf-8")
    return request


def get_status_code(response):
    """extract status code"""
    response_lines_list = response.splitlines()
    first_line = response_lines_list[0]
    first_line_components = first_line.split()
    status_code = first_line_components[1]
    return status_code


def get_redirect_path(response):
    """extract redirect path"""
    lines = response.splitlines()
    path = ""
    for line in lines:
        word_list = line.split()
        if word_list[0].lower() == "location:":
            path = word_list[1]
            break
    return path


def print_to_console(response, verbosity):
    """print response to console, and return the printed response"""
    if verbosity:
        # print all
        print(response)
        return response
    else:
        response_components = response.split("\r\n\r\n")
        print(response_components[1])
        return response_components[1]


def print_to_file(file_name, content):
    """output response to file"""
    if file_name != "":
        # Append-adds at last
        file = open(file_name, "a")  # append mode
        file.write(content)
        file.close()


def print_help(help_type):
    if help_type.lower() == "get":
        print("Usage: httpc get [-v] [-h key:value] URL\r\n"
              "Get executes a HTTP GET request for a given URL.\r\n"
              "\t-v\tPrints the detail of the response such as protocol, status, and headers.\r\n"
              "\t-h\tkey:value\tAssociates headers to HTTP Request with the format\'key:value\'.")
    elif help_type.lower() == "post":
        print("Usage: httpc post [-v] [-h key:value] [-d inline-data] [-f file] URL\r\n"
              "Post executes a HTTP POST request for a given URL with inline data or from file.\r\n"
              "\t-v\tPrints the detail of the response such as protocol, status, and headers.\r\n"
              "\t-h\tkey:value\tAssociates headers to HTTP Request with the format\'key:value\'\r\n"
              "\t-d\tstring\tAssociates an inline data to the body HTTP POST request.\r\n"
              "\t-f\tfile\tAssociates the content of a file to the body HTTP POST request.\r\n"
              "Either [-d] or [-f] can be used but not both.")
    else:
        print("httpc is a curl-like application but supports HTTP protocol only. \r\n"
              "Usage:\r\n "
              "\thttpc command [arguments]\r\n"
              "The commands are:\r\n"
              "\tget executes a HTTP GET request and prints the response.\r\n"
              "\tpost executes a HTTP POST request and prints the response.\r\n"
              "\thelp prints this screen.\r\n"
              "Use \"httpc help [command]\" for more information about a command.")


# packet_type = 0, SYN
# packet_type = 1, SYN-ACK
# packet_type = 2, ACK
# packet_type = 3, DATA
# packet_type = 4, DATA_END
# packet_type = 5, FIN
# packet_type = 6, FIN-ACK

# convert encoded data to packets
def data_to_packets(data, server_ip, server_port):
    packet_list = []

    # split encoded data into chunks
    chunk_size = 100
    data_chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    # put each data chunk into packet, put each packet into packet_list
    for i in range(len(data_chunks)):
        payload = data_chunks[i]
        p = Packet(packet_type=3,
                   seq_num=i,
                   peer_ip_addr=server_ip,
                   peer_port=server_port,
                   payload=payload)
        packet_list.append(p)
    return packet_list


def send_to_server(router_addr, router_port, server_ip, server_port, packet_list):
    # three-way handshake
    data_packet_num = len(packet_list)
    logging.debug('Initializing TCP connection...')
    send_syn_packet(router_addr, router_port, server_ip, server_port, data_packet_num)
    send_ack_packet(router_addr, router_port, server_ip, server_port)
    # three_way_handshake(router_addr, router_port, server_ip, server_port, data_packet_num)

    # send ack together with the first data packet
    send_ack_packet(router_addr, router_port, server_ip, server_port)
    # send all un-send packets in window
    global window_sent
    packets_num = len(packet_list)
    while window_sent < len(packet_list) - 1:
        i = window_sent + 1
        while i < min(send_window_end, packets_num):
            global expected_acks_list, un_acked_packets_list
            expected_acks_list.append(packet_list[i].seq_num)
            un_acked_packets_list.append(packet_list[i])
            threading.Thread(target=send_data_packet_to_server, args=(router_addr, router_port, packet_list[i], packets_num)).start()
            i = i + 1
            window_sent = window_sent + 1

    # receiving response from server
    decoded_response = receive_from_server()
    # say goodbye
    logging.debug('Disconnecting TCP connection...')
    send_fin_packet(router_addr, router_port, server_ip, server_port)
    # wait for the last disconnect FIN request from server
    wait_for_server_disconnect()
    return decoded_response


def send_syn_packet(router_addr, router_port, server_ip, server_port, data_packet_num):
    try:
        timeout = 0.1
        msg = str(data_packet_num)
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        syn_packet = Packet(packet_type=0,
                            seq_num=0,
                            peer_ip_addr=server_ip,
                            peer_port=server_port,
                            payload=msg.encode('utf-8'))
        conn.sendto(syn_packet.to_bytes(), (router_addr, router_port))
        logging.debug('Send SYN packet "{}" to router.'.format(syn_packet.seq_num))

        conn.settimeout(timeout)
        logging.debug('Waiting for SYN-ACK packet {}.'.format(syn_packet.seq_num))

        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)
        logging.debug('Received type {} packet {}.'.format(p.packet_type, p.seq_num))
        if p.packet_type == 1 and p.seq_num == 0:
            # SYN-ACK
            logging.debug('Client connection established.')
            global established_connection
            established_connection = True

    except socket.timeout:
        logging.debug('SYN packet {} no response after {}s.'.format(syn_packet.seq_num, timeout))
        send_syn_packet(router_addr, router_port, server_ip, server_port, data_packet_num)
    finally:
        logging.debug('SYN Packet 0 Connection closed.\n')
        conn.close()


def send_ack_packet(router_addr, router_port, server_ip, server_port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ack_packet = Packet(packet_type=2,
                        seq_num=1,
                        peer_ip_addr=server_ip,
                        peer_port=server_port,
                        payload="".encode('utf-8'))
    conn.sendto(ack_packet.to_bytes(), (router_addr, router_port))
    logging.debug('Send ACK packet "{}" to router.'.format(ack_packet.seq_num))
    conn.close()


def three_way_handshake(router_addr, router_port, server_ip, server_port, data_packet_num):
    logging.debug('Initializing TCP connection...')
    send_syn_packet(router_addr, router_port, server_ip, server_port, data_packet_num)
    send_ack_packet(router_addr, router_port, server_ip, server_port)


def send_data_packet_to_server(router_addr, router_port, packet, packets_num):
    try:
        timeout = 0.1
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.sendto(packet.to_bytes(), (router_addr, router_port))
        logging.debug('Send data packet "{}" to router.'.format(packet.seq_num))

        conn.settimeout(timeout)
        logging.debug('Waiting for data packet {} ack.'.format(packet.seq_num))

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
            logging.debug('Packet {} ~ {} correctly acked.'.format(p.seq_num, (p.seq_num + acked_count - 1) % send_window_size))

            # shift window
            global send_window_start, send_window_end
            send_window_start = send_window_start + acked_count
            send_window_end = min(send_window_end + acked_count, packets_num)

            logging.debug('Sending window shifts to [{}, {})'.format(send_window_start, send_window_end))

        elif p.seq_num != un_acked_packets_list[0].seq_num:
            # update the un_acked
            pos = expected_acks_list.index(p.seq_num)
            expected_acks_list[pos] = -1

    except socket.timeout:
        logging.debug('Packet {} no response after {}s.'.format(packet.seq_num, timeout))
        if established_connection:
            send_data_packet_to_server(router_addr, router_port, packet, packets_num)
    finally:
        logging.debug('Packet {} Connection closed.\n'.format(packet.seq_num))
        conn.close()


def send_fin_packet(router_addr, router_port, server_ip, server_port):
    try:
        timeout = 0.1
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fin_packet = Packet(packet_type=5,
                            seq_num=0,
                            peer_ip_addr=server_ip,
                            peer_port=server_port,
                            payload=''.encode('utf-8'))
        conn.sendto(fin_packet.to_bytes(), (router_addr, router_port))
        logging.debug('Send FIN packet {} to router.'.format(fin_packet.seq_num))

        conn.settimeout(timeout)
        logging.debug('Waiting for FIN-ACK packet {}.'.format(fin_packet.seq_num))

        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)
        logging.debug('Received type {} packet {}.'.format(p.packet_type, p.seq_num))
        if (p.packet_type == 6 or p.packet_type == 5) and p.seq_num == 0:
            global to_be_closed
            to_be_closed = True
            # FIN-ACK
            logging.debug('Client in Fin waiting state...')

    except socket.timeout:
        logging.debug('FIN packet {} no response after {}s.'.format(fin_packet.seq_num, timeout))
        if to_be_closed is False:
            send_fin_packet(router_addr, router_port, server_ip, server_port)
    finally:
        logging.debug('FIN Packet 0 Connection closed.\n')
        conn.close()


# handling the udp packets from server
def receive_udp_packet_from_server(conn, data, sender):
    try:
        decoded_response = ''
        p = Packet.from_bytes(data)

        global delivered, expected_data_packets_num, received_pkt_count, received_all
        if p.packet_type == 3:
            if p.seq_num == 0:
                expected_data_packets_num = int(p.payload.decode('utf-8'))

            # receiving data, # re-construct the packet
            global rcv_window_start, rcv_window_end
            if p.seq_num - 1 == rcv_window_start:
                logging.debug('Accept packet {}'.format(p.seq_num))
                if delivered[p.seq_num - 1] is None:
                    received_pkt_count = received_pkt_count + 1
                delivered[p.seq_num - 1] = p

                i = rcv_window_start
                while i < len(delivered) and delivered[i] is not None:
                    i = i + 1
                shift = i - rcv_window_start

                logging.debug('Shift the window by {}'.format(shift))
                rcv_window_start = rcv_window_start + shift
                rcv_window_end = rcv_window_end + shift

                logging.debug('Extend the delivered list by {}'.format(shift))
                extension = [None] * shift
                delivered.extend(extension)

            elif rcv_window_start < p.seq_num - 1 < rcv_window_end:
                logging.debug('Accept packet {}'.format(p.seq_num))
                if delivered[p.seq_num - 1] is None:
                    received_pkt_count = received_pkt_count + 1
                delivered[p.seq_num - 1] = p
            else:
                logging.debug('Discard packet {}'.format(p.seq_num))

            # send ACK
            p.packet_type = 2
            conn.sendto(p.to_bytes(), sender)

            if received_pkt_count == expected_data_packets_num and received_all is False:
                received_all = True
                # concatenate the data of all received packets
                i = 0
                while i < expected_data_packets_num:
                    decoded_response = decoded_response + delivered[i].payload.decode('utf-8')
                    i = i + 1
    except Exception as e:
        logging.debug("Error: ", e)
    finally:
        return decoded_response


def receive_from_server():
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    conn.bind(('', 41830))
    decoded_response = ''
    try:
        while received_all is False:
            data, sender = conn.recvfrom(1024)
            decoded_response = receive_udp_packet_from_server(conn, data, sender)
    finally:
        logging.debug('Client received all response packets.')
        conn.close()
        return decoded_response


def wait_for_server_disconnect():
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    conn.bind(('', 41830))
    global to_be_closed_confirmed
    timeout = 0.1
    try:
        while to_be_closed is True:
            data, sender = conn.recvfrom(1024)
            wait_for_fin(conn, data, sender)
            if to_be_closed_confirmed is True:
                to_be_closed_confirmed = False
                conn.settimeout(timeout)
    except socket.timeout:
        logging.debug('Nothing received from server in {} seconds'.format(timeout))
    finally:
        reset_all_global()
        logging.debug('Client TCP connection closed.')
        conn.close()


def wait_for_fin(conn, data, sender):
    try:
        p = Packet.from_bytes(data)
        if p.packet_type == 5:
            p.packet_type = 6
            conn.sendto(p.to_bytes(), sender)
            global to_be_closed_confirmed
            to_be_closed_confirmed = True
            logging.debug('Client to be closed confirmed.')
    except Exception as e:
        logging.debug("Error: ", e)


def four_way_goodbye(router_addr, router_port, server_ip, server_port):
    logging.debug('Disconnecting TCP connection...')
    send_fin_packet(router_addr, router_port, server_ip, server_port)
