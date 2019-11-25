import socket
from urllib.parse import urlparse
from packet import Packet


# global vars for receiving
rcv_window_start = 0
rcv_window_size = 8
rcv_window_end = rcv_window_start + rcv_window_size
delivered = [None] * rcv_window_size
expected_data_packets_num = 0
received_pkt_count = 0
received_all = False
establishedConnection = False
toBeClosed = False

# global vars for sending
expected_acks_list = []
un_acked_packets_list = []
send_window_size = 8
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

    port = 8080
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
def data_to_packets(data, ip, port):
    packet_list = []

    # split encoded data into chunks
    chunk_size = 100
    data_chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    # put each data chunk into packet, put each packet into packet_list
    for i in range(len(data_chunks)):
        payload = data_chunks[i]
        p = Packet(packet_type=3,
                   seq_num=i,
                   peer_ip_addr=ip,
                   peer_port=port,
                   payload=payload)
        packet_list.append(p)
    return packet_list


def send_syn_packet(router_addr, router_port, server_ip, server_port, data_packet_num):
    try:
        timeout = 2
        msg = str(data_packet_num)
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        syn_packet = Packet(packet_type=0,
                            seq_num=0,
                            peer_ip_addr=server_ip,
                            peer_port=server_port,
                            payload=msg.encode('utf-8'))
        conn.sendto(syn_packet.to_bytes(), (router_addr, router_port))
        print('Send SYN packet "{}" to router.'.format(syn_packet.seq_num))

        conn.settimeout(timeout)
        print('Waiting for SYN-ACK packet {}.'.format(syn_packet.seq_num))

        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)
        print('Get type {} packet {}.'.format(p.packet_type, p.seq_num))
        if p.packet_type == 1 and p.seq_num == 0:
            # SYN-ACK
            print('Client connection established.')
            # TODO: setup the client establishment flag
            global establishedConnection
            establishedConnection = True
        else:
            # resend the syn packet
            send_syn_packet(router_addr, router_port, server_ip, server_port, data_packet_num)

    except socket.timeout:
        print('SYN packet {} no response after {}s.'.format(syn_packet.seq_num, timeout))
        send_syn_packet(router_addr, router_port, server_ip, server_port, data_packet_num)
    finally:
        print('SYN Packet 0 Connection closed.\n')
        conn.close()


def send_ack_packet(router_addr, router_port, server_ip, server_port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ack_packet = Packet(packet_type=2,
                        seq_num=1,
                        peer_ip_addr=server_ip,
                        peer_port=server_port,
                        payload="".encode('utf-8'))
    conn.sendto(ack_packet.to_bytes(), (router_addr, router_port))
    print('Send ACK packet "{}" to router.'.format(ack_packet.seq_num))
    conn.close()


def three_way_handshake(router_addr, router_port, server_ip, server_port, data_packet_num):
    print('Initializing TCP connection...')
    send_syn_packet(router_addr, router_port, server_ip, server_port, data_packet_num)
    send_ack_packet(router_addr, router_port, server_ip, server_port)


def send_fin_packet(sender, fin_packet):
    try:
        timeout = 2
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fin_packet.packet_type = 5
        fin_packet.seq_num = 0
        conn.sendto(fin_packet.to_bytes(), sender)
        print('Send FIN packet {} to router.'.format(fin_packet.seq_num))

        conn.settimeout(timeout)
        print('Waiting for FIN-ACK packet {}.'.format(fin_packet.seq_num))

        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)
        print('Get type {} packet {}.'.format(p.packet_type, p.seq_num))
        if p.packet_type == 6 and p.seq_num == 0:
            # FIN-ACK
            print('Client in Fin waiting state...')
            # TODO: setup the client establishment flag
            global toBeClosed
            toBeClosed = True

    except socket.timeout:
        print('FIN packet {} no response after {}s.'.format(fin_packet.seq_num, timeout))
        send_fin_packet(sender, fin_packet)
    finally:
        print('FIN Packet 0 Connection closed.\n'.format(fin_packet.seq_num))
        conn.close()


def four_way_goodbye(sender, fin_packet):
    print('Client Disconnecting TCP connection...')
    send_fin_packet(sender, fin_packet)


def send_last_fin_ack(sender, fin_ack_packet):
    try:
        timeout = 2
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.sendto(fin_ack_packet.to_bytes(), sender)
        print('Client will close connection if no response from server in {} seconds'.format(timeout))
        conn.settimeout(timeout)

        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)
        print('Get type {} packet {}.'.format(p.packet_type, p.seq_num))
        if p.packet_type == 5:
            # FIN-ACK
            print('Server did not receive the last fin ack, resend...')
            send_last_fin_ack(conn, sender, fin_ack_packet)

    except socket.timeout:
        print('No response from server, Client ends TCP connection')
        global establishedConnection
        establishedConnection = False
        # TODO: reset all the global variables
    finally:
        conn.close()
