import logging
import socket
from urllib import parse
from time import gmtime, strftime
from xml.dom import minidom

from lxml import etree, html
from json2html import *
from dicttoxml import dicttoxml
import json
import os

from packet import Packet

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
toBeClosed = False

# global vars for sending
expected_acks_list = []
un_acked_packets_list = []
send_window_size = 8
send_window_start = 0
window_sent = send_window_start - 1
send_window_end = send_window_start + send_window_size


def get_client_type(client_request):
    client_request = client_request.decode("utf-8")
    components = client_request.split()
    if components[2] == "HTTP/1.0":
        return "httpc"
    elif components[2] == "HTTPFS/1.0":
        return "httpfs"


def decompose_file_request(client_request):
    client_request = client_request.decode("utf-8")
    request_components = client_request.split("\r\n")
    line0 = request_components[0]
    line0_components = line0.split()
    request_type = line0_components[0]
    path = line0_components[1]
    if len(request_components) >= 2:
        header = request_components[1]
    else:
        header = ""

    return request_type, path, header


def decompose_request(client_request):
    client_request = client_request.decode("utf-8")
    client_request_components = client_request.split("\r\n\r\n")
    request_and_headers = client_request_components[0]
    data_body = ""
    if len(client_request_components) > 1:
        data_body = client_request_components[1]

    lines = request_and_headers.split("\r\n")
    hostname = lines[1].split(": ")[1]
    header_list = lines[1:]
    request_components = lines[0].split()
    request_type = request_components[0]
    path_query = request_components[1]
    protocol = request_components[2]

    return request_type, path_query, protocol, hostname, header_list, data_body


def get_args(path_query):
    args = {}

    # no args
    if "?" not in path_query:
        return args

    path_query_components = path_query.split("?")
    query = path_query_components[1]
    query_dict = parse.parse_qs(query)

    for key, value in query_dict.items():
        value_str = "".join(value)
        args[key] = value_str
    return args


def get_headers(header_list):
    headers = {}
    for line in header_list:
        line_components = line.split(":")
        headers[line_components[0]] = line_components[1]
    return headers


def get_origin(ip):
    ip += ", " + ip
    return ip


def get_url(hostname, query_path):
    url = "http://" + hostname + query_path
    return url


def print_to_file(file_name, content):
    """output response to file"""
    if file_name != "":
        # Append-adds at last
        file = open(file_name, "a")  # append mode
        file.write(content)
        file.close()


def get_error_respose():
    response_info = "HTTPFS/1.0" + " 500 Internal Server Error\r\n" \
                    + "Date: " + strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime()) + "\r\n" \
                    + "Server: Lan's Mac\r\n\r\n"
    response = response_info
    return response


def get_httpfs_response(client_request, ip):
    request_type, path, header = decompose_file_request(client_request)

    response = {}
    origin = get_origin(ip)
    url = get_url("localhost", path)
    response["origin"] = origin
    response["url"] = url
    if header:
        response["headers"] = header

    # print(os.path.dirname(path))
    if os.path.dirname(path) == "/no_permission":
        response_info = "HTTPFS/1.0" + " 403 No Permission\r\n" \
                        + "Date: " + strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime()) + "\r\n" \
                        + "Server: Lan's Mac\r\n\r\n"
        response_body = json.dumps(response, indent=2) + "\r\n"
        response = response_info + response_body
        return response

    if request_type.lower() == "get":
        if path[-1] == "/":
            # get files list
            cwd = os.getcwd()
            files_list = os.listdir(cwd + path)
            response["files_list"] = files_list
        else:
            # get the data in file
            file_content = ""
            if os.path.exists(path[1:]):
                with open(path[1:], 'r') as data_file:
                    file_content = data_file.read()
                response["file_content"] = file_content
            else:
                response_info = "HTTPFS/1.0" + " 404 Not Found\r\n" \
                                + "Date: " + strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime()) + "\r\n" \
                                + "Server: Lan's Mac\r\n\r\n"
                response_body = json.dumps(response, indent=2) + "\r\n"
                response = response_info + response_body
                return response

    elif request_type.lower() == "post":
        # get the file
        path_components = path.split("/")
        file_name = path_components[-1]
        # print to file
        client_request = client_request.decode("utf-8")
        print_to_file(file_name, client_request)
        response["file_content"] = client_request

    response_format = "json"
    if header:
        key_value = header.split(":")
        key = key_value[0]

        if key.lower() == "content-type":
            response_format = key_value[1].lower()

        if response_format == "json":
            response_body = json.dumps(response, indent=2) + "\r\n"
        elif response_format == "xml":
            # xml = dicttoxml(response)
            # response_body = xml.decode() + "\r\n"
            xml = dicttoxml(response, custom_root='test', attr_type=False)
            xml_string = xml.decode()
            xmlstr = minidom.parseString(xml_string).toprettyxml(indent="   ")
            response_body = xmlstr + "\r\n"
        elif response_format == "plain-text":
            response_body = json.dumps(response, indent=2) + "\r\n"
        elif response_format == "html":
            response_json = json.dumps(response, ensure_ascii=False)
            response_body = json2html.convert(json=response_json)
            document_root = html.fromstring(response_body)
            response_body = etree.tostring(document_root, encoding='unicode', pretty_print=True)
            response_body = response_body + "\r\n"
    else:
        response_body = json.dumps(response, indent=2) + "\r\n"
    response_body_len = len(response_body)

    response_info = "HTTPFS/1.0" + " 200 OK\r\n" \
                                   "" \
                    + "Content-Type: application/" + response_format + "\r\n" \
                    + "Date: " + strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime()) + "\r\n" \
                    + "Server: Lan's Mac\r\n" \
                    + "Content-Length: " + str(response_body_len) + "\r\n\r\n"

    response = response_info + response_body
    return response


def get_httpc_response(client_request, ip):
    request_type, path_query, protocol, hostname, header_list, data_body = decompose_request(client_request)

    response = {}
    args = get_args(path_query)
    headers = get_headers(header_list)
    origin = get_origin(ip)
    url = get_url(hostname, path_query)

    if request_type.lower() == "get":
        response["args"] = args
        response["headers"] = headers
        response["origin"] = origin
        response["url"] = url

    elif request_type.lower() == "post":
        response["args"] = args
        response["data"] = data_body
        response["files"] = {}
        response["form"] = {}
        response["headers"] = headers
        response["json"] = None
        response["origin"] = origin
        response["url"] = url

    response_body = json.dumps(response, indent=2) + "\r\n"
    response_body_len = len(response_body)

    response_info = protocol + " 200 OK\r\n" \
                    + "Content-Type: application/json\r\n" \
                    + "Date: " + strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime()) + "\r\n" \
                    + "Server: Lan's Mac\r\n" \
                    + "Content-Length: " + str(response_body_len) + "\r\n\r\n"

    response = response_info + response_body
    return response


def get_response(decoded_request, server_ip):
    try:
        if decoded_request:
            # process the request according to client types
            encoded_request = decoded_request.encode('utf-8')
            client_type = get_client_type(encoded_request)
            if client_type == "httpfs":
                response = get_httpfs_response(encoded_request, server_ip)
            elif client_type == "httpc":
                response = get_httpc_response(encoded_request, server_ip)
            else:
                response = get_error_respose()
    except:
        response = get_error_respose()
    finally:
        response = response.encode("utf-8")
        return response


# convert encoded data to packets
def data_to_packets(data, ip, port):
    packet_list = []

    # split encoded data into chunks
    chunk_size = 100
    data_chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    packets_num = str(len(data_chunks))
    p = Packet(packet_type=3,
               seq_num=0,
               peer_ip_addr=ip,
               peer_port=port,
               payload=packets_num.encode('utf-8'))
    packet_list.append(p)

    # put each data chunk into packet, put each packet into packet_list
    for i in range(len(data_chunks)):
        payload = data_chunks[i]
        p = Packet(packet_type=3,
                   seq_num=i + 1,
                   peer_ip_addr=ip,
                   peer_port=port,
                   payload=payload)
        packet_list.append(p)
    return packet_list


def send_fin_ack_packet(conn, router, packet):
    try:
        # conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fin_ack_packet = packet
        fin_ack_packet.packet_type = 6
        conn.sendto(fin_ack_packet.to_bytes(), router)
        print('Send FIN-ACK packet {} to router.'.format(fin_ack_packet.seq_num))
        # it doesn't matter whether the client receive it or not
        # thus, there no need to resend it
    except Exception as e:
        logging.warning("Error: ", e)
    finally:
        print('FIN-ACK Packet 0 Connection closed.\n')
        conn.close()


def send_fin_packet(router, client_ip, client_port):
    try:
        timeout = 2
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fin_packet = Packet(packet_type=5,
                            seq_num=0,
                            peer_ip_addr=client_ip,
                            peer_port=client_port,
                            payload=''.encode('utf-8'))
        conn.sendto(fin_packet.to_bytes(), router)
        print('Send FIN packet "{}" to router.'.format(fin_packet.seq_num))

        conn.settimeout(timeout)
        print('Waiting for FIN-ACK packet {}.'.format(fin_packet.seq_num))

        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)
        print('Get type {} packet {}.'.format(p.packet_type, p.seq_num))
        if p.packet_type == 6 and p.seq_num == 0:
            # setup the server establishment flag
            global establishConnection
            establishConnection = False
            # TODO: reset all the other global variables
            print('Server shuts down TCP connection.')

    except socket.timeout:
        print('FIN packet {} no response after {}s.'.format(fin_packet.seq_num, timeout))
        send_fin_packet(router, client_ip, client_port)
    finally:
        print('FIN Packet 0 Connection closed.\n')
        conn.close()


def four_way_goodbye(router, client_ip, client_port):
    print('Server disconnecting TCP connection...')
    send_fin_packet(router, client_ip, client_port)
