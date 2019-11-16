from urllib.parse import urlparse

from packet import Packet


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


# convert encoded data to packets
def data_to_packets(data, ip, port):

    # packet_type = 0, SYN
    # packet_type = 1, SYN-ACK
    # packet_type = 2, DATA

    packet_list = []

    # split encoded data into chunks
    chunk_size = 100
    data_chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    # put each data chunk into packet, put each packet into packet_list
    for i in range(len(data_chunks)):
        payload = data_chunks[i]
        # packet_type = 2, DATA Packet
        p = Packet(packet_type=2,
                   seq_num=(i % 16),
                   peer_ip_addr=ip,
                   peer_port=port,
                   payload=payload)
        packet_list.append(p)
    return packet_list


def get_expected_acks_list(window_sent, window_end, packet_list):
    expected_acks_list = []
    i = window_sent + 1
    while i < window_end:
        expected_acks_list.append(packet_list[i].seq_num)
        i = i + 1
    return expected_acks_list
