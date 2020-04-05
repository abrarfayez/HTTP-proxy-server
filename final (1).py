import functools
import operator
import re
import sys
import os
import enum
import socket
import threading
import time

ThreadCounter = 1  # global counters for threads

hash = {}
threads = []
i = 0  # global iterator
x=True


def on_new_client_Request(s):
    # open new connection
    global threads
    global i
    while 1:
        connection, addr = s.accept()
        val = i
        thread = threading.Thread(target=do_socket_logic, args=(s, connection, addr, val))
        thread.start()
        threads.append(thread)

class HttpRequestInfo(object):

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        # port is removed (because it goes into the request_port variable)
        self.headers = headers
        self.relative = 0
        self.request = ''
        self.original = ''
        self.version = 'HTTP/1.0'

    def set_relative(self):
        self.relative = 1

    def not_relative(self):
        self.relative = 0

    def is_relative(self):
        if self.relative == 0:
            return 0
        else:
            return 1

    def set_version(self, string):
        self.version = string

    def to_http_string(self):
        print("*" * 50)
        print("[to_http_string] Implement me!")
        print("*" * 50)
        headers_to_string = functools.reduce(operator.add, self.headers)
        http_string = self.method + ' ' + self.requested_path + ' ' + 'HTTP/1.0'  + '\r\n'
        i = 0
        while i < len(headers_to_string):
            if i % 2 == 0:
                http_string += headers_to_string[i] + ': '
            else:
                http_string += headers_to_string[i] + '\r\n'
            i += 1
        http_string += '\r\n'
        return http_string

    def to_byte_array(self, http_string):
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))

class Url_Type(str):
    Relative = "/"
    Absolute = ""


class HttpErrorResponse(object):
    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        http_string ="HTTP/1.0" + " " + str(self.code) + " " + self.message
        self.to_byte_array(http_string)
        return http_string

    def to_byte_array(self, http_string):
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def caching(requestURL, response):
    global hash
    hash[requestURL] = response


def entry_point(proxy_port_number):
    setup_sockets(proxy_port_number)
    print("*" * 50)
    print("[entry_point] Implement me!")
    print("*" * 50)
    return None


def setup_sockets(proxy_port_number):
    # when calling socket.listen() pass a number
    # that's larger than 10 to avoid rejecting
    # connections automatically.
    print("Starting HTTP proxy on port:", proxy_port_number)
    print("*" * 50)
    print("[setup_sockets] Implement me!")
    print("*" * 50)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', int(proxy_port_number)))
    s.listen(1)
    print(str(socket.gethostname()))
    on_new_client_Request(s)
    # do_socket_logic(s,proxy_port_number)
    return s


def remote_host_connection(s, object):
    address = (object.requested_host, 80)
    buf = b''
    # print(str(object.requested_host))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #lock=threading.Lock()
    try:
        sock.connect(address)
        message = object.to_byte_array(object.to_http_string())
        #   print(message)
        sock.send(message)
        data = sock.recv(2048)
        buf += data
        print('received from remote host ' + str(data))

        sock.close()  # close the connection with the remote server

    except socket.error:
        print('couldnt connect to server')
    return buf


def do_socket_logic(s, connection, client_address, val):
    print('waiting for a connection')
    buf = ''
    lock=threading.Lock()
    try:
        print('client connected:' + str(client_address))
        global  x
        while True:
          with lock:

            data = connection.recv(1024)
            buf += data.decode("utf-8")
            print(data)
            print('received ' +  str(data))
            if str(buf).endswith('\r\n\r\n'):
                print('hi')
                h = http_request_pipeline(client_address, buf)
                print(h.to_http_string())
                break


    finally:
        if (isinstance(h, HttpRequestInfo)):  # if it's valid
            global hash
            if(h.requested_path!=''):
                fullurl = str(h.requested_host) + str(h.requested_path)
            else:
                fullurl=h.requested_host

            if str(fullurl) in hash:  # if the url was visited before

                response = hash[fullurl]
                print('site visited before')

            else:
                response = remote_host_connection(s, h)
                caching(str(fullurl), response)

            if (isinstance(response, str)):
                response = response.encode()
            connection.send(response)  # send response to client
            connection.close()


        else:
            connection.send(h.to_byte_array(h.to_http_string()))
            connection.close()
def http_request_pipeline(source_addr, http_raw_data):
    # check format validity
    out = check_http_request_validity(http_raw_data)
    # if valid then parse
    # 3ala asas el state reponse ele gyele ab3at el error
    if out.value == HttpRequestState.INVALID_INPUT.value:
        ret = HttpErrorResponse(400, "Bad Request")
    elif out.value == HttpRequestState.NOT_SUPPORTED.value:
        ret = HttpErrorResponse(501, "Not implemented")
    else:
        parsed = parse_http_request(source_addr, http_raw_data)
        ret = sanitize_http_request(parsed)
    return ret


def splitting_request(data):
    split_data = data.split("\r\n")
    request_line = split_data[0].split(" ")
    split_path = request_line[1].split("/")
    return split_data, request_line, split_path


def parsing_relative(split_data, split_path):
    path = ''
    Requested_Host = split_data[1].split(": ")
    if Requested_Host == ['']:
        Requested_Host = Requested_Host[0]
    else:
        i = 0
        while i < len(Requested_Host):
            if Requested_Host[i].lower() == 'host':
                Requested_Host = Requested_Host[i + 1]
                i += 1
                break
    i = 1
    while i < len(split_path):
        path += '/' + split_path[i]
        i += 1
    return Requested_Host, path


def parse_absolute(request_line, split_path):
    path = ''
    if split_path[0].startswith('http'):
        Requested_Host = split_path[2]
        if len(split_path) > 3:
            i = 3
            while i < len(split_path):
                path += '/'
                path += split_path[i]
                i += 1
        if len(split_path) == 3:
            path = "/" + ''
    else:
        if len(split_path) == 1:
            Requested_Host = request_line[1]
            path = '/'
        else:
            i = 1
            while i < len(split_path):
                path += '/' + split_path[i]
                i += 1
                Requested_Host = split_path[0]
            print(request_line)
    return Requested_Host, path


def extract_port(Requested_Host):
    if Requested_Host.__contains__(':'):
        splitting = Requested_Host.split(':')
        Requested_Host = splitting[0]
        port = int(splitting[1])
    else:
        port = 80
    return port, Requested_Host


def pasrse_headers(host, headers, Requested_Host, split_data):
    i = 1
    while i < len(split_data):
        data = split_data[i].split(": ")
        if host.__contains__(":") and data[0].lower() == "host":
            data = ['Host', Requested_Host]
            headers.append(data)
        else:
            headers.append(data)
        i += 1
    if i > 1:
        headers = headers[: len(headers) - 2]
    return headers


def parse_http_request(source_addr, http_raw_data) -> HttpRequestInfo:
    Requested_Host = ''
    headers = []
    path = ''
    split_data, request_line, split_path = splitting_request(http_raw_data)
    relative_flag = 0
    if request_line[1].startswith(Url_Type.Relative) == True:
        relative_flag = 1
        Requested_Host, path = parsing_relative(split_data, split_path)
        host = Requested_Host

    else:
        relative_flag = 0
        Requested_Host, path = parse_absolute(request_line, split_path)
        host = Requested_Host
    port, Requested_Host = extract_port(Requested_Host)
    headers = pasrse_headers(host, headers, Requested_Host, split_data)

    ret = HttpRequestInfo(source_addr, request_line[0], Requested_Host, port, path,
                          headers)
    ret.set_version(request_line[2])
    if relative_flag == 1:
        ret.set_relative()
    else:
        ret.not_relative()
        ret.original = request_line[1]
    return ret


def sanitize_http_request(request_info: HttpRequestInfo) -> HttpRequestInfo:
    if request_info.is_relative() == 0:
        split_path = request_info.original.split("/")
        if split_path[0].lower().startswith("http"):
                request_info.headers.append(tuple(['Host', request_info.requested_host]))
        else:
            request_info.headers.append(tuple(['Host', request_info.requested_host]))
    i = 0
    while i < len(request_info.headers):
        request_info.headers[i] = tuple(request_info.headers[i])
        i += 1
    ret = request_info
    return ret



def end_with_two_enter(split):
    if split[len(split) - 1] == '' and split[len(split) - 2] == '':
        valid = 1
    else:
        valid = 0
    return valid


def check_http_request_validity(httprequest) -> HttpRequestState:
    split_data, request_line, split_path = splitting_request(httprequest)
    valid = 0
    method = 0
    relative = 0
    if end_with_two_enter(split_data):
        valid = 1
    else:
        return HttpRequestState.INVALID_INPUT

    # CHECKS the format of both relative and absolute
    while not re.match(
            "^(\w* (?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+ ((HTTP/1.0)|(HTTP/1.1))$)|(^\w* \/(.*) ((HTTP/1.0)|(HTTP/1.1))$)",
            split_data[0]):
        return HttpRequestState.INVALID_INPUT
        break
    else:
        valid = 1
    count = 1
    # Checks if headers are in the specified format
    print(split_data)
    while count < len(split_data) - 2:
        while not re.match("(([\w-]+): (.*))$", split_data[count]):
            valid = 0
            return HttpRequestState.INVALID_INPUT
            break
        else:
            valid = 1
        count += 1
    if valid == 0:
        return HttpRequestState.INVALID_INPUT

    ret = check_method_and_Host(request_line, split_data)
    if ret == HttpRequestState.PLACEHOLDER and valid == 1:
        return HttpRequestState.GOOD
    else:
        return ret


    return HttpRequestState.PLACEHOLDER

def check_method_and_Host(request_line, split_data):
    method = request_line[0]
    if method.lower() == "get":
        valid = 1  # valid
    elif (method.lower() == "post") or (method.lower() == "delete") or (
            method.lower() == "put") or (method.lower() == "head") or \
            (method.lower() == "connection") or (method.lower() == "options") or \
            (method.lower() == "trace") or (method.lower() == "patch"):
        method = 1  # not implemented
    else:
        method = 2  # bad request
    # check host address validity
    if request_line[1].startswith(Url_Type.Relative):
        i = 1
        while i < len(split_data):
            if split_data[i].lower().__contains__('host'):
                valid = 1
                break
            else:
                valid = 0
            i += 1
    if valid == 0:
        return HttpRequestState.INVALID_INPUT

    if method == 1:
        return HttpRequestState.NOT_SUPPORTED
    elif method == 2:
        return HttpRequestState.INVALID_INPUT
    return HttpRequestState.PLACEHOLDER


def get_arg(param_index, default=None):
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")


def main():
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)
    #ret = parse_http_request(1111, "GET /jfjfj/shsj HTTP/1.0\r\nHost: sjdjhdkj:80\r\n\r\n")
   # ret = sanitize_http_request(ret)
    #print(ret.to_http_string())
   # print(check_http_request_validity("get / HTTP/1.0\r\nHost:hdjd\r\n\r\n"))


if __name__ == "__main__":
    main()
