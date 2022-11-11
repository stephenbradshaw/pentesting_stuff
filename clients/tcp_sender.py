import socket
import ssl

def send_receive(host: str, port: int, filename: str, wrap_ssl: bool=False, sni_hostname: str=None, timeout: int=5):
    '''Connect to host on given TCP port, with optional ssl wrapping, send data from provided filename, and return response'''
    client_socket = socket.socket()
    client_socket.settimeout(timeout)
    
    if wrap_ssl:
        #client_socket = ssl.wrap_socket(client_socket, ssl_version=ssl.PROTOCOL_TLSv1_2)
        #context = ssl._create_unverified_context(protocol=ssl.PROTOCOL_TLSv1_2)
        context = ssl._create_unverified_context()
        if sni_hostname:
            client_socket = context.wrap_socket(client_socket, server_hostname=sni_hostname)
        else:
            client_socket = context.wrap_socket(client_socket)
        

    client_socket.connect((host, port))
    client_socket.send(open(filename, 'rb').read())
    out = b''
    moar = True
    while moar:
        try:
            d = client_socket.recv(1024)  
            if len(d) < 1:
                moar = False
            out += d
        except (TimeoutError, ConnectionResetError):
            moar = False
        except:
            break
            
    client_socket.close()
    return out

