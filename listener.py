#!/usr/bin/python3

import socket, sys
import ipWhitelist

# TODO - Make Host/port part of a config file
# TODO - soc.listen(X) a variable in config?
# TODO - would threading help improve high volume performance?

HOST = ''
PORT = 9500

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    soc.bind((HOST, PORT))
except:
    print('Bind failed. Address:Port already in use?')
    sys.exit()

print(f'Listening on {HOST}:{PORT}')

soc.listen(4)

while True:
    # Wait for a connection
    connection, client_address = soc.accept()
    # Receive the data in small chunks
    data = connection.recv(1024).decode('utf-8')
    if not data:
        break

    # Grab the X-Forward-For Header (could improve with index method?)
    xForwardFor = data.split("\r\n")[3]
    # Pull the ip from the header
    ip = xForwardFor[xForwardFor.index(":") + 2:]

    # Send the ip to our Whitelist checking applet
    decision = ipWhitelist.checkIP(ip)

    # OK
    if decision:
        header = "HTTP/1.1 200 OK\r\n"
        ok = "Content-Type: 'default_type text/plain'\r\nConnection: Closed\r\n\r\nOK"
        response = header + ok
        connection.send(response.encode('utf-8'))
        connection.close()

    # Forbidden
    else:
        header = "HTTP/1.1 403 FORBIDDEN\r\n"
        nope = "Content-Type: 'default_type text/plain'\r\nConnection: Closed\r\n\r\n403 Forbidden"
        response = header + nope
        connection.send(response.encode('utf-8'))
        connection.close()
