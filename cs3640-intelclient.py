#!/usr/bin/env python3
"""
        Project : CS3640 Assignment 4
        File    : cs3640-intelclient.py
"""

import socket
import argparse
from net_comms_lib import transmit, receive, utf8decoder
import ast

def create_domain_query(domain, query):
    return str([domain, query])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-intel_server_addr',type=str,help='ip address of record server')
    parser.add_argument('-intel_server_port',type=int,help='service port of record server')
    parser.add_argument('-domain',type=str,help='domain name to query')
    parser.add_argument('-service',type=str,help='information desired about domain')
    args = parser.parse_args()

    SERVER      = args.intel_server_addr
    SERVER_PORT = args.intel_server_port
    DOMAIN      = args.domain
    QUERY       = args.service
    query = str([DOMAIN,QUERY])

    SERVER_SOCKET = (SERVER, SERVER_PORT)

    connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection_socket.settimeout(10)
    connection_socket.connect(SERVER_SOCKET)

    transmit(msg=query,outbound_socket=connection_socket)
    response = receive(inbound_socket=connection_socket , decode_proc=utf8decoder)
    response = ast.literal_eval(response)

    if QUERY ==  'HOSTING_AS':
        print(response[0])
    else:
        print(response)

if __name__ == '__main__':
    main()
