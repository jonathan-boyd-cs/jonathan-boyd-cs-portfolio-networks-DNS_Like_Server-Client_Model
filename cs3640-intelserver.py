#!/usr/bin/env python3
"""
        Project : CS3640 Assignment 4
        File    : cs3640-intelserver.py
"""


import socket
import time
import threading
from net_comms_lib import transmit, receive, utf8decoder
from domain_query_lib import DomainQueryDatabase
from typing import List

# ==============================================================================================

# [ CONSTANT VARIABLES ]
LOCALHOST       = '127.0.0.1'
SERVER_SOCKET   = (LOCALHOST, 5555)
MAX_CLIENTS     = 10
LISTEN_SOCKET   = None


def parse_domain_query(query : str) -> List[str]:
    """
        parsing out quotations and extra space for query command
        
        original format for server-client implementation is...
        str(['domain','query'])
    """
    ret = query.split(',')
    ret[0] = ret[0][2:len(ret[0])-1]
    ret[1] = str(ret[1][2:len(ret[1])-2])
    return ret


def client_handler(client_socket : socket.socket, domainQueryDatabase : DomainQueryDatabase) -> None:
    """
        Thread function handles client connections/domain queries for the server.<br>
        
        Parameters:<br>
        - <strong>client_socekt</strong>          (<code>socket.socket</code>)       the socket corresponding to client connection<br>
        - <strong>domainQueryDatabase</strong>    (<code>DomainQueryDatabase</code>) the servers local database of query results<br>
        
        Returns:<br>
        - None
    """
    
    data = receive(
                        inbound_socket  =   client_socket, 
                        decode_proc     =   utf8decoder)
    query_parse = parse_domain_query(data)
    
    domain  = query_parse[0]
    query_       = query_parse[1]
    
    if not domainQueryDatabase.is_valid_query(query_):
        transmit(
                    msg             =  "attempting invalid query... unknown request.", 
                    outbound_socket =   client_socket)
    
    result_of_query = domainQueryDatabase.accept_query(query=query_, domain=domain)
    if result_of_query == None or result_of_query == ['unresolved']:
        
        error = domainQueryDatabase.get_ErrMsgDatabase().generate_error_msg(case=query_, violator=domain)
        transmit(
                    msg             =   error, 
                    outbound_socket =   client_socket)
    
    else:
        transmit(
                    msg             =   str(result_of_query), 
                    outbound_socket =   client_socket)
    
    client_socket.close()


  
def main() -> None :
    """ 
        Main function of program to instantiate a TCP server to listen for and answer domain queries.
    """
    
    # [ SERVER INSTANTIATION ]
    print( f'~~[ (0) BOOT ] Server running... address:{LOCALHOST}.')

    print( '[ (1) SOCKET - ATTEMPT ] socket().')
    try:
        LISTEN_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print( '[ (1) SOCKET - SUCCESS ]...  success.')
    except Exception as e:
        print( f'[(1) [ ERROR) ] SOCKET - FAILURE...exiting.\n{e}')
        exit(-1)

    print( '[ (2) BIND - ATTEMPT ] bind().')
    try:
        LISTEN_SOCKET.bind(SERVER_SOCKET)
        print( '[ (2) BIND - SUCCESS ]... success.')
    except Exception as e:
        print( f'[(2) [ ERROR ] BIND - FAILURE...exiting.\n{e}')
        LISTEN_SOCKET.close()
        exit(-1)

    print( '[ (3) LISTEN - ATTEMPT ] listen().')
    try:
        LISTEN_SOCKET.listen(MAX_CLIENTS)
        print( '[ (3) LISTEN - SUCCESS ]... success.')
        
    except Exception as e:
        print( f'[(3) [ ERROR ] LISTEN - FAILURE...exiting.\n{e}')
        LISTEN_SOCKET.close()
        exit(-1)

    print( '[ (4) SERVER RUNNING ]')

    # OPERATION START
    try:
        domainQueryDatabase = DomainQueryDatabase()  
        while True:
            
            client_connection, addr = LISTEN_SOCKET.accept()
            print('CONNECTION DETECTED FROM -> {}'.format(addr))
            client_thread = threading.Thread(target=client_handler, args=[client_connection,domainQueryDatabase])
            client_thread.start()

    except:
        LISTEN_SOCKET.close()    

if __name__ == '__main__':
    main()