#!/usr/bin/env python3
"""
        Project : CS3640 Assignment 4
        File    : cs3640-ping.py
"""
import socket
import dpkt
import  threading
import datetime
import argparse
import time
import ipaddress
import sys

class PingContainer():
    def __init__(self):
        """ 
            Constructor creates a dicationary to store data and set 
            the most recent hop to an empty string
        """
        self.data   = {}
        self.most_recent_hop = ""

def validate_ipv4_address( address : str ) -> bool :
    """
        Ensures a valid ipv4 address is present
    """
    try:
        ip = ipaddress.ip_address(u"{}".format(address))
        return True
    except:
        return False
    

def make_icmp_socket( ttl : int , timeout : int ) -> socket.socket:
    """
        Constructs and configures an ICMP socket for sending and receiving ICMP packets.<br>

        Parameters:<br>
        - <strong>ttl</strong>     (<code>int</code>)  time to live for the ICMP packets<br>
        - <strong>timeout</strong> (<code>int</code>)  time (in seconds) to wait for a response before timing out<br>

        Returns:<br>
        - a configured raw socket for ICMP communication.
    """
    # Define the socket and its attributes
    raw_socket = socket.socket( family = socket.AF_INET,
                                type   = socket.SOCK_RAW,
                                proto  = socket.IPPROTO_ICMP)
    raw_socket.settimeout(timeout)
    raw_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    return raw_socket

def make_icmp_payload() -> dpkt.icmp.ICMP:
    """ 
        Function that handles the creation of the ICMP Payload

    """
    #Declare and define the type of the ICMP.
    icmp = dpkt.icmp.ICMP()
    icmp.type = dpkt.icmp.ICMP_ECHO
    return icmp

def send_icmp_echo( socket : socket.socket , payload : str , id : int , seq : int , destination : str) -> None :
    """
        Procedure sends an ICMP ping to a destination.<br>

        Parameters:<br>
        - <strong>socket</strong>       (<code>socket.socekt</code>) the raw socket through which the ICMP packet will be sent<br>
        - <strong>payload</strong>      (<code>str</code>)           the payload data for the ping<br>
        - <strong>id</strong>           (<code>int</code>)           the identifier for the ICMP ping request<br>
        - <strong>seq</strong>          (<code>int</code>)           the sequence number for the ping<br>
        - <strong>destination</strong>  (<code>str</code>            the destination IP address to which the ICMP packet is sent<br>

        Returns:<br>
        - None
    """
    
    echo        = dpkt.icmp.ICMP.Echo()
    echo.id     = id
    echo.seq    = seq
    echo.data   = str(payload).encode('utf-8')
    icmp = dpkt.icmp.ICMP()
    icmp.type = dpkt.icmp.ICMP_ECHO
    icmp.data = echo
    
    #Connect to the socket at the provided destination.
    socket.connect((destination,80))
    #Send out the ICMP packet to the given destination!
    socket.sendto(icmp.pack(), (destination,80))

def generate_icmp_response_results_str(*, dst : str, seqno : int, id : int, ttl : int, rtt : float) -> str:
    """
        Function generates a formatted string of ICMP response 
        results for display in a human-readable format.<br>

        Parameters:<br>
        - <strong>dst</strong>            (<code>str</code>)  the destination IP address of the ping<br>
        - <strong>seqno</strong>          (<code>int</code>)  the sequence number of the ping<br> 
        - <strong>id</strong>             (<code>str</code>)  the identifier of the ping<br>
        - <strong>ttl</strong>            (<code>str</code>)  time to live value of the ICMP packet<br>
        - <strong>rtt</strong>            (<code>str</code>)  round-trip time of the ICMP response in milliseconds<br>

        Returns:<br>
        - a formatted string containing the destination, sequence number,
            identifier, TTL, and RTT.
    """
    dst_str = "destination = {}".format(dst)
    seq_str = "icmp_seq = {}".format(seqno)
    id_str  = "icmp_id = {}".format(id)
    ttl_str = "ttl = {}".format(ttl)
    rtt_str = "rtt = {} ms".format(round(rtt,2))

    #Returns the combined formatted data
    return "{}; {}; {}; {}; {}".format(
        dst_str, seq_str, id_str, ttl_str, rtt_str
    )
    
def recv_icmp_response() -> dict:
    """
        Procedure receives ICMP responses from the network and returns relevant data.
        through the creation of a socket, binds it to a specified port,
        and listens for incoming ICMP responses. It also includes error handling to
        prevent exceptions from crashing the program.<br>

        Returns:<br>
        - a dictionary containing the arrival time, response message, and source address
        of the ICMP response, or None if no response is received.
    """

    #Bind the socket to an empty string for 5000
    raw_socket = make_icmp_socket(1,5)
    raw_socket.bind(("",5000))
    
    #Recieves the data
    try:
        data, addr = raw_socket.recvfrom(1048576)
    except:
        return None
    
    #Handles time conversion from microseconds to milliseconds
    curr_time = datetime.datetime.now().microsecond /1000
    
    
    return {'arrival-time'      :curr_time,
            'response-msg'      :data,
            'source-addr'       :addr
        }
        
        

def extraction_decorator_recv_icmp_response(container : dict) -> None :
    """
        Decorator allows for extraction and manipulation
        of return data from 
        recv_icmp_response, in the instance in which the function
        is called in a different thread.
        
    """
    #Grab the data from the ICMP response
    data = recv_icmp_response()
    if data == None:
        return None
    
    src = data['source-addr'][0]
    container.data[src] ={
                        'msg'           : data['response-msg'],
                        'source'        : src,
                        'arrival-time'  : data['arrival-time']
                    }

def icmp_ping(*, container : dict, dst :str , ttl : int , timeout : int , sequence_no : int, id : int) -> dict:
    """
        Sends an ICMP ping to a destination and processes the response.<br>

    Parameters:<br>
    - <strong>container</strong>   (<code>dict</code>) an object to store the ping results and hop information<br>
    - <strong>dst</strong>         (<code>str</code>)  the destination IP address to ping<br>
    - <strong>ttl</strong>         (<code>int</code>)  time to live for the ICMP packet<br>
    - <strong>timeout</strong>     (<code>int</code>)  time (in seconds) to wait for a response before timing out<br>
    - <strong>sequence_no</strong> (<code>int</code>)  the sequence number which is used for identification purposes<br>
    - <strong>id</strong>          (<code>int</code>)  ID of the ICMP ping<br>

    Returns:<br>
    - the updated container object containing information about the most recent hop and the received ICMP response or a placeholder if nothing was recieved. 
    
    """
    sock = make_icmp_socket(ttl, timeout)
    
    __temp_container = PingContainer()
    
    #Define the thread to allows listening for multiple responses at once.
    recv_thread = threading.Thread(
                    target=extraction_decorator_recv_icmp_response,
                    args=[__temp_container])
    
    #Begin the listening process
    recv_thread.start()
    
    time.sleep(1)
    
    # Send the ICMP Echo Request and wait for thread to process response.
    comms_start_time = datetime.datetime.now().microsecond /1000
    
    try:
        send_icmp_echo(sock,'.', sequence_no, id, dst)
        recv_thread.join()
    except:
        return None

    #Returns the container: handles the case of nodes being hidden or secure or
    # none answers
    if len(__temp_container.data.keys()) == 0: 
        src = 'secure/hidden/na'
        container.most_recent_hop = 'secure/hidden/na'
        return  
    
    src = list(__temp_container.data.keys())[0]
    if not src in container.data:
        container.data[src] = { 'entries' : [] }
    
    # Append ping results to relevant PingContainer entry cache.
    container.most_recent_hop = src
    container.data[src]['entries'].append(__temp_container.data[src])
    # Id serving as an index into the 'entries' list (per list entry -> id 0...len('entries'))
    container.data[src]['entries'][id]['seq-no']        = sequence_no
    container.data[src]['entries'][id]['id']            = id
    container.data[src]['entries'][id]['transmit-time'] = comms_start_time
    container.data[src]['entries'][id]['ttl-allotted']  = ttl
    


def display_ping_results(ping_container : PingContainer, dst : str) -> None:
    """
        Displays the ICMP ping results.<br>

        Parameters:<br>
        - <strong>ping_container</strong>     (<code>PingContainer</code>) an object containing ping results<br>
        - <strong>dst</strong>                (<code>str</code>)           destination of the ping container results<br> 

        Returns:<br>
        - result containing the ping container data. 
    
    """
    if dst not in ping_container.data:
        print('invalid display ping query')
        return 
    
    # Retrieve the requested ping data.
    result = ping_container.data[dst]['entries']
    
    # Iteratively print all ping data associated with the provided dst.
    for entry in result:
        seq_no  = entry['seq-no']
        id      = entry['id']
        ttl     = entry['ttl-allotted']
        rtt     = entry['arrival-time'] - entry['transmit-time']
        print(generate_icmp_response_results_str(
                    dst=dst, 
                    seqno=seq_no, 
                    id=id, 
                    ttl=ttl, 
                    rrt=rtt))

def display_ping_result_i(*, ping_container : PingContainer, dst : str , idx : int) -> None:
    """
        Displays the specific ping result for a given destination and entry index.<br>

        Parameters:<br>
        - <strong>ping_container</strong>  (<code>PingContainer</code>)  an object containing ping results, organized by destination.
        - <strong>dst</strong>             (<code>str</code>)            the destination IP address for which to display the ping result.
        - <strong>idx</strong>             (<code>int</code>)            the index of the specific entry in the ping results to display.

        Returns:
        - Nothing
    """
    result = ping_container.data[dst]['entries']
    
    entry = result[idx]
    seq_no  = entry['seq-no']
    id      = entry['id']
    ttl     = entry['ttl-allotted']
    rtt     = entry['arrival-time'] - entry['transmit-time']

    print(generate_icmp_response_results_str(
                dst=dst, 
                seqno=seq_no, 
                id=id, 
                ttl=ttl, 
                rtt=rtt))
            

def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-destination', type=str, 
                                help='target for icmp echo request(s)',
                                default='127.0.0.1')
    parser.add_argument('-n', type=int, 
                                help='number of icmp echo request(s) to send',
                                default=1)
    parser.add_argument('-ttl', type=int, 
                                help='limit on number of router hops permitted to reach destination',
                                default=255)
    args = parser.parse_args()
    
    
    comms_destination   = args.destination
    
    if not validate_ipv4_address(comms_destination):
        print("invalid destination ... please enter valid ipv4 address")
        return -1

    comms_ttl           = args.ttl
    comms_timeout       = 5
    comms_iterations    = args.n

    results = PingContainer()
    
    for i in range(comms_iterations):
        try:
            # ping success ?
            icmp_ping(
                container=results, 
                dst=comms_destination, 
                ttl=comms_ttl,
                timeout=comms_timeout,
                sequence_no=i,
                id=i)
            display_ping_result_i(
                    ping_container=results, 
                    dst=comms_destination, 
                    idx=i)
        except KeyboardInterrupt:
            sys.exit()
        except:
            # ping failure
            print("...")
  
            
if __name__ == '__main__':
    main()