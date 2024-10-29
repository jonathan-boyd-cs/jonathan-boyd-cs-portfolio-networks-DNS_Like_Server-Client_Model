#!/usr/bin/env python3
"""
        Project : CS3640 Assignment 4
        File    : cs3640-traceroute.py
"""
import argparse
import importlib
import sys
cs3640_ping = importlib.import_module("cs3640-ping")




def generate_icmp_traceroute_results_str(*, dst : str, hop_no : int, ttl : int, rtt : int) -> str:
    """
        Function generates a well formatted display string of traceroute data, given the provided parameters
    """
    dst_str = "destination = {}".format(dst)
    hop_str = "hop  = {}".format(hop_no)
    ttl_str = "ttl = {}".format(ttl)
    rtt_str = "rtt = {} ms".format(round(rtt,2))
    return "{}; {}; {}; {}".format(
        dst_str, hop_str, ttl_str, rtt_str
    )

# parameter : ping_container -> cs3640_ping#PingContainer
def display_traceroute_results(*, ping_container , dst : str, hop_no : int) -> None:
    """
        Procedure dynamically displays traceroute results, given data present in the provided
        PingContainer and specified dst entry. The program utilizes this procedure on PingContainers
        which always posses a single entry per dst probe.
    """
    if dst not in ping_container.data:
        print('invalid query')
        return None
    
    result = ping_container.data[dst]['entries']
    
    for entry in result:
        ttl     = entry['ttl-allotted']
        rtt     = entry['arrival-time'] - entry['transmit-time']
        print(generate_icmp_traceroute_results_str(
                        dst=dst, 
                        hop_no=hop_no,
                        ttl=ttl, 
                        rtt=rtt))


def main():
    try:
        #Setup parsing 
        parser = argparse.ArgumentParser()
        parser.add_argument('-destination', type=str, 
                                        help='target for icmp traceroute',
                                        default='127.0.0.1')
        parser.add_argument('-n_hops', type=int, 
                                    help='max number of hops permitted',
                                    default=255)
        args = parser.parse_args()
        comms_destination   = args.destination

        if not cs3640_ping.validate_ipv4_address(comms_destination):
                print("invalid destination ... please enter valid ipv4 address")
                return -1

        # Asserting valid IPv4 address / reachable
        temp = cs3640_ping.PingContainer()
        cs3640_ping.icmp_ping(
            container=temp,
            dst=comms_destination,
            ttl=255,
            timeout=5,
            sequence_no=0,
            id=0)
        if comms_destination not in temp.data.keys():
            print('invalid/unreachable ipv4 address')
            return
        # End assertion


        comms_max_hops      = args.n_hops
        #Initializes a PingContainer to store hop results.
        comms_traceroute_hops  = cs3640_ping.PingContainer()
        comms_traceroute_ttl        = 0

        # index hops in route
        i = 0
        # track most recent hop observed
        most_recent = ''
        print("\ntracing to... {}".format(comms_destination))
        # Cycle through each hop and perform ICMP pings until the destination is 
        # reached or the maximum number of hops is exceeded.
        while comms_destination not in comms_traceroute_hops.data and \
            comms_traceroute_ttl < comms_max_hops:
        
            comms_traceroute_ttl += 1

            #Send a ping to the destination with the updated TTL
            cs3640_ping.icmp_ping(
                container=comms_traceroute_hops,
                dst=comms_destination,
                ttl=comms_traceroute_ttl,
                timeout=5,
                sequence_no=i,
                id=0)
            
            prev_hop    = most_recent
            most_recent = comms_traceroute_hops.most_recent_hop
            
            # Print hop result, assuming a new hop has successfully been reached.
            if most_recent != prev_hop:
                #Increment for the next hop
                i += 1
                # able to interpret the most recent hop...
                if most_recent  != 'secure/hidden/na':
                    display_traceroute_results(
                                ping_container=comms_traceroute_hops, 
                                dst=most_recent, 
                                hop_no=i)
                else: 
                    # hop secured, hidden, or unavailable...
                    print('*** hop {}: secure/hidden/na'.format(i))

                
        if most_recent != comms_destination:
            print('hops exceeded before destination was reached.')
    except:
        sys.exit()    
        
        
if __name__ == '__main__':
    main()