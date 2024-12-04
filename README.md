# Multi-Tasked Project 
## Author : Jonathan Boyd



## a DNS-like client-server implementation 
### (University of Iowa - Networking course assignment)
## an ICMP ping and traceroute implementation
### Following packages must be installed...
<ol>
    <li>dpkt</li>
    <li>ssl</li>
    <li>dnspython</li>
    <li>ipwhois</li>
    <li>ipaddress</li>
    <li>datetime</li>
    <li>ast</li>
    <li>*** THIS IMPLEMENTATION REQUIRES PYTHON3</li>
</ol>
This project coincides with a university networking assignment, involving the use of dnspython, ssl, and various
network-based python modules to implement a client-server-query application. The client in this implementation is capable of 
connecting to the server, utilizing the comand-line to pass a desired query on a specified domain name. The server attempts to mimic 
a caching system, populating a database with query results from client connections, returning information as needed.

### UPDATES
- (11/06/2024) Considering refactoring the DomainQuery structure for easier addition and removal of components...

### How to run <code>cs3640-ping.py</code>
To run the project file. At the command-line...<br>
enter command: <code>sudo python3 cs3640-ping.py -destination ('ipv4 address') -n (number of pings to send) -ttl (time to live)</code>

### How to run <code>cs3640-traceroute.py</code>
To run the project file. At the command-line...<br>
enter command: <code>sudo python3 cs3640-traceroute.py -destination ('ipv4 address') -n_hops (int constraint on the number of hops allowed to trace over to destination)</code>

### How to run DNS-like implementation
To run the project file. At the command-line of multiple terminals...<br>
<ol>
    <li>run the server: <code>python3 cs3640-intelserver.py</code></li>
    <li>run any given client quiery: <code>python3 cs3640-intelclient.py -intel_server_addr ('ip addr') -intel_server_port ('server service port') -domain ('domain name to query') -service (query option ~see below)</code></li>
</ol>
The query options: 'IPV4_ADDR', 'IPV6_ADDR', 'TLS_CERT', 'HOSTING_AS', 'ORGANIZATION'

#### Example command-lines

<code>python3 cs3640-intelclient.py -intel_server_addr '127.0.0.1' -intel_server_port 5555 -domain 'www.google.com' -service 'IPV4_ADDR'</code><br>

<code>sudo python3 cs3640-ping.py -destination '8.8.8.8' -n 3 -ttl 100</code><br>

 <code>sudo python3 cs3640-traceroute.py -destination '8.8.8.8' -n_hops 10</code>

#### CREDITS
>> socket.SOL_IP  <br>
https://stackoverflow.com/questions/38142075/setsockopt-sol-ip-api-level-and-ipt-so-set-replace-switch<br>
>> socket.IP_TTL<br>
https://stackoverflow.com/questions/46059768/how-to-set-ip-ttl-for-a-packet-in-python<br>
>> raw sockets <br>
https://www.man7.org/linux/man-pages/man7/raw.7.html<br>
>> echo<br>
https://jon.oberheide.org/blog/2008/08/25/dpkt-tutorial-1-icmp-echo/<br>
>> time<br>
https://docs.python.org/3/library/time.html<br>
https://www.geeksforgeeks.org/get-current-time-in-milliseconds-using-python/<br>
>> dispatcher<br>
https://stackoverflow.com/questions/9205081/is-there-a-way-to-store-a-function-in-a-list-or-dictionary-so-that-when-the-inde<br>
>> IPWhoIs<br>
https://ipwhois.readthedocs.io/en/latest/<br>
>>threading<br>
https://docs.python.org/3/library/threading.html#threading.Thread<br>
>> valid address<br>
https://docs.python.org/3/library/ipaddress.html#ipaddress.ip_address<br>
>> round float<br>
https://www.geeksforgeeks.org/how-to-round-floating-value-to-two-decimals-in-python/<br>
>> string to list<br>
https://stackoverflow.com/questions/1894269/how-to-convert-string-representation-of-list-to-a-list

#### Known Bugs
- The intelserver implementation demonstrates a threading bug, which requires the double entry of control-C for keyboard interruption. An uncaught error is
then outputted, corresponding to the threading module-> lock.aquire()
- (10/31/2024) Investigating a need to implement database lock aquisition in database monitor clearing thread. Considering centralizing the answer for unresolved queries to an environment variable.
