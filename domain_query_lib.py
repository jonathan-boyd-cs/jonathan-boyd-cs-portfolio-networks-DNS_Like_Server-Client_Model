#!/usr/bin/env python3

import threading
import time
import dns.message
import dns.query
import dns.rdatatype
import ssl
from ipwhois import IPWhois
import socket
from typing import List
import dns.rrset
import ipaddress

def validate_address( address : str ) -> bool :
    """
        Ensures a valid ipv4 address is present
    """
    try:
        ip = ipaddress.ip_address(u"{}".format(address))
        return True
    except:
        return False


class ErrMsgDatabase( object ) :
    """
        Class serves as a database of error messages to be dynamically generated and returned 
        for the caller.
    """
    def __init__(self, *, cases: List[any]):
        """
            Constructor...<br>
            
            Parameters:<br>
            -<strong>cases</strong>   (<code>list</code>) list of error type names to populate database.
        """
        super().__init__()
        self.__err_msg_registry = {
            x : "{}... unresolved for -> ".format(x) for x in cases
        }
        
    def generate_error_msg(self , *, case: any, violator: str) -> str:
        """
            Function dynamically generates an error message, appending the specified
            domain to the error case if found in error database.<br>
            
            Parameters:<br>
            - <strong>case</strong>          (<code>any</code>) error code/name in database<br>
            - <strong>violator</strong>      (<code>str</code>) violator name<br>
            
            Returns:<br>
            - generated error message
        """
        if not case in self.__err_msg_registry:
            return "unknown error instance for -> {}".format(violator)
        return self.__err_msg_registry[case] + str(violator)

    def set_database_err_msg(self, *, case: any, msg_base: str ) -> None:
        """
            Procedure is used to modify the base error message corresponding to an ErrMsgDatabase case instance.<br>
            
            Parameters:<br>
            - <strong>case</strong>         (<code>any</code>)   the error code/name to modify<br>
            - <strong>msg_base</strong>     (<code>str</code>)   the desired new error message<br>
            
            Returns:<br>
            - None              
        """
        if case in self.__err_msg_registry:
            self.__err_msg_registry[case] = msg_base
    

class DomainQueries( object ) :
    """
        Class provides an assortment of network queries which can be run, given a provided domain.
    """
    
    def __init__(self):
        """ 
            Initializes the instance of the class including a default DNS Server 
            of Google's public DNS one.

        """
        super().__init__()
        self.__query_registry = {
            'IPV4_ADDR'     : self.ipv4_resolver,
            'IPV6_ADDR'     : self.ipv6_resolver,
            'TLS_CERT'      : self.tls_ssl_certificate_fetcher,
            'HOSTING_AS'    : self.domain_as_fetcher,
            'ORGANIZATION'  : self.tls_organization_fetcher
        }
        self.__errMsgDatabase = ErrMsgDatabase(cases=self.__query_registry.keys())
        self.__dns_server = '8.8.8.8'
    
    def get_ErrMsgDatabase(self) -> ErrMsgDatabase:
        return self.__errMsgDatabase
    
    def get_registry(self) -> dict:
        return self.__query_registry
    
    def is_valid_query(self, query : str) -> bool:
        return query in self.__query_registry
       
    def extract_ip_from_rrset_query_result(self, rrset: dns.rrset.RRset) -> str:
        """
            Function parses the dnspython library rrset datatype, aquired from a name resolution,
            returning the ip address within as a string.<br>
            
            Parameters:<br>
            - <strong>rrset</strong>        (<code>dns.datatype.rrset</code>) the rrset dns resolution result to parse<br>
            
            Returns:<br>
            - None
        """
        ret = rrset.to_text().split()
        return ret[4]

    
    def ipv4_resolver(self, domain : str, container: dict) -> None:
        """
            Procedure resolves a domain name (<code>str</code>) to an ipv4 address, storing
            the result in a provided python dictionary container. Returns <code>['unresolved']</code> on
            failure.<br>
            
            Parameters:<br>
            - <strong>domain</strong>        (<code>str</code>)  the domain name to resolve to an ipv4 address<br>
            - <strong>container</strong>     (<code>dict</code>) the result storage structure<br>
            
            Returns:<br>
            - None
            
        """
        query = dns.message.make_query(domain, dns.rdatatype.A)
        response = dns.query.tls(query, self.__dns_server)
        if len(response.answer) > 0:
            container['answer'] = [self.extract_ip_from_rrset_query_result(x) for x in response.answer]
        else:
            container['answer'] = ['unresolved']


    def ipv6_resolver(self, domain : str, container : dict) -> None:
        """
            Procedure resolves a domain name (<code>str</code>) to an ipv6 address, Stores
            the result in a provided python dictionary container. Returns <code>['unresolved']</code> on
            failure.<br>
            
            Parameters:<br>
            - <strong>domain</strong>        (<code>str</code>)  the domain name to resolve to an ipv6 address<br>
            - <strong>container</strong>     (<code>dict</code>) the result storage structure<br>
            
            Returns:<br>
            - None
            
        """
        query = dns.message.make_query(domain, dns.rdatatype.AAAA)
        response = dns.query.tls(query, self.__dns_server)
        if len(response.answer) > 0:
          
            container['answer'] =  [self.extract_ip_from_rrset_query_result(x) for x in response.answer]
        else:
            container['answer'] = ['unresolved']

    def domain_to_ip(self, domain : str) -> List[str]:
        """
            Function attempts to resolve a domain name to either ipv4 or ipv6 address(es).<br>
            
            Parameters:<br>
            - <strong>domain</strong>    (<code>str</code>)  the domain to resolve to ipv4/ipv6<br>
            
            Returns:<br>
            - None
        """
        temp_container = {}
        self.ipv4_resolver(domain, temp_container)
        if temp_container['answer'] == ['unresolved']:
            self.ipv6_resolver(domain, temp_container)
            if temp_container['answer'] == ['unresolved']:
                return None

        return [(x) for x in temp_container['answer']] 

    def tls_ssl_certificate_fetcher(self, domain : str, container: dict) -> None:
        """
            Procedure retrieves the ssl/tls certificate corresponding to a provided 
            domain name. Stores a result in the provided python dictionary container. 
            Returns <code>['unresolved']</code> on failure.<br>
            
            Parameters:<br>
            - <strong>domain</strong>     (<code>str</code>)  the domain to query<br>
            - <strong>container</strong>  (<code>dict</code>) the result storage structure<br>
        """
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        try:
            conn.connect((domain,443))
            cert = conn.getpeercert()
            container['answer'] = [cert]
            
        except:
            container['answer'] = ['unresolved']
 

    def asn_formatter(self, *, domain : str, asn_data : dict) -> str:
        """
            Function formats network asn data, as retrieved from dictionary captured 
            by the IPWhoIs module, and returns a string.<br>
            
            Parameters:<br>
            - <strong>domain</strong>    (<code>str</code>)  the domain corresponding to the asn<br>
            - <strong>asn_data</strong>  (<code>dict</code>) the dictionary to format<br>
            
            Returns:<br>
            - None
            
        """
        s = "DOMAIN {} ASN:\n".format(domain)                             + \
            "ASN               {}\n".format(asn_data['asn'])              + \
            "ASN REGISTRY      {}\n".format(asn_data['asn_registry'])     + \
            "ASN CIDR          {}\n".format(asn_data['asn_cidr'])         + \
            "ASN COUNTRY CODE  {}\n".format(asn_data['asn_country_code']) + \
            "ASN DATE          {}\n".format(asn_data['asn_date'])         + \
            "ASN DESCRIPTION   {}\n".format(asn_data['asn_description'])
        return s  
    
    def domain_as_fetcher(self, domain : str, container : dict) -> None:
        """
            Procedure returns ASN information corresponding to a given domain. Stores the result in the provided
            python dictionary container. Returns <code>['unresolved']</code> on failure.<br>
        
            Parameters:<br>
            - <strong>domain</strong>        (<code>str</code>)  the domain name to resolve to an ipv4 address<br>
            - <strong>container</strong>     (<code>dict</code>) the result storage structure<br>
            
            Returns:<br>
            - None
        """
        ip_addr = self.domain_to_ip(domain)
        if ip_addr == None:
            container['answer'] = ['unresolved']
            return
        for ip in ip_addr:
            try:
                obj = IPWhois(ip)
                who = obj.lookup_rdap(depth=1)
                s= self.asn_formatter(domain=domain, asn_data=who)

                container['answer'] = [(s)]
                return
            except: # non ipv4/ipv6 entry
                continue 
        container['answer'] = ['unresolved']

    def tls_organization_fetcher(self, domain : str, container : dict) -> None:
        """
            Procedure returns organization information corresponding to a given domain. Stores the result in the provided
            python dictionary container. Returns <code>['unresolved']</code> on failure.<br>
            
            Parameters:<br>
            - <strong>domain</strong>        (<code>str</code>)  the domain name to resolve to an ipv4 address<br>
            - <strong>container</strong>     (<code>dict</code>) the result storage structure<br>
            
            Returns:<br>
            - None
        """
        temp_container = {}
        self.tls_ssl_certificate_fetcher(domain, temp_container)
        cert = temp_container['answer'][0]
        if cert == 'unresolved':
            container['answer'] = ['unresolved']
            return
        
        container['answer'] = [cert['subject']]    


    
    
    
    
class DomainQueryDatabase( DomainQueries ):
    """
        Class serves as a quasi-DNS cache system, storing results from client queries.
    """
    def __init__(self):
        super().__init__()
        self.__query_database = {}
        self.monitor_thread = threading.Thread(target=self.__run_monitor)
        self.database_lock  = threading.Lock()
        self.monitor_thread.start()
            
    def __run_monitor(self) -> None:
        """
            Procedure clears database cache on a schedule.
        """
        while True:
            time.sleep(120)
            try:
                self.inventory_clear_all()
            except:
                return
        
    
    def get_database(self) -> dict:
        return self.__query_database
    
    def inventory_new_domain(self, domain : str) -> None :
        """
            Procedure will create a new database entry, given a domain name, if 
            it does not already exist.<br>
            
            Parameters:<br>
            - <strong>domain</strong>    (<code>str</code>)  the domain to add to the database<br>
            
            Returns:<br>
            - None
        """
        if domain not in self.__query_database:
            self.__query_database[domain] = {
                x : None for x in self.get_registry().keys()
            }
        
    def inventory_load_domain(self, domain : str) -> None:
        """
            Procedure populates a domain entry with all potential query information.
            Does nothing if domain doesn't exist in database.<br>
            
            Parameters:<br>
            - <strong>domain</strong>    (<code>str</code>)  the domain in the database to populate<br>
            
            Returns:<br>
            - None
        """
        if domain in self.__query_database:
            for x in self.get_registry().keys():
                self.__query_database[domain][x] = {}
                self.get_registry()[x](domain, self.__query_database[domain][x])
        

    def inventory_clear_all(self) -> None:
        """
            Procedure removes all cached information.
        """
        self.__query_database.clear()
    
    def inventory_clear_domain(self,domain: str) -> None:
        """
            Procedure removes information in cache for a given domain.
        """
        if domain in self.__query_database:
            del self.__query_database[domain]  

    
    def accept_query(self, query : str, domain : str) -> List[any]:
        """
            Function takes a query and domain as arguments and runs that query 
            against the domain, if the query is present in the database's query registry.
            Returns the result of the query as a list. Returns ['unresolved'] if query fails.
            Returns None if query does not exist.<br>
            
            Parameters:<br>
            - <strong>query</strong>   (<code>str</code>)  the query to run against the database<br>
            - <strong>domain</strong>  (<code>str</code>)  the domain to query<br>
            
            Returns:<br>
            - None
        """
        
        if self.is_valid_query(query):
            if not domain in self.__query_database:
                self.database_lock.acquire()
                
                self.inventory_new_domain(domain)
                self.inventory_load_domain(domain)
                
                self.database_lock.release()
            
            self.database_lock.acquire()
            result = self.__query_database[domain][query]['answer']
            self.database_lock.release()
            return result
        else:
            return None
        

