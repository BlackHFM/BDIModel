import bdiagent.bdiagent as agent
import nmap

# agent = agent.Agent()
# agent.beliefbase = {'os_type', 'port', 'service', 'vulnerability', 'password_ssh'}
# agent.believe_support('port', '20')
# agent.believe_support('port', '80')
# def get_initial_belief(beliefbase):
#     beliefbase['port'] = {'20', '80'}

class Main(agent.Agent):
    def __init__(self):
        agent.Agent.__init__(self)

    def getpercepts(self, beliefbase):
        beliefbase['port'] = self.open_port()
    def open_port(self):
        # define the range of ports to be scanned
        begin = 1
        end = 25
        # define a list
        ports = []

        # assign the target IP to be scanned
        target_ip = input("please enter ip address:\n")
        # instantiate a portScanner object
        scanner = nmap.PortScanner()

        # scan the target ports and print the state of each port
        for i in range(begin, end + 1):
            res = scanner.scan(target_ip, str(i))
            res_state = res['scan'][target_ip]['tcp'][i]['state']
            # print(res['scan'][target_ip]['tcp'][i])
            if res_state == 'open':
                ports.append(i)
        #     print(f'port {i} is {res}.')
        return ports


agent = Main()
