#This script is to convert firewall policies from a Juniper firewall to a Fortigate firewall. This is not to convert a whole config file from one type to another.

CONFIGFILENAME = '/usr/local/rancid/var/Juniper/configs/internal-dmz'


with open(CONFIGFILENAME, 'r') as f:
        tmp1_address = [line for line in f if ('set security zones security-zone' in line) and ('address-book address ' in line)]
        tmp2_address = [x.replace('set security zones security-zone ', '') for x in tmp1_address]
        tmp3_address = [x.replace('address-book address ', '') for x in tmp2_address]
        addresses = [x.split() for x in tmp3_address]

with open(CONFIGFILENAME, 'r') as f:
        tmp1_address_group = [line for line in f if ('set security zones security-zone' in line) and ('address-book address-set ' in line)]
        tmp2_address_group = [x.replace('set security zones security-zone ','') for x in tmp1_address_group]
        tmp3_address_group = [x.replace('address-book address-set ', '') for x in tmp2_address_group]
        address_group = [x.split() for x in tmp3_address_group]





address_command = 'config firewall address\n'
address_group_command = 'config firewall addrgrp\n'
temp_address_group = ''
for x in addresses:
        address_command += ('edit ' + x[1] + '\n' + 'set type ipmask\nset subnet ' + x[2] + '\nnext\n')
address_command += '\nend\n'
for index,x in enumerate(address_group):
        if index != 0 and temp_address_group != x[1]:
                address_group_command += ('\nnext\n')
                address_group_command += ('edit ' + x[1] + '\nset member ' + x[3] + ' ')
                temp_address_group = x[1]
        elif index == 0 and temp_address_group != x[1]:
                address_group_command += ('edit ' + x[1] + '\nset member ' + x[3] + ' ')
                temp_address_group = x[1]
        else:
                address_group_command += ( x[3] + ' ' )
address_group_command += '\nend\n'


with open(CONFIGFILENAME, 'r') as f:
        tmp_firewall_application_juniper = [line for line in f if 'set applications application ' in line]
        firewall_application_juniper = [x.split() for x in tmp_firewall_application_juniper]

firewall_application_command = 'config firewall service custom\n'
temp_application = ''
temp_application_term = ''
temp_protocol = ''
temp_protocol_stat = 0
temp_tcp_stat = 0
temp_udp_stat = 0
temp_tcp_text = ''
temp_udp_text = ''
for index,x in enumerate(firewall_application_juniper):
        if index == 0 and temp_application != x[3]:
                temp_application = x[3]
                firewall_application_command += ('edit ' + x[3] + '\n')
                if x[4] != 'term':
                        temp_protocol = x[5]
                        firewall_application_command += ('set ' + temp_protocol + '-portrange ')
                elif x[4] == 'term':
                        temp_protocol = x[7]
                temp_protocol_stat = 0
        elif index != 0 and temp_application != x[3]:
                temp_application = x[3]
                if temp_tcp_stat == 1:
                        firewall_application_command +=('set tcp-portrange ' + temp_tcp_text + '\n')
                        temp_tcp_stat = 0
                        temp_tcp_text = ''
                if temp_udp_stat == 1:
                        firewall_application_command +=('set udp-portrange ' + temp_udp_text + '\n')
                        temp_udp_stat = 0
                        temp_udp_text = ''
                firewall_application_command += '\nnext\n'
                firewall_application_command += ('edit ' + x[3] + '\n')
                if x[4] != 'term':
                        temp_protocol = x[5]
                        firewall_application_command += ('set ' + temp_protocol + '-portrange ')
                elif x[4] == 'term':
                        temp_protocol = x[7]

                temp_protocol_stat = 0
        else:
                if x[4] == 'destination-port':
                        firewall_application_command += ( x[5] + '\n' )
                elif x[4] == 'term' and x[6] == 'protocol':
                        temp_protocol = x[7]
                elif x[4] == 'term' and x[6] == 'destination-port' and temp_protocol == 'udp':
                        temp_udp_text += ( x[7] + ' ')
                        temp_udp_stat = 1
                elif x[4] == 'term' and x[6] == 'destination-port' and temp_protocol == 'tcp':
                        temp_tcp_text += ( x[7] + ' ')
                        temp_tcp_stat = 1

firewall_application_command += '\nend\n'
firewall_application_command += 'config firewall service custom\nedit SNPP\nset tcp-portrange 444\nnext\nedit ECHO\nset udp-portrange 7\nnext\nedit NETBIOS-SESSION\nset tcp-portrange 139\nn
ext\nedit TACACS\nset tcp-portrange 49\nnext\nedit TACACS-DS\nset tcp-portrange 65\nnext\nend\n'

firewall_application_group_command = '\nconfig firewall service group\n'
temp_application_group = ''
with open(CONFIGFILENAME, 'r') as f:
        tmp_firewall_application_group_juniper = [line for line in f if 'set applications application-set ' in line]

        firewall_application_group_juniper = [x.split() for x in tmp_firewall_application_group_juniper]

for index,x in enumerate(firewall_application_group_juniper):
        if index != 0 and temp_application_group != x[3]:
                if 'junos-' not in x[5]:
                        pass


                else:
                        x[5] = x[5].replace('junos-', '')
                        x[5] = x[5].upper()
                if ('ICMP' not in x[5]) and ('icmp' not in x[5]):
                        pass
                else:
                        x[5] = 'ALL_ICMP'
                if ('TRACEROUTE' not in x[5]) and ('traceroute' not in x[5]):
                        pass
                else:
                        x[5] = 'TRACEROUTE'
                firewall_application_group_command += ('\nnext\n')
                firewall_application_group_command += ('edit ' + x[3] + '\nset member ' + x[5] + ' ')
                temp_application_group = x[3]
        elif index == 0 and temp_application_group != x[3]:
                if 'junos-' not in x[5]:
                        pass

                else:
                        x[5] = x[5].replace('junos-', '')
                        x[5] = x[5].upper()
                if ('ICMP' not in x[5]) and ('icmp' not in x[5]):
                        pass
                else:
                        x[5] = 'ALL_ICMP'
                if ('TRACEROUTE' not in x[5]) and ('traceroute' not in x[5]):
                        pass
                else:
                        x[5] = 'TRACEROUTE'

                firewall_application_group_command += ('edit ' + x[3] + '\nset member ' + x[5] + ' ')
                temp_application_group = x[3]
        else:
                if 'junos-' not in x[5]:
                        pass

                else:
                        x[5] = x[5].replace('junos-', '')
                        x[5] = x[5].upper()
                if ('ICMP' not in x[5]) and ('icmp' not in x[5]):
                        pass
                else:
                        x[5] = 'ALL_ICMP'
                if ('TRACEROUTE' not in x[5]) and ('traceroute' not in x[5]):
                        pass
                else:
                        x[5] = 'TRACEROUTE'

                firewall_application_group_command += ( x[5] + ' ' )
firewall_application_group_command += '\nend\n'



policy_number = 1

with open(CONFIGFILENAME, 'r') as f:
        tmp_firewall_policies_juniper = [line for line in f if 'set security policies from-zone ' in line]

        firewall_policies_juniper = [x.split() for x in tmp_firewall_policies_juniper]

firewall_policies_command = 'config firewall policy\n'
temp_policy = ''
temp_match = ''
for index,x in enumerate(firewall_policies_juniper):
        if index == 0 and temp_policy != x[8]:

                temp_policy = x[8]
                firewall_policies_command += ('edit ' + str(policy_number) + '\n')
                firewall_policies_command += ('set srcintf ' + x[4] + '\nset dstintf ' + x[6] + '\n')
                firewall_policies_command += ('set name ' + temp_policy + '\n')
                policy_number += 1

        elif index !=0 and temp_policy != x[8]:

                temp_policy = x[8]
                firewall_policies_command += ('\nset schedule always\n')
                firewall_policies_command += ('\nnext\n')
                firewall_policies_command += ('edit ' + str(policy_number) + '\n')
                firewall_policies_command += ('set srcintf ' + x[4] + '\nset dstintf ' + x[6] + '\n')
                firewall_policies_command += ('set name ' + temp_policy + '\n')
                policy_number += 1

        if temp_match != (temp_policy + x[9] + x[10]) and x[9] == 'match' and x[10] == 'source-address':
                if x[11] == 'any':
                        firewall_policies_command += ('\nset srcaddr all')
                else:
                        firewall_policies_command += ('\nset srcaddr ' + x[11] + ' ')
                temp_match = (temp_policy + x[9] + x[10])
        elif temp_match == (temp_policy + x[9] + x[10]) and x[9] == 'match' and x[10] == 'source-address':
                firewall_policies_command += ( x[11] + ' ' )
        elif temp_match != (temp_policy + x[9] + x[10]) and x[9] == 'match' and x[10] == 'destination-address':
                if x[11] == 'any' or x[11] == 'any-ipv4':
                        firewall_policies_command += ('\nset dstaddr all')
                else:
                        firewall_policies_command += ('\nset dstaddr ' + x[11] + ' ')
                temp_match = (temp_policy + x[9] + x[10])
        elif temp_match == (temp_policy + x[9] + x[10]) and x[9] == 'match' and x[10] == 'destination-address':
                firewall_policies_command += ( x[11] + ' ' )
        elif temp_match != (temp_policy + x[9] + x[10]) and x[9] == 'match' and x[10] == 'application':
                if 'junos-' not in x[11]:
                        pass
                else:
                        x[11] = x[11].replace('junos-', '')
                        x[11] = x[11].upper()
                if ('ICMP' not in x[11]) and ('icmp' not in x[11]):
                        pass
                else:
                        x[11] = 'ALL_ICMP'
                if ('TRACEROUTE' not in x[11]) and ('traceroute' not in x[11]):
                        pass
                else:
                        x[11] = 'TRACEROUTE'

                if x[11] == 'any':
                        firewall_policies_command += ('\nset service ALL')
                else:
                        firewall_policies_command += ('\nset service "' + x[11] + '" ')
                temp_match = (temp_policy + x[9] + x[10])
        elif temp_match == (temp_policy + x[9] + x[10]) and x[9] == 'match' and x[10] == 'application':
                if 'junos-' not in x[11]:
                        pass
                else:
                        x[11] = x[11].replace('junos-', '')
                        x[11] = x[11].upper()
                if ('ICMP' not in x[11]) and ('icmp' not in x[11]):
                        pass
                else:
                        x[11] = 'ALL_ICMP'
                if ('TRACEROUTE' not in x[11]) and ('traceroute' not in x[11]):
                        pass
                else:
                        x[11] = 'TRACEROUTE'

                firewall_policies_command += ( '"' + x[11] + '"' + ' ' )
        elif x[9] == 'then' and x[10] == 'permit':
                firewall_policies_command += ( '\nset action accept\n' )
                if x[6] == 'INTERNET':
                        firewall_policies_command += 'set nat disable\n'
                else:
                        firewall_policies_command += 'set nat disable\n'
        elif x[9] == 'then' and x[10] == 'deny':
                firewall_policies_command += ( '\nset action deny\n' )
                if x[6] == 'INTERNET':
                        firewall_policies_command += 'set nat disable\n'
                else:
                        firewall_policies_command += 'set nat disable\n'

firewall_policies_command += '\nend\n'





print firewall_application_command

file = open("Converted_Internal-DMZ_Fortigate.conf", "w")

file.truncate()

file.write(address_command + address_group_command + firewall_application_command + firewall_application_group_command +firewall_policies_command)

file.close()