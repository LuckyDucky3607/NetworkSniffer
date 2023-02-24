#!/usr/bin/env python2

import scapy.all as scapy
import argparse


# Let the user pick which interface to scan using -i or --interface in the command
def parsing():
    parser = argparse.ArgumentParser()

    # Add the -t command and assign it to "target"
    parser.add_argument("-t", "--target", type=str, dest="target", help="The ip range you want to scan")
    parser.add_argument("-T", "--timeout", type=int, dest="timeout", help="The timeout value you want to set if an IP did not respond (the default is 3 seconds)")
    # Get the user input of the interface
    options = parser.parse_args()

    # Check if the user actually specified an interface
    if not options.timeout:
        options.timeout = 3
    if not options.target:
        parser.error("[-] Please specify the IP range you want to scan")

    # Return the user input to use it in other functions
    return options


# Scan the interface
def scan(ip, timeout_value):
    # Asks each ip the MAC address of it
    arp_request = scapy.ARP(pdst=ip)

    # Broadcasts the arp_request to the Broadcasting MAC
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff:ff")

    # Does both
    arp_request_broadcast = broadcast/arp_request
    # Checks the MACs that answered two lists answered, not-answered and they divide into lists of answers like of we print the [0] one it is going to give us the first ip that it founds
    answered_list = scapy.srp(arp_request_broadcast, timeout=timeout_value, verbose=False)[0]
    return answered_list


# Prints the IPs and the MACs in a table
def print_data(list_of_answers):
    print("IP\t\t\tMAC Address\n----------------------------------------------")
    num = -1
    answers = []
    for answer in list_of_answers:
        num += 1
        answer_dict = {"ip": answer[1].psrc, "mac": answer[1].hwsrc}
        answers.append(answer_dict)
        print(answers[num]["ip"] + "\t\t" + answers[num]["mac"])


# Calls all the functions

option = parsing()
data = scan(option.target, option.timeout)
print_data(data)
