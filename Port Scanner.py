import sys
from xml.dom import ValidationErr
import validators
import nmap
import socket

def scan(input):
    print(input)
    nmScan = nmap.PortScanner()
    nmScanResult = nmScan.scan(input, '21-444')
    if 'tcp' in nmScanResult['scan'][input]:
        print(list(nmScanResult['scan'][input]['tcp'].keys()))
        if 443 in list(nmScanResult['scan'][input]['tcp'].keys()):
            print("connects to port 443")
    else:
        print("No tcp found")

def getInput():
    userInput = input("Type url or ip: \n")
    if validators.url(userInput, public=True):
        print("Initialting scan against url: " + userInput) 
        userInput = userInput.split("//")[1].split("/")[0]
        scan(socket.gethostbyname(userInput))
    elif validators.domain(userInput):
        print("Initialting scan against url: " + userInput) 
        scan(socket.gethostbyname(userInput))
    elif validators.ip_address.ipv6(userInput):
        print("Initiating scan against IPv6: " + userInput)
        scan(userInput)
    elif validators.ip_address.ipv4(userInput):
        print("Initiating scan against IPv4: " + userInput)
        scan(userInput)
    else:
        print("Not valid input")


getInput()