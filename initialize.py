import argparse
import os
import platform

import requests
from dotenv import load_dotenv
from flask import Flask

# initialize platform
systemPlatform = platform.system()
info = platform.uname()

# load environment variables
load_dotenv()

cloudLoggerDisable = False
verbose = False

# linux enable support for flags, others no
if systemPlatform == 'Linux':
    # initialize server
    # create argument parser
    parser = argparse.ArgumentParser(description='Electro Wizard')

    # cloudloggerdisable flag
    parser.add_argument('--cloudloggerdisable', action='store_true', help='Disable Google Cloud Logger')

    # domain flag
    parser.add_argument('--domain', help='Add support for domain names')

    # http flag
    parser.add_argument('--https', action='store_true', default=False, help='Disable HTTPS for testing purposes')

    # host flag
    parser.add_argument('--host', default='127.0.0.1', help='Specify which host to run on')
    # port flag
    parser.add_argument('--port', type=int, default=5000, help='Specify which port to run on')

    # ip flag
    parser.add_argument('--ip', action='store_true', default=False, help='Fetch your IP address and serve publicly')

    # verbose flag
    parser.add_argument('--verbose', action='store_true', default=False, help='Enable verbose mode to print debug messages')

    # parse all arguments
    args = parser.parse_args()
    cloudLoggerDisable = args.cloudloggerdisable
    domain = args.domain
    https = args.https
    host = str(args.host)
    port = str(args.port)
    verbose = args.verbose

    # check if http flag is enabled and set protocol
    if https:
        protocol = 'https://'
    else:
        protocol = 'http://'
        print('\033[91mWARNING: HTTPS flag not enabled, serving unsecurely\033[0m')

    # check if domain flag is enabled
    if not domain:
        # if domain not used, then:
        # check if ip flag is enabled
        if args.ip:
            # detecting ip shenanigans
            print("Fetching IP...")
            ip_json = requests.get('https://api.ipify.org?format=json')
            if ip_json.status_code == 200:
                data = ip_json.json()
                ip = data['ip']
                print('Your public IP is: ' + ip)
                hostURL = protocol + ip + ':' + port
                print('\033[92mServing on: ' + hostURL + '\033[0m')
                print()
            else:
                print('Error getting IP')
        else:
            hostURL = protocol + host + ':' + port
            print('\033[91mWARNING: Serving locally, unable to serve outside local network\033[0m')
            print('\033[92mServing on: ' + hostURL + '\033[0m')
    elif domain:
        # if domain is used, then override everything on top
        hostURL = protocol + domain
    else:
        print("omegalul")

# if not linux, use default host
else:
    host = '127.0.0.1'
    hostURL = 'http://' + host + ':5000'
    args = 'Started with Windows; Flags not supported'
