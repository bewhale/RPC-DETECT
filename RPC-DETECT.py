import argparse
import json
from concurrent.futures import ThreadPoolExecutor
import requests
import urllib3
from impacket.dcerpc.v5 import rprn, transport
from impacket.dcerpc.v5.dtypes import NULL
from netaddr import IPNetwork

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TS = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
IFACE_UUID = rprn.MSRPC_UUID_RPRN
dns_ips = []
http_ips = []


def print_banner():
    banner = """
    ____  ____  ______     ____  ______________________________
   / __ \/ __ \/ ____/    / __ \/ ____/_  __/ ____/ ____/_  __/
  / /_/ / /_/ / /  ______/ / / / __/   / / / __/ / /     / /   
 / _, _/ ____/ /__/_____/ /_/ / /___  / / / /___/ /___  / /    
/_/ |_/_/    \____/    /_____/_____/ /_/ /_____/\____/ /_/

                                                  - by bewhale
"""
    print(banner)


def save(file, content):
    with open(file, "w") as op:
        op.write("\n".join(content))


def parse_hash(hashes):
    global lmhash
    global nthash
    try:
        lmhash, nthash = hashes.split(':')
        if (len(lmhash) != 32) and (len(nthash) != 32):
            exit("\033[31;1m[-] Hashes Length Error!\033[0m")
        elif (lmhash != "" and len(lmhash) != 32 and len(nthash) == 32) or (nthash != '' and len(nthash) != 32 and len(lmhash) == 32):
            exit("\033[31;1m[-] Hashes Type Error!\033[0m")
    except Exception as e:
        exit("\033[31;1m[-] " + str(e) + "\033[0m")


def dcerpc(ip, domain, username, password, lmhash, nthash):
    global subdomain
    rpctransport = transport.DCERPCTransportFactory(rf'ncacn_np:{ip}[\pipe\spoolss]')
    try:
        rpctransport.set_credentials(username, password, domain, lmhash, nthash)
        rpctransport.set_connect_timeout(3)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        print(f"\033[33;1m[+] {ip} 认证成功!\033[0m")
        dce.bind(IFACE_UUID, transfer_syntax=TS)
        request = rprn.RpcOpenPrinter()
        if rpctransport:
            target_url = rf"http://{ip}.{subdomain}/{ip}"
            request['pPrinterName'] = f'{target_url}\x00'
            request['pDatatype'] = NULL
            request['pDevModeContainer']['pDevMode'] = NULL
            request['AccessRequired'] = rprn.SERVER_READ
            dce.request(request)
    except Exception as e:
        # print(str(err))
        if "0x709" in str(e):
            print("\033[33;1m[+] " + str(ip) + " 请求发送成功!\033[0m")
        else:
            print("\033[31;1m[-] " + str(ip) + ": " + str(e) + "\033[0m")


def fuzz_red():
    try:
        res = requests.get("https://fuzz.red/get", timeout=15, verify=False).text
        # print(res)
        return json.loads(res)['subdomain'], json.loads(res)['key']
    except Exception as e:
        exit('\033[31;1m[-] error: ' + str(e) + "\033[0m")


def get_results():
    global key
    data = {'key': key}
    try:
        res = requests.post("https://fuzz.red/", data=data, timeout=15, verify=False).text
        # print(res)
        lists = json.loads(res)['data']
        if lists:
            for data in lists:
                if data['type'] == 'http':
                    ip = data['reqbody']['url'][1:]
                    if ip not in http_ips:
                        http_ips.append(ip)
                        print("\033[33;1m[+] HTTP: " + ip + "\033[0m")
                if data['type'] == 'dns':
                    a, b, c, d, e = data['subdomain'].split('.', 4)
                    ip = '.'.join([a, b, c, d])
                    if ip not in dns_ips:
                        dns_ips.append(ip)
                        print('\033[33;1m[+] DNS: ' + ip + "\033[0m")
            save("http.txt", http_ips)
            save("dns.txt", dns_ips)
        else:
            print('\033[31;1m[-] 未检测到可出网的机器!\033[0m')
    except Exception as e:
        exit('\033[31;1m[-] error: ' + str(e) + "\033[0m")


if __name__ == '__main__':
    print_banner()
    parser = argparse.ArgumentParser()
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument('-t', '--target', help='target ip')
    group1.add_argument('-f', '--file', help='target ips file')

    parser.add_argument('-d', '--domain', default='', help='Specify domain')
    parser.add_argument('-u', '--username', help='user name')

    group2 = parser.add_mutually_exclusive_group(required=True)
    group2.add_argument('-p', '--password', help='user password')
    group2.add_argument('-H', '--hashes', help='NTLM hashes, format is LMHASH:NTHASH')
    parser.add_argument('-s', '--speed', default='100', help='speed')
    args = parser.parse_args()

    subdomain, key = fuzz_red()
    nthash, lmhash = '', ''
    if args.hashes:
        parse_hash(args.hashes)
    if args.target:
        if "/" in args.target:
            with ThreadPoolExecutor(int(args.speed)) as executor:
                [executor.submit(dcerpc, target, args.domain, args.username, args.password, lmhash, nthash) for
                 target in IPNetwork(args.target)]
        else:
            dcerpc(args.target, args.domain, args.username, args.password, lmhash, nthash)
    else:
        with ThreadPoolExecutor(int(args.speed)) as executor:
            [executor.submit(dcerpc, target.strip(), args.domain, args.username, args.password, lmhash, nthash) for
             target in
             open(args.file, 'r')]
    get_results()
