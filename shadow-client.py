#!/usr/bin/env python3

import hmac
import hashlib
import json
import configparser
import time

from urllib.request import urlopen, Request

config = configparser.ConfigParser()
config.read("shadow.conf")
credentials = config["shadow"]
uri = "https://transform.shadowserver.org/api2/"

TIMEOUT = 45

reportDescription = {
    'blocklist':'IP Blocklist',
    'device_id':'Device Identification',
    'event4_honeypot_brute_force':'Brute-force attack observed by honeypots',
    'event4_sinkhole':'Sinkhole connections',
    'event4_sinkhole_http':'Sinkhole connections to HTTP',
    'scan6_telnet':'Open IPv6 telnet found',
    'scan_ftp':'Open FTP found',
    'scan_ipmi':'Open IPMI found',
    'scan_isakmp':'Open Isakmp found',
    'scan_mdns':'Open mDNS found',
    'scan_netbios':'Open netbios found',
    'scan_portmapper':'Open portmapper found',
    'scan_rdp':'open RDP found',
    'scan_rsync':'Open rsync found',
    'scan_smb':'Open SMB found',
    'scan_snmp':'Open SNMP found',
    'scan_ssl_poodle':'Open SSLv3 found',
    'scan_telnet':'Open telnet found',
    'scan_tftp':'Open TFTP found'
}



def add_ip_port_fields(device):
    '''
    Change src_ip to srcip and src_port to srcport, also for dst_ip, dst_port, port, ip
    for Wazuh to be able to parse the logs:
    '''
    if 'src_ip' in device:
        device['srcip'] = device['src_ip']
        del device['src_ip']
    if 'src_port' in device:
        device['srcport'] = device['src_port']
        del device['src_port']
    if 'dst_ip' in device:
        device['dstip'] = device['dst_ip']
        del device['dst_ip']
    if 'dst_port' in device:
        device['dstport'] = device['dst_port']
        del device['dst_port']
    if 'port' in device:
        device['srcport'] = device['port']
        del device['port']
    if 'ip' in device:
        device['srcip'] = device['ip']
        del device['ip']

    return device

def change_to_date_isoformat(device):
    device['timestamp'] = device['timestamp'].replace(' ','T')
    return device

def add_type_report(device, reportTypes, typeToFind):
    for reportType in reportTypes:
        if typeToFind == reportType['type']:
            device.update(reportType)
            break
    return device

def modify_description(reportTypes):
    '''
    Add description to netbios and ntp. Also add consistency to the other description.
    '''
    for reportType in reportTypes:
        try:
            reportType['description'] = reportDescription[reportType['type']]
        except:
            print("report with no description")

    return reportTypes

def log_json(jsonFile, content, output=True):
    content['app'] = "shadowserver"
    content = json.dumps(content)
    jsonFile.write(content)
    jsonFile.write('\n')
    if output:
        print(content)

def api_call(method, request):
    """
    Call the specified api method with a request dictionary.

    """

    url = f"{uri}{method}"

    request['apikey'] = credentials['key']

    secret_bytes = bytes(str(credentials['secret']), 'latin-1')
    request_bytes = bytes(json.dumps(request), 'latin-1')

    hmac_generator = hmac.new(secret_bytes, request_bytes, hashlib.sha256)
    hmac2 = hmac_generator.hexdigest()

    ua_request = Request(url, data=request_bytes, headers={'HMAC2': hmac2})
    response = urlopen(ua_request, timeout=TIMEOUT)

    return response.read()


if __name__ == '__main__':

    while True:

        reports = json.loads(api_call("reports/list", json.loads('{"detail":true}')))
        lastDateReport = reports[-1]['timestamp'] # Getting date of the more update report.

        reportTypes = json.loads(api_call("reports/types", json.loads(f'{{"detail":true, "date":"{lastDateReport}"}}')))
        
        reportTypes = modify_description(reportTypes)

        with open('log.json','a') as jsonFile:

            for report in [report for report in reports if report['timestamp'] == lastDateReport]:
                devices = json.loads(api_call("reports/download", json.loads(f'{{"id": "{report["id"]}" }}')))

                for device in devices:
                    device = add_ip_port_fields(device)
                    device = change_to_date_isoformat(device)
                    device = add_type_report(device, reportTypes, report['type'])
                    log_json(jsonFile, device)

        sleepTime = 60*60*24 # sleeps for 1 day
        print(f"sleep for {sleepTime} seconds.")
        time.sleep(sleepTime) 
        