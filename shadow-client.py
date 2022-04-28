#!/usr/bin/env python3

import os
import sys
import hmac
import hashlib
import json
import configparser

from urllib.request import urlopen, Request

config = configparser.ConfigParser()
config.read("shadow.conf")
credentials = config["shadow"]
uri = "https://transform.shadowserver.org/api2/"

TIMEOUT = 45


def add_ip_port_fields(device):
    '''
    Change src_ip to ip and src_port to port in these reports:
        event4_honeypot_http_scan
        event4_sinkhole
        event4_sinkhole_http
    '''
    if 'src_ip' in device:
        device['ip'] = device['src_ip']
        del device['src_ip']
    if 'src_port' in device:
        device['port'] = device['src_port']
        del device['src_port']

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
        if reportType['type'] == 'scan_netbios':
            reportType['description'] = "Open Netbios Scan"
        elif reportType['type'] == 'scan_ntp':
            reportType['description'] = "Open NTP Scan"
        reportType['description'] = reportType['description'].replace("Results","").replace("Scan","Scanned").replace("Scannedned","Scanned").strip()
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

    reports = json.loads(api_call("reports/list", json.loads('{"detail":true}')))
    lastDateReport = reports[-1]['timestamp'] # Getting date of the more update report.

    reportTypes = json.loads(api_call("reports/types", json.loads(f'{{"detail":true, "date":"{lastDateReport}"}}')))
    reportTypes = modify_description(reportTypes)

    with open('log.json','a') as jsonFile:

        for report in [report for report in reports if report['timestamp'] == lastDateReport]:
            devices = json.loads(api_call("reports/download", json.loads(f'{{"id": "{report["id"]}" }}')))
            print(report['timestamp'], report['type'])

            for device in devices:
                device = add_ip_port_fields(device)
                device = add_type_report(device, reportTypes, report['type'])
                log_json(jsonFile, device)
