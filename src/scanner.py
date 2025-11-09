#!/usr/bin/env python
# -*- coding: utf-8 -*-

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

def nmap_scan(targets, options):
    nm = NmapProcess(targets, options)
    rc = nm.run()

    if rc != 0:
        raise Exception(f"NMap scan failed: {nm.stderr}")
    
    try:
        report = NmapParser.parse(nm.stdout)
    except NmapParserException as e:
        raise Exception(f"Exception raised while parsing scan: {e.msg}")
    
    report_meta = []

    for host in report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        host_data = {}
        host_data['host'] = tmp_host
        host_data['ip_address'] = host.address
        host_data['results'] = []

        for service in host.services:
            service_data = {
                'port': str(service.port),
                'protocol' : service.protocol,
                'state' : service.state,
                'service': service.service + " " + service.banner,
            }
            host_data['results'].append(service_data)

        report_meta.append(host_data)
    print(report_meta)



# start a new nmap scan on localhost with some specific options
def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets, options)
    rc = nmproc.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))
    print(type(nmproc.stdout))

    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))

    return parsed


# print scan results from a nmap report
def print_scan(nmap_report):
    print("Starting Nmap {0} ( http://nmap.org ) at {1}".format(
        nmap_report.version,
        nmap_report.started))

    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        print("Nmap scan report for {0} ({1})".format(
            tmp_host,
            host.address))
        print("Host is {0}.".format(host.status))
        print("  PORT     STATE         SERVICE")

        for serv in host.services:
            pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                    str(serv.port),
                    serv.protocol,
                    serv.state,
                    serv.service)
            if len(serv.banner):
                pserv += " ({0})".format(serv.banner)
            print(pserv)
    print(nmap_report.summary)


if __name__ == "__main__":
    report = nmap_scan("scanme.nmap.org", "-sV -sS")