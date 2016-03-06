#! /usr/bin/env python

"""vtc.py

Usage:
  vtc.py [options] init --virustotal KEY [--googl KEY]
  vtc.py [options] report (file|hash|url|domain|ip) <resource>
  vtc.py [options] scan (file [--rescan]|url) <resource>

Options:
  -a KEY, --api-key KEY   This will override the api key in the config file.
  -j, --json              This will return output in json rather than a table.
  -h, --help              Show this screen.
  -v, --version           Show version.
"""

import collections
import ConfigParser
import hashlib
import json
import os
import time

from docopt import docopt
from prettytable import PrettyTable

import googl

from virustotal import *


def jprint(jsondoc):
    print json.dumps(jsondoc, sort_keys=True, indent=2, separators=(',', ': '))


def gethash(path):
    return hashlib.sha256(open(path, 'rb').read()).hexdigest()


def createconfig(keydict):
    HOME = os.path.expanduser('~')
    CONFIG = HOME + '/.vtc.cfg'
    parser = ConfigParser.SafeConfigParser()
    for key in keydict:
        parser.add_section(key)
        parser.set(key, 'apikey', keydict[key])
    with open(CONFIG, 'w') as fout:
        parser.write(fout)


def readconfig(section):
    HOME = os.path.expanduser('~')
    CONFIG = HOME + '/.vtc.cfg'
    parser = ConfigParser.SafeConfigParser()
    parser.read(CONFIG)
    return parser.get(section, 'apikey')


def table(data):
    try:
        googlkey = readconfig('googl')
        g = googl.Googl(googlkey)
        shorten = True
    except:
        googlkey = None
        shorten = False
    metatable = PrettyTable()
    metafields = collections.OrderedDict()
    if arguments['report']:
        if not arguments['ip'] and not arguments['domain']:
            if arguments['url']:
                metafields['URL'] = data['url']
            elif arguments['file'] or arguments['hash']:
                metafields['MD5'] = data['md5']
                metafields['SHA1'] = data['sha1']
                metafields['SHA256'] = data['sha256']
            metafields['Detection ratio'] = '{0}/{1}'.format(data['positives'],
                                                         data['total'])
            metafields['Analysis date'] = data['scan_date']
            metafields['Scan id'] = data['scan_id']
            if shorten:
                link = g.shorten(data['permalink'])['id']
            else:
                link = data['permalink']
            metafields['Link'] = link
            for f in metafields:
                metatable.add_row([f, metafields[f]])
            metatable.align = "l"
            metatable.header = False
            print metatable
            scans = data['scans']
            scanstable = PrettyTable(['Engine',
                                      'Detected',
                                      'Result',
                                      'Detail'])
            for key in scans.keys():
                engine = key
                detected = scans[key]['detected']
                result = scans[key]['result']
                if 'detail' in scans[key]:
                    if shorten:
                        detail = g.shorten(scans[key]['detail'])['id']
                    else:
                        detail = scans[key]['detail']
                else:
                    detail = None
                scanstable.add_row([engine, detected, result, detail])
            scanstable.align = "l"
            print scanstable
        elif arguments['ip'] or arguments['domain']:
            if arguments['ip']:
                headtype = 'Hostname'
                headtype2 = 'hostname'
                if 'asn' in data:
                    metafields['AS owner'] = data['as_owner']
                    metafields['ASN'] = data['asn']
                    metafields['Country'] = data['country']
                    for f in metafields:
                        metatable.add_row([f, metafields[f]])
                    metatable.align = "l"
                    metatable.header = False
                    print metatable
            elif arguments['domain']:
                headtype = 'IP address'
                headtype2 = 'ip_address'
                cattable = PrettyTable(['Categories'])
                for c in data['categories']:
                    cattable.add_row([c])
                cattable.align = "l"
                print cattable
                if 'WOT domain info' in data:
                    print 'WOT domain info'
                    wottable = PrettyTable()
                    for key in data['WOT domain info']:
                        wottable.add_row([key, data['WOT domain info'][key]])
                    wottable.align = "l"
                    wottable.header = False
                    print wottable
                if 'webutation domain info' in data:
                    print 'Webutation domain info'
                    webtable = PrettyTable()
                    for key in data['Webutation domain info']:
                        webtable.add_row([key,
                                          data['Webutation domain info'][key]])
                    webtable.align = "l"
                    webtable.header = False
                    print webtable
                if 'subdomains' in data:
                    subtable = PrettyTable(['Subdomains'])
                    for s in data['subdomains']:
                        subtable.add_row([s])
                    subtable.align = "l"
                    print subtable
                whoistable = PrettyTable(['Whois lookup'])
                whoistable.add_row([data['whois']])
                whoistable.align = "l"
                print whoistable
            if len(data['resolutions']) > 0:
                print 'Resolutions {0}'.format(len(data['resolutions']))
                restable = PrettyTable([headtype, 'Last resolved'])
                for ip in data['resolutions']:
                    restable.add_row([ip[headtype2], ip['last_resolved']])
                restable.align = "l"
                print restable
            if len(data['detected_urls']) > 0:
                print 'URLs {0}'.format(len(data['detected_urls']))
                urltable = PrettyTable(['Analysis date',
                                        'Detection ratio',
                                        'URL'])
                for u in data['detected_urls']:
                    adate = u['scan_date']
                    positives = u['positives']
                    total = u['total']
                    url = u['url']
                    ratio = '{0}/{1}'.format(positives, total)
                    urltable.add_row([adate, ratio, url])
                urltable.align = "l"
                print urltable
            if 'detected_referrer_samples' in data:
                print 'Detected referrer samples {0}'.format(len(data['detected_referrer_samples']))
                dreftable = PrettyTable(['SHA256', 'Detection ratio'])
                for dref in data['detected_referrer_samples']:
                    positives = dref['positives']
                    total = dref['total']
                    ratio = '{0}/{1}'.format(positives, total)
                    shahash = dref['sha256']
                    dreftable.add_row([shahash, ratio])
                dreftable.align = "l"
                print dreftable
            if 'detected_downloaded_samples' in data:
                print 'Detected downloaded samples {0}'.format(len(data['detected_downloaded_samples']))
                ddowntable = PrettyTable(['Analysis date', 'SHA256', 'Detection ratio'])
                for ddown in data['detected_downloaded_samples']:
                    adate = ddown['date']
                    positives = ddown['positives']
                    total = ddown['total']
                    ratio = '{0}/{1}'.format(positives, total)
                    shahash = ddown['sha256']
                    ddowntable.add_row([adate, shahash, ratio])
                ddowntable.align = "l"
                print ddowntable
            if 'detected_communicating_samples' in data:
                print 'Detected communicating samples {0}'.format(len(data['detected_communicating_samples']))
                dcommtable = PrettyTable(['Analysis date', 'SHA256', 'Detection ratio'])
                for dcomm in data['detected_communicating_samples']:
                    adate = dcomm['date']
                    positives = dcomm['positives']
                    total = dcomm['total']
                    ratio = '{0}/{1}'.format(positives, total)
                    shahash = dcomm['sha256']
                    dcommtable.add_row([adate, shahash, ratio])
                dcommtable.align = "l"
                print dcommtable
    elif arguments['scan'] and not arguments['--rescan']:
        if arguments['url']:
            metafields['URL'] = data['url']
        elif arguments['file']:
            metafields['MD5'] = data['md5']
            metafields['SHA1'] = data['sha1']
            metafields['SHA256'] = data['sha256']
        metafields['Scan id'] = data['scan_id']
        if shorten:
            link = g.shorten(data['permalink'])['id']
        else:
            link = data['permalink']
        metafields['Link'] = link
        for f in metafields:
            metatable.add_row([f, metafields[f]])
        metatable.align = "l"
        metatable.header = False
        print metatable
        time.sleep(30)
        arguments['scan'] = False
        arguments['report'] = True
        arguments['<resource>'] = data['scan_id']
        key = readconfig('virustotal')
        vtc = Virustotal(key)
        if arguments['url']:
            output(vtc.urlReport(arguments['<resource>']))
        elif arguments['file']:
            output(vtc.rscReport(arguments['<resource>']))
    elif arguments['--rescan']:
        arguments['scan'] = False
        arguments['report'] = True
        arguments['<resource>'] = data['scan_id']
        key = readconfig('virustotal')
        vtc = Virustotal(key)
        output(vtc.rscReport(arguments['<resource>']))


def output(data):
    if data['response_code'] > 0:
        if arguments['--json']:
            jprint(data)
        else:
            table(data)
    else:
        print data['verbose_msg']


def main(a):
    if a['init']:
        keydict = {}
        keydict['virustotal'] = a['KEY'][0]
        if a['--googl']:
            keydict['googl'] = a['KEY'][1]
        createconfig(keydict)
    else:
        if a['--api-key'] is not None:
            key = a['--api-key']
        else:
            key = readconfig('virustotal')
            if key is None:
                exit(1)
        vtc = Virustotal(key)
        if a['report']:
            if a['file'] or a['hash']:
                if a['hash']:
                    filehash = a['<resource>']
                else:
                    filehash = gethash(a['<resource>'])
                output(vtc.rscReport(filehash))
            elif a['url']:
                output(vtc.urlReport(a['<resource>']))
            elif a['ip']:
                output(vtc.ipReport(a['<resource>']))
            elif a['domain']:
                output(vtc.domainReport(a['<resource>']))
        elif a['scan']:
            if a['file']:
                if a['--rescan']:
                    filehash = gethash(a['<resource>'])
                    output(vtc.rscRescan(filehash))
                else:
                    output(vtc.rscSubmit(a['<resource>']))
            elif a['url']:
                output(vtc.scanURL(a['<resource>']))
        else:
            exit(1)


if __name__ == '__main__':
    arguments = docopt(__doc__, version='vtc.py 0.1b')
    main(arguments)
