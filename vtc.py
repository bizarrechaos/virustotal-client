#! /usr/bin/env python

"""vtc.py

Usage:
  vtc.py init --virustotal KEY [--googl KEY]
  vtc.py [options] report (file|hash|url|domain|ip) <resource>
  vtc.py [options] scan (file [--rescan]|url) <resource>
  vtc.py sha256 <file>
  vtc.py signature <file>

Options:
  -a KEY, --api-key KEY   This will override the api key in the config file.
  -j, --json              This will return output in json rather than a table.
  -h, --help              Show this screen.
  -v, --version           Show version.
"""

import binascii
import collections
import ConfigParser
import hashlib
import json
import os
import time

from colors import red, green, blue, bold, strip_color, underline
from prettytable import PrettyTable

from docopt import docopt
from googl import Googl
from virustotal import Virustotal


def getsignature(path):
    with open(path, 'rb') as f:
        content = f.read()
    signature = binascii.hexlify(content)[:16]
    return ' '.join([signature[i:i+2]for i in range(0, len(signature), 2)])


def jprint(jsondoc):
    print json.dumps(jsondoc, sort_keys=True, indent=2, separators=(',', ': '))


def colorize(l, c):
    if isinstance(l, str):
        return c(str(l))
    elif isinstance(l, list):
        r = []
        for i in l:
            if isinstance(i, unicode):
                i = i.encode('utf-8')
                r.append(c(i))
            elif isinstance(i, PrettyTable):
                r.append(i)
            else:
                i = str(i)
                r.append(c(i))
        return r
    else:
        return l


def gethash(path):
    try:
        return hashlib.sha256(open(path, 'rb').read()).hexdigest()
    except IOError:
        print 'Cannot locate the file at: {0}'.format(path)
        exit(1)


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
        g = Googl(googlkey)
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
            if int(data['positives']) > (int(data['total']) / 2):
                c = red
            else:
                c = green
            detectionratio = '{0}/{1}'.format(data['positives'],
                                              data['total'])
            metafields['Detection ratio'] = '{0}'.format(detectionratio)
            metafields['Analysis date'] = data['scan_date']
            metafields['Scan id'] = data['scan_id']
            if shorten:
                link = g.shorten(data['permalink'])['id']
            else:
                link = data['permalink']
            metafields['Link'] = link
            for f in metafields:
                col = green
                if f == 'Detection ratio':
                    col = c
                metatable.add_row([colorize(colorize(f, blue), bold),
                                   colorize(str(metafields[f]), col)])
            metatable.align = "l"
            metatable.header = False
            print metatable
            scans = data['scans']
            scanstable = PrettyTable(colorize(colorize(['Engine',
                                                        'Detected',
                                                        'Result',
                                                        'Detail'],
                                              blue), bold))
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
                if detected:
                    scanstable.add_row(colorize([engine,
                                                 detected,
                                                 result,
                                                 detail], red))
                else:
                    scanstable.add_row(colorize([engine,
                                                 detected,
                                                 result,
                                                 detail], green))
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
                        metatable.add_row([colorize(colorize(f, blue), bold),
                                           colorize(str(metafields[f]),
                                                    green)])
                    metatable.align = "l"
                    metatable.header = False
                    print metatable
            elif arguments['domain']:
                headtype = 'IP address'
                headtype2 = 'ip_address'
                cattable = PrettyTable(colorize(colorize(['Categories'],
                                                         blue), bold))
                for c in data['categories']:
                    cattable.add_row([colorize(str(c), green)])
                cattable.align = "l"
                print cattable
                if 'WOT domain info' in data:
                    print 'WOT domain info'
                    w = PrettyTable()
                    for k in data['WOT domain info']:
                        w.add_row([colorize(colorize(str(k), blue), bold),
                                   colorize(str(data['WOT domain info'][k]),
                                   green)])
                    w.align = "l"
                    w.header = False
                    print w
                if 'subdomains' in data:
                    subtable = PrettyTable(colorize(colorize(['Subdomains'],
                                                             blue), bold))
                    for s in data['subdomains']:
                        subtable.add_row([colorize(str(s), green)])
                    subtable.align = "l"
                    print subtable
                whoistable = PrettyTable(colorize(colorize(['Whois lookup'],
                                                           blue), bold))
                whoistable.add_row([data['whois']])
                whoistable.align = "l"
                print whoistable
            if len(data['resolutions']) > 0:
                print 'Resolutions {0}'.format(len(data['resolutions']))
                restable = PrettyTable(colorize(colorize([headtype,
                                                         'Last resolved'],
                                                         blue), bold))
                for ip in data['resolutions']:
                    restable.add_row(colorize([ip[headtype2],
                                               ip['last_resolved']], green))
                restable.align = "l"
                print restable
            if len(data['detected_urls']) > 0:
                print 'URLs {0}'.format(len(data['detected_urls']))
                urltable = PrettyTable(colorize(colorize(['Analysis date',
                                                          'Detection ratio',
                                                          'URL'], blue), bold))
                for u in data['detected_urls']:
                    adate = u['scan_date']
                    positives = u['positives']
                    total = u['total']
                    url = u['url']
                    ratio = '{0}/{1}'.format(positives, total)
                    if int(positives) > (int(total) / 2):
                        c = red
                    else:
                        c = green
                    urltable.add_row(colorize([adate, ratio, url], c))
                urltable.align = "l"
                print urltable
            if 'detected_referrer_samples' in data:
                print 'Detected referrer samples {0}'.format(
                      len(data['detected_referrer_samples']))
                dreftable = PrettyTable(colorize(colorize(['SHA256',
                                                           'Detection ratio'],
                                                 blue), bold))
                for dref in data['detected_referrer_samples']:
                    positives = dref['positives']
                    total = dref['total']
                    ratio = '{0}/{1}'.format(positives, total)
                    shahash = dref['sha256']
                    if int(positives) > (int(total) / 2):
                        c = red
                    else:
                        c = green
                    dreftable.add_row(colorize([shahash, ratio], c))
                dreftable.align = "l"
                print dreftable
            if 'detected_downloaded_samples' in data:
                print 'Detected downloaded samples {0}'.format(
                      len(data['detected_downloaded_samples']))
                ddowntable = PrettyTable(colorize(colorize(['Analysis date',
                                                            'SHA256',
                                                            'Detection ratio'],
                                                  blue), bold))
                for ddown in data['detected_downloaded_samples']:
                    adate = ddown['date']
                    positives = ddown['positives']
                    total = ddown['total']
                    ratio = '{0}/{1}'.format(positives, total)
                    shahash = ddown['sha256']
                    if int(positives) > (int(total) / 2):
                        c = red
                    else:
                        c = green
                    ddowntable.add_row(colorize([adate, shahash, ratio], c))
                ddowntable.align = "l"
                print ddowntable
            if 'detected_communicating_samples' in data:
                print 'Detected communicating samples {0}'.format(
                      len(data['detected_communicating_samples']))
                dcommtable = PrettyTable(colorize(colorize(['Analysis date',
                                                            'SHA256',
                                                            'Detection ratio'],
                                                  blue), bold))
                for dcomm in data['detected_communicating_samples']:
                    adate = dcomm['date']
                    positives = dcomm['positives']
                    total = dcomm['total']
                    ratio = '{0}/{1}'.format(positives, total)
                    shahash = dcomm['sha256']
                    if int(positives) > (int(total) / 2):
                        c = red
                    else:
                        c = green
                    dcommtable.add_row(colorize([adate, shahash, ratio], c))
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
            metatable.add_row([colorize(colorize(f, blue), bold),
                               colorize(str(metafields[f]), green)])
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
        elif a['sha256']:
            print gethash(a['<file>'])
        elif a['signature']:
            print getsignature(a['<file>'])
        else:
            exit(1)


if __name__ == '__main__':
    arguments = docopt(__doc__, version='vtc.py 1.0')
    main(arguments)
