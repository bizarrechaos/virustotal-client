#! /usr/bin/env python
"""vtc.py

Usage:
  vtc.py [options] init <apikey>
  vtc.py [options] report (file|hash|url|ip|domain) <resource>
  vtc.py [options] scan (file [--rescan]|url) <resource>

Options:
  -a KEY, --api-key KEY   This will override the api key in the config file.
  -h, --help              Show this screen.
  -v, --version           Show version.
"""
import hashlib
import os
import json

import ConfigParser

from docopt import docopt

from virustotal import *


def jprint(jsondoc):
    print json.dumps(jsondoc, sort_keys=True, indent=2, separators=(',', ': '))


def gethash(path):
    return hashlib.sha256(open(path, 'rb').read()).hexdigest()


def createconfig(apikey):
    HOME = os.path.expanduser('~')
    CONFIG = HOME + '/.vtc.cfg'
    parser = ConfigParser.SafeConfigParser()
    parser.add_section('virustotal')
    parser.set('virustotal', 'apikey', apikey)
    with open(CONFIG, 'w') as fout:
        parser.write(fout)


def readconfig():
    HOME = os.path.expanduser('~')
    CONFIG = HOME + '/.vtc.cfg'
    parser = ConfigParser.SafeConfigParser()
    parser.read(CONFIG)
    return parser.get('virustotal', 'apikey')


def output(data):
    jprint(data)


def main(a):
    if a['init']:
        createconfig(a['<apikey>'])
    else:
        if a['--api-key'] is not None:
            key = a['--api-key']
        else:
            key = readconfig()
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
