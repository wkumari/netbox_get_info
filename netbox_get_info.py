#!/usr/bin/env python

"""
This small program connects to my Netbox and pulls information, suitable for
use in Ansible.
"""

from colored import stylize
from optparse import OptionParser
import colored
import json
import pynetbox
import sys
import util_token

# Debug. If True then we print more stuff.
DEBUG = False

SERVER='netbox.kumari.net'

class Error(Exception):
    """Generic error."""

class TemplateError(Error):
    """Netbox Info Error"""

def debug(msg):
    """Iff DEBUG then we print message."""
    if opts.debug:
        sys.stderr.write(stylize('DEBUG: %s\n' % msg,
            colored.fg("light_magenta")))

def log(msg):
    """If --verbose, print the message"""
    if opts.verbose or opts.debug:
        sys.stderr.write(stylize('LOG: %s\n' % msg,
            colored.fg("blue") + colored.attr("bold")))

def abort(msg):
    """Print error message and abort"""
    sys.stderr.write(stylize('ABORT: %s\n' % msg,
        colored.fg("red") + colored.attr("bold")))
    sys.exit(-1)

def output(msg):
    """Simply prints the message provided."""
    sys.stdout.write('%s\n' % msg)

def ParseOptions():
    """Parses the command line options."""
    global opts, args
    usage = """%prog [-v, -d ]

  This connects to my netbox server and gets various information.
  It is intended to be used by Ansible.

  Usage:

	%prog <command>

  The commands are:
    bgp           Get prefixes tagged with 'BGP', output prefix, description
    targets       Get IP addresses tagged with 'Ping'. These are for ping targets

  Example:
      %prog bgp

  192.0.2.1/32,"Example BGP Prefix"
  """

    options = OptionParser(usage=usage)
    options.add_option('-v', '--verbose', dest='verbose',
                      action='store_true',
                      default=False,
                      help='Be more verbose in output.')
    options.add_option('-d', '--debug', dest='debug',
                      action='store_true',
                      default=DEBUG,
                      help='Debug output.')
    options.add_option('-p', '--plain', dest='plain',
                      action='store_true',
                      default=False,
                      help='''Plain output instead of JSON.''')
    options.add_option('-s', '--server', dest='server',
                      default=SERVER,
                      help='''The name of the netbox server.
                        Expects a file ~/.token_<server> containing the token.''')


    (opts, args) = options.parse_args()
    if not args:
      options.print_usage()
      sys.exit(1)
    return opts, args


def cmd_bgp(nb):
  '''Command to get BGP prefixes'''
  prefixes = []
  bgp_prefixes = nb.ipam.prefixes.filter(tag='bgp')
  for prefix in bgp_prefixes:
    if opts.plain:
      output('%s,"%s"' % (prefix.prefix, prefix.description))
      return
    network = {}
    network["prefix"] = prefix.prefix
    network["description"] = prefix.description
    if prefix.custom_fields["announced_from"]:
      network["announced_from"] = prefix.custom_fields["announced_from"]
    prefixes.append(network)
  print (json.dumps(prefixes, indent=2))


def cmd_targets(nb):
  '''Command to get ping targets'''
  addresses = []
  addrs = nb.ipam.ip_addresses.filter(tag='ping')
  for addr in addrs:
    # Remove prefix length, if any.
    ip = addr.address
    if '/' in ip:
      ip = ip.split('/')[0]

    object = addr.assigned_object
    desc = "[%s - %s] %s" % (object.device.name, object.name, addr.description)
    if opts.plain:
      output('%s,"%s"' % (ip, desc))
      return
    address = {}
    address["address"] = ip
    address["description"] = desc
    addresses.append(address)
  print (json.dumps(addresses, indent=2))

def main():
    """pylint FTW"""
    token = util_token.get_token(opts.server)

    debug('Connecting to %s' % opts.server)
    nb = pynetbox.api('https://'+opts.server, token=token)
    debug('Connected to %s' % opts.server)

    if args[0] == 'bgp':
        cmd_bgp(nb)
        return
    if args[0] == 'targets':
        cmd_targets(nb)
        return
    else:
        abort('Unknown command: %s' % args[0])


if __name__ == "__main__":
    ParseOptions()
    main()
    sys.exit(0)
