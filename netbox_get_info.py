#!/usr/bin/env python3

"""
This small program connects to my Netbox and pulls information, suitable for
use in Ansible.

It uses Authelia to login to Netbox. This is because I don't really want to
just expose my Netbox API token to the world.
"""

from colored import stylize
from optparse import OptionParser
import colored
import json
import os
import pynetbox
import requests
import sys
import util_token

# Debug. If True then we print more stuff.
DEBUG = False

# The name of the netbox server.
# Expects a file ~/.token_<server> containing the token.
SERVER = "netbox.kumari.net"

# The URL of my Authelia server's login. We post here to get a cookie.
LOGIN_URL = "https://authelia.kumari.net/api/firstfactor"

# Credential file for Authelia
CREDENTIALS_FILE = "~/.credentials_authelia_netbox.json"

# The payload we send to Authelia
PAYLOAD_TEMPLATE = """{{"username": "{username}", \
  "password": "{password}", "keepMeLoggedIn": false, \
  "targetURL": "https://netbox.kumari.net/api",
  "requestMethod": "GET"}}"""


# Base class for all exceptions
class Error(Exception):
    """Generic error."""


class TemplateError(Error):
    """Netbox Info Error"""


def debug(msg):
    """Iff DEBUG then we print message."""
    if opts.debug:
        sys.stderr.write(stylize("DEBUG: %s\n" % msg, colored.fg("light_magenta")))


def log(msg):
    """If --verbose, print the message"""
    if opts.verbose or opts.debug:
        sys.stderr.write(
            stylize("LOG: %s\n" % msg, colored.fg("blue") + colored.attr("bold"))
        )


def error(msg):
    """Print error message, but don't abort.."""
    sys.stderr.write(
        stylize("ERROR: %s\n" % msg, colored.fg("red") + colored.attr("bold"))
    )


def abort(msg):
    """Print error message and abort"""
    sys.stderr.write(
        stylize("ABORT: %s\n" % msg, colored.fg("red") + colored.attr("bold"))
    )
    sys.exit(-1)


def output(msg):
    """Simply prints the message provided."""
    sys.stdout.write("%s\n" % msg)


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
    ip            Get list of IPs tagged with --tag (must add --tag!)

  Example:
      %prog bgp

  192.0.2.1/32,"Example BGP Prefix"
  """

    options = OptionParser(usage=usage)
    options.add_option(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        default=False,
        help="Be more verbose in output.",
    )
    options.add_option(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        default=DEBUG,
        help="Debug output.",
    )
    options.add_option(
        "-n",
        "--nologin",
        dest="nologin",
        action="store_true",
        default=False,
        help="""Do not login through Authelia.""",
    )
    options.add_option(
        "-p",
        "--plain",
        dest="plain",
        action="store_true",
        default=False,
        help="""Plain output instead of JSON.""",
    )
    options.add_option(
        "-t",
        "--tag",
        dest="tag",
        default="",
        help="""The tag to filter (only for 'ip' - e.g Infrastructure)""",
    )
    options.add_option(
        "-f",
        "--format",
        dest="format",
        default="",
        help="""Output format (junos, def)""",
    )
    options.add_option(
        "-s",
        "--server",
        dest="server",
        default=SERVER,
        help="""The name of the netbox server.
                        Expects a file ~/.token_<server> containing the token.""",
    )

    (opts, args) = options.parse_args()
    if not args:
        options.print_usage()
        sys.exit(1)
    if args[0] == "ip" and opts.tag == "":
        error("'ip' requires --tag option")
        options.print_usage()
        sys.exit(1)
    return opts, args


def get_credentials(filename):
    """Get the username and password from the config file."""
    filename = os.path.expanduser(filename)
    try:
        with open(filename, "r") as jsonfile:
            data = json.load(jsonfile)
            username = data["username"]
            password = data["password"]
    except IOError as e:
        abort(e)
    except (ValueError, KeyError) as e:
        abort(
            'JSON object %s could be decoded from file: %s\n \
      Expected: {"username":"bob", "password": "Hunter2"}'
            % (e, filename)
        )
    return username, password


def cmd_bgp(nb):
    """Command to get BGP prefixes"""
    prefixes = []
    bgp_prefixes = nb.ipam.prefixes.filter(tag="bgp")
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
    print((json.dumps(prefixes, indent=2)))


def cmd_targets(nb, tag="ping"):
    """Command to get ping targets"""
    addresses = []
    addrs = nb.ipam.ip_addresses.filter(tag=tag)
    for addr in addrs:
        # Remove prefix length, if any.
        ip = addr.address
        if "/" in ip:
            ip = ip.split("/")[0]

        # Build the output line
        device = "[Device]"
        descr = "[Description]"
        interface = "[Interface]"
        if addr.assigned_object is not None:
            if addr.assigned_object.device is not None:
                device = addr.assigned_object.device.name
                interface = addr.assigned_object.name
                descr = addr.description

        if opts.format == "junos":
            print("/* %s:%s - %s */" % (device, interface, descr))
            print("%s/32;" % ip)
        elif opts.format == "def":
            print("%s\t # %s:%s - %s" % (ip, device, interface, descr))
        else:
            print(
                "IP: %s, Device: %s, Interface: %s, Description: %s"
                % (ip, device, interface, descr)
            )


def main():
    """pylint FTW"""
    token = util_token.get_token(opts.server)

    # Create a session to use for all requests
    session = requests.Session()

    if not opts.nologin:
        (username, password) = get_credentials(CREDENTIALS_FILE)

        payload = PAYLOAD_TEMPLATE.format(username=username, password=password)

        # Get a cookie from Authelia
        debug("Connecting to %s" % LOGIN_URL)
        post = session.post(LOGIN_URL, data=payload)
        if post.status_code != 200:
            abort("Authelia login failed: %s" % post.text)
        debug("Logged in through %s - Cookies: %s" % (LOGIN_URL, session.cookies))

    debug("Connecting to %s" % opts.server)
    nb = pynetbox.api("https://" + opts.server, token=token)
    nb.http_session = session
    debug("Connected to %s" % opts.server)

    if args[0] == "bgp":
        cmd_bgp(nb)
        return
    if args[0] == "targets":
        cmd_targets(nb)
        return
    if args[0] == "ip":
        cmd_targets(nb, opts.tag)
        return
    else:
        abort("Unknown command: %s" % args[0])


if __name__ == "__main__":
    ParseOptions()
    main()
    sys.exit(0)
