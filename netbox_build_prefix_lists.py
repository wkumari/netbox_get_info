#!/usr/bin/env python3

"""
This small program connects to my Netbox and builds a set of prefix lists.
This relies on 'tags' in Netbox. If an IP is tagged with 'filter', it will be
added to prefix-lists according to the other tags.

It uses Authelia to login to Netbox. This is because I don't really want to
just expose my Netbox API token to the world.
"""

import argparse
import coloredlogs
import json
import logging
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


class Prefix:
    ip = None
    device = None
    interface = None
    dns = None
    desc = None
    tags = []
    custom_fields = None
    prefix_lists = {}  # List of prefix lists to add this prefix to.

    def __str__(self):
        return (
            f"Prefix(ip={self.ip}, device={self.device}, "
            f"interface={self.interface}, dns={self.dns}, "
            f"descr={self.descr}, tags={self.tags}, "
            f"custom_fields={self.custom_fields}, "
            f"prefix_lists={self.prefix_lists})"
        )


# A dictionary of prefix-filter name [ Prefix ]
# E.g: prefixes["BASTIONS"][{ip:"192.168.1.1", device:"rtr1.iad", ...}]
prefixes = {}


# Base class for all exceptions
class Error(Exception):
    """Generic error."""


class TemplateError(Error):
    """Netbox Info Error"""


def abort(msg):
    """Print error message and abort"""
    logging.critical("Aborting: %s" % msg)
    sys.exit(-1)


def ParseOptions(arg_list: list[str] | None):
    """Parses the command line options."""
    usage = """%prog [-v, -d ]

  This connects to my netbox server, pulls IPs / prefixes which have a custom
  field 'prefix_list_names' and builds a prefix list file from them.

  Usage:

	%prog <command>

  Example:
      %prog -s netbox.kumari.net

  192.0.2.1/32,"Example BGP Prefix"
  """

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        default=DEBUG,
        help="Debug output.",
    )
    parser.add_argument(
        "-n",
        "--nologin",
        dest="nologin",
        action="store_true",
        default=False,
        help="""Do not login through Authelia.""",
    )
    parser.add_argument(
        "-l",
        "--limit",
        dest="limit",
        default="",
        help="""The tag to filter (e.g: BASTIONS)""",
    )
    parser.add_argument(
        "-w",
        "--write",
        dest="dumpfile",
        default="",
        help="""File to dump (JSON) prefixes to. This is used so I can download
        the prefixes and e.g play with them on a plane, or to build test data.""",
    )
    parser.add_argument(
        "-r",
        "--read",
        dest="infile",
        default="",
        help="""File to read prefixes from. This is used to play without hitting
        the netbox server itself (e.g on a plane).""",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="outfile",
        default="GENERATED_PREFIX_LISTS.j2",
        help="""File to write the prefix lists to. This is a JUNOS style file.""",
    )
    parser.add_argument(
        "-s",
        "--server",
        dest="server",
        default=SERVER,
        help="""The name of the netbox server.
                  Expects a file ~/.token_<server> containing the token.""",
    )

    args = parser.parse_args(arg_list)
    return args


def get_credentials(filename):
    """Get the username and password from the config file."""
    filename = os.path.expanduser(filename)
    try:
        with open(filename, "r") as jsonfile:
            data = json.load(jsonfile)
            username: str = data["username"]
            password: str = data["password"]
    except IOError as e:
        abort(e)
    except (ValueError, KeyError) as e:
        abort(
            'JSON object %s could be decoded from file: %s\n \
      Expected: {"username":"bob", "password": "Hunter2"}'
            % (e, filename)
        )
    return username, password


def parse_prefixes(prefixes):
    """Parse the prefixes from the Netbox API."""
    parsed_prefixes = []
    for entry in prefixes:
        # Convert the entry to a dictionary if it is not already one.
        # This is because the Netbox API returns a list of objects, not dictionaries.
        # If the entry is already a dictionary, this will do nothing.
        if not isinstance(entry, dict):
            entry = dict(entry)

        # Convert the entry to a Prefix object
        prefix = Prefix()
        prefix.ip = entry["address"]
        prefix.device = entry.get("device", None)
        prefix.interface = entry.get("interface", None)
        prefix.dns = entry.get("dns_name", None)
        prefix.descr = entry.get("description", None)
        prefix.tags = entry.get("tags", [])
        prefix.custom_fields = entry.get("custom_fields")

        if (
            "prefix_list_names" in prefix.custom_fields
            and prefix.custom_fields["prefix_list_names"] is not None
        ):
            prefix.prefix_lists = prefix.custom_fields["prefix_list_names"]
        parsed_prefixes.append(prefix)
    return parsed_prefixes


def build_prefix_list_dict(prefixes):
    """Build a dictionary of prefix lists from the prefixes."""
    prefix_list_dict = {}
    for prex in prefixes:
        # If the prefix has no prefix lists, skip it.
        if not prex.prefix_lists:
            continue

        # For each prefix list, add the prefix to it.
        for prefix_list in prex.prefix_lists:
            if prefix_list not in prefix_list_dict:
                prefix_list_dict[prefix_list] = []
            prefix_list_dict[prefix_list].append(prex)
    return prefix_list_dict


def connect_to_netbox(server, token):
    """Connect to the Netbox server."""
    # Create a session to use for all requests
    session = requests.Session()

    if not args.nologin:
        (username, password) = get_credentials(CREDENTIALS_FILE)

        payload = PAYLOAD_TEMPLATE.format(username=username, password=password)

        # Get a cookie from Authelia
        logging.debug("Connecting to %s" % LOGIN_URL)
        post = session.post(LOGIN_URL, data=payload)
        if post.status_code != 200:
            abort("Authelia login failed: %s" % post.text)
        logging.debug("Logged in through %s" % LOGIN_URL)

    logging.debug("Connecting to %s" % args.server)
    nb = pynetbox.api("https://" + args.server, token=token)
    nb.http_session = session
    logging.debug("Connected to %s" % args.server)
    return nb


def get_prefixes_from_netbox(nb):
    """Command to get prefixes from Netbox."""

    # This used to also parse the prefixes, but now it just returns
    # the prefixes with the tag 'filter'.
    # This was done to make testing of the code easier.
    logging.debug("Getting prefixes from Netbox")
    prefixes = []
    addrs = nb.ipam.ip_addresses.all()  # (tag="filter")
    for addr in addrs:
        prefixes.append(addr)
    return prefixes


def dump_prefixes_to_file(prefixes, outfile):
    """Command to dump prefixes to a JSON file. Used for testing."""
    all = []
    for addr in prefixes:
        addr_dict = dict(addr)
        all.append(addr_dict)
    with open(outfile, "w") as jsonfile:
        json.dump(
            all,
            jsonfile,
            indent=2,
            default=str,
        )
    print("Dumped JSON to file %s" % outfile)


def get_prefixes_from_file(filename):
    logging.debug("Reading prefixes from file: %s" % filename)
    try:
        with open(filename, "r") as jsonfile:
            prefixes = json.load(jsonfile)
            logging.debug("Read %d prefixes from file" % len(prefixes))
    except IOError as e:
        abort(e)
    except ValueError as e:
        abort("Could not decode JSON from file: %s" % e)
    return prefixes


def write_prefix_list_files(prefix_list_dict):
    """Build the prefix lists from the prefix list dictionary."""
    for prefix_list, prefixes in prefix_list_dict.items():
        logging.info("Building prefix list: %s" % prefix_list)
        with open(prefix_list + "-prefix.j2", "w") as f:
            for prex in prefixes:
                f.write(
                    "%s,%s,%s,%s\n" % (prex.ip, prex.device, prex.interface, prex.descr)
                )
        logging.info("Wrote %d prefixes to %s-prefix.j2" % (len(prefixes), prefix_list))


def write_prefix_list_file(prefix_list_dict, filename):
    """Writes a JUNOS style prefix list file."""
    header_str = "    prefix-list {} {{\n"
    comment_str = "        {}\n"
    address_str = "        {};\n"
    footer_str = "    }\n\n"

    file_header = """
/*
# The below was auto-generated by netbox_build_prefix_lists.py on {date}.
# To update the prefix lists, run netbox_build_prefix_lists.py again.
#
# This is built from Netbox prefixes with the custom field 'prefix_list_names'.
# Each prefix list is named after the prefix list name in Netbox.
# The format is:
#   prefix-list <name> {{
#       /* <dns> - <device>:<interface>  -- <description> */
#       <address>;
#   }}
#
*/
"""

    file_footer = """/*
# End of auto-generated prefix-lists.
*/
"""

    if len(prefix_list_dict.keys()) == 0:
        abort("No prefix lists to write, skipping file creation.")
        return

    with open(filename, "w") as f:
        str = file_header.format(date=os.popen("date").read().strip())
        f.write(str)
        for prefix_list, prefixes in prefix_list_dict.items():
            f.write(header_str.format(prefix_list.upper()))
            for prex in prefixes:
                have_info = False
                comment = "/* "
                # Format the address and comment.
                address = prex.ip
                if address == "192.108.73.74/26":
                    logging.warning("Dump prefix %s" % prex)
                if prex.dns:
                    comment += "[ %s ] " % prex.dns
                    have_info = True
                if prex.device:
                    comment += "%s" % prex.device
                    have_info = True
                if prex.interface:
                    comment += ":%s " % prex.interface
                    have_info = True
                if prex.descr:
                    if have_info:
                        comment += "--"
                    comment += " %s " % prex.descr
                else:
                    if not have_info:
                        comment += " No description and no info "
                comment += "*/"
                f.write(comment_str.format(comment))
                f.write(address_str.format(address))
            f.write(footer_str)
        f.write(file_footer)
        f.close()


def main(arg_list: list[str] | None = None):
    """pylint FTW"""

    global args
    args = ParseOptions(arg_list)

    # Default logging level.
    coloredlogs.install(
        fmt="%(asctime)s %(module)s.%(lineno)-04d %(levelname)-8s: %(message)s",
        datefmt="%H:%M:%S",
    )
    if args.debug:
        coloredlogs.set_level("DEBUG")

    prefixes = []

    token = util_token.get_token(args.server)

    if args.infile:
        # If we have an input file, read the prefixes from it.
        prefixes = get_prefixes_from_file(args.infile)

    else:
        # If we don't have an input file, get the prefixes from Netbox.
        nb = connect_to_netbox(args.server, token)
        if not nb:
            abort("Could not connect to Netbox server: %s" % args.server)
        logging.debug("Connected to Netbox server: %s" % args.server)

        prefixes = get_prefixes_from_netbox(nb)

    if args.dumpfile:
        # If we have an output file, write the prefixes to it.
        logging.debug("Writing prefixes to file: %s" % args.dumpfile)
        dump_prefixes_to_file(prefixes, args.dumpfile)
        logging.info("Wrote %d prefixes to file" % len(prefixes))
        logging.debug("Exiting after writing prefixes to file")
        sys.exit(0)

    logging.debug("Found %d prefixes" % len(prefixes))
    prefix_list_list = parse_prefixes(prefixes)
    prefix_list_dict = build_prefix_list_dict(prefix_list_list)
    # write_prefix_list_files(prefix_list_dict)
    write_prefix_list_file(prefix_list_dict, args.outfile)

    logging.info(
        "Wrote %d prefix lists to file: %s" % (len(prefix_list_dict), args.outfile)
    )


if __name__ == "__main__":
    main()
    sys.exit(0)
