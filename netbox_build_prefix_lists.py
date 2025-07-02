#!/usr/bin/env python3

"""
This  connects to my Netbox and builds a set of prefix lists.
It relied on the custom field 'prefix_list_names' in Netbox to determine which
prefixes to include in which prefix lists.

Note: If the "type" of the entry is "ip-address", it will be converted to a
/32 or /128 prefix, depending on whether it is IPv4 or IPv6.
If the type is "prefix" or "aggregate", it will be left as is.

It will output the prefix list information in both an Aerleon style YAML file, as
well as a JUNOS style .j2 file. This initially seems redundant, but it turns out
that we need this information both toe build ACLs (e.g. in Aerleon) and
to build prefix lists in JUNOS (e.g. for BGP).

It uses Authelia to login to Netbox, because I don't really want to
just expose my Netbox API token to the world.
"""

from enum import Enum
import argparse
import coloredlogs
import json
import logging
import os
import pynetbox
import requests
import sys
import yaml

# This expects a configuration fille. By default it is ~/.credentials_netbox.json
# It should contain a JSON object with the following format
# {
#   "server": "netbox.example.com,
#   "token": "your_nextbox_api_token",
#   "authelia_server": "authelia.example.com",
#   "authelia_login_url": "https://authelia.example.com/api/firstfactor"
#   "username": "your_username",
#   "password": "your_password"
# }


# Debug. If True then we print more stuff.
DEBUG = False

# Credential file for Authelia
CREDENTIALS_FILE = "~/.credentials_netbox.json"

# The payload we send to Authelia
PAYLOAD_TEMPLATE = """{{"username": "{username}", \
  "password": "{password}", "keepMeLoggedIn": false, \
  "targetURL": "https://netbox.kumari.net/api",
  "requestMethod": "GET"}}"""

# Output file for the prefix lists
# This is a JUNOS style file.
# It will be written to the current directory.
OUTPUT_FILE = "NETBOX_PREFIX_LISTS.j2"


class PrefixType(Enum):
    """Enum for the type of prefix."""

    UNKNOWN = 0
    IP_ADDRESS = 1
    PREFIX = 2
    AGGREGATE = 3


class Prefix:
    """Class to hold a prefix and its associated data."""

    def __init__(self):
        """Initialize the Prefix object."""
        self.type = PrefixType.UNKNOWN  # Type of prefix (IP, prefix, aggregate)
        self.v4v6 = None  # IPv4 or IPv6
        self.ip = None
        self.device = None
        self.interface = None
        self.dns = None
        self.desc = None
        self.tags = []
        self.custom_fields = None
        self.prefix_lists = {}  # List of prefix lists to add this prefix to.

    def __str__(self):
        return (
            f"Prefix(ip={self.ip}, device={self.device}, "
            f"interface={self.interface}, dns={self.dns}, "
            f"descr={self.descr}, tags={self.tags}, "
            f"custom_fields={self.custom_fields}, "
            f"prefix_lists={self.prefix_lists})"
        )

    def format_comment(self):
        """Format the comment for the prefix."""
        have_info = False
        comment = ""
        # Format the address and comment.
        if self.dns:
            comment += "[ %s ] " % self.dns
            have_info = True
        if self.device:
            comment += "%s" % self.device
            have_info = True
        if self.interface:
            comment += ":%s " % self.interface
            have_info = True
        if self.descr:
            if have_info:
                comment += "--"
            comment += " %s " % self.descr
        else:
            if not have_info:
                comment += " No description and no info "
        return comment


class Config:
    """Class to hold the information from the credentials file.

    This is just to encapsulate the information and not have a very long list
    of returns values from the get_credentials function."""

    def __init__(self):
        """Initialize the Config object."""
        self.netbox_server = None
        self.netbox_token = None
        self.use_authelia = False
        self.authelia_login_url = None
        self.authelia_username = None
        self.authelia_password = None


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
    logging.critical("Aborting: %s", msg)
    sys.exit(-1)


def ParseOptions(arg_list: list[str] | None):
    """Parses the command line options."""

    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        default=DEBUG,
        help="Debug output.",
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
        default=OUTPUT_FILE,
        help=f"""File to write the prefix lists to. This is a JUNOS style file.
        Default: {OUTPUT_FILE}""",
    )

    parser.add_argument(
        "-y",
        "--no-yaml",
        dest="yaml",
        action="store_false",
        default=True,
        help="""Output the prefix lists in YAML format.""",
    )
    parser.add_argument(
        "-j",
        "--j2",
        dest="j2",
        action="store_true",
        default=False,
        help="""Output the prefix lists in .j2 (text) format.""",
    )
    parser.add_argument(
        "-c",
        "--credentials",
        dest="credentials",
        default="~/.netbox_credentials.json",
        help="""Path to the credentials file (JSON) to use for authentication.
        Default: ~/.netbox_credentials.json""",
    )

    return parser.parse_args(arg_list)


def get_credentials(filename):
    """Get the username and password from the config file."""
    config = Config()
    # Expand the user directory if needed.
    filename = os.path.expanduser(filename)
    try:
        with open(filename, "r") as jsonfile:
            data = json.load(jsonfile)
            config.netbox_server = data["server"]
            config.netbox_token = data["token"]
            if "authelia" in data:
                print("Using Authelia for authentication.")
                config.authelia_login_url = data["authelia"]["authelia_login_url"]
                config.authelia_username = data["authelia"]["username"]
                config.authelia_password = data["authelia"]["password"]

    except IOError as e:
        abort(e)
    except (ValueError, KeyError) as e:
        abort(
            'JSON object %s could be decoded from file: %s\n \
      Expected: {"username":"bob", "password": "Hunter2"}'
            % (e, filename)
        )
    return config


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
        url = entry.get("url", None)
        if not url:
            logging.warning("Skipping entry with no URL: %s" % entry)
            continue
        match url:
            case url if "/api/ipam/aggregates/" in url:
                prefix.type = PrefixType.AGGREGATE
            case url if "/api/ipam/prefixes/" in url:
                prefix.type = PrefixType.PREFIX
            case url if "/api/ipam/ip-addresses/" in url:
                prefix.type = PrefixType.IP_ADDRESS
            case _:
                logging.warning("Unknown prefix type for URL: %s" % url)
                prefix.type = PrefixType.UNKNOWN
                continue
        prefix.ip = entry.get("address", None)
        if not prefix.ip:
            prefix.ip = entry.get("prefix", None)
        if not prefix.ip:
            # If the entry has no address, skip it.
            logging.warning("Skipping entry with no address: %s" % entry)
            continue
        # Fixup the IP addresses. If it is an IP, make it a /32 or /128.
        if prefix.type == PrefixType.IP_ADDRESS:
            family = entry.get("family", None)
            if family["value"] == 4:
                prefix.ip += "/32"
                ip = prefix.ip.split("/")[0]
                prefix.ip = f"{ip}/32"
            elif family["value"] == 6:
                prefix.ip += "/128"
                ip = prefix.ip.split("/")[0]
                prefix.ip = f"{ip}/128"
            else:
                logging.warning(
                    "Unknown family for IP address %s: %s. Skipping entry."
                    % (prefix.ip, family)
                )
                continue
        assigned_object = entry.get("assigned_object", None)
        if assigned_object:
            # If the assigned object is a device, set the device and interface.
            if assigned_object.get("device", None):
                prefix.device = assigned_object["device"]["name"]
            if assigned_object.get("name", None):
                prefix.interface = assigned_object["name"]
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


def connect_to_netbox(config):
    """Connect to the Netbox server."""
    # Create a session to use for all requests
    session = requests.Session()

    if config.authelia_login_url:
        logging.debug(
            "Using Authelia for authentication - %s" % config.authelia_login_url
        )
        payload = PAYLOAD_TEMPLATE.format(
            username=config.authelia_username, password=config.authelia_password
        )

        # Get a cookie from Authelia
        logging.debug("Connecting to %s" % config.authelia_login_url)
        post = session.post(config.authelia_login_url, data=payload)
        if post.status_code != 200:
            abort("Authelia login failed: %s" % post.text)
        logging.debug("Logged in through %s" % config.authelia_login_url)

    logging.debug("Connecting to %s" % config.netbox_server)
    nb = pynetbox.api("https://" + config.netbox_server, token=config.netbox_token)
    nb.http_session = session
    logging.debug("Connected to %s" % config.netbox_server)
    return nb


def get_prefixes_from_netbox(nb):
    """Command to get IP addresses, prefixes and aggregates from Netbox."""

    prefixes = []
    logging.info("Getting IP addresses from Netbox. Server: %s" % nb.base_url)
    addrs = nb.ipam.ip_addresses.all()  # (tag="filter")
    for addr in addrs:
        prefixes.append(addr)
    logging.info("Getting prefixes from Netbox. Server: %s" % nb.base_url)
    addrs = nb.ipam.prefixes.all()  # (tag="filter")
    for addr in addrs:
        prefixes.append(addr)
    logging.info("Getting aggregates from Netbox. Server: %s" % nb.base_url)
    aggregates = nb.ipam.aggregates.all()
    for agg in aggregates:
        prefixes.append(agg)
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
    logging.info
    ("Dumped JSON to file %s" % outfile)


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


def build_yaml_structure(prefix_list_dict):
    """Build a YAML structure from the prefix list dictionary."""
    yaml_structure = {"networks": {}}
    for prefix_list_name, prefixes in prefix_list_dict.items():
        prefix_list_name = "NB_" + prefix_list_name
        prefix_list = {"values": []}
        for prex in prefixes:
            # Create a dictionary for each prefix with its details.
            prefix_info = {
                "address": prex.ip,
                "comment": prex.format_comment(),
            }
            prefix_list["values"].append(prefix_info)
        yaml_structure["networks"][prefix_list_name.upper()] = prefix_list
    return yaml_structure


def write_prefix_list_file(prefix_list_dict, filename):
    """Writes a JUNOS style prefix list file."""
    header_str = "    prefix-list {} {{\n"
    comment_str = "        {}\n"
    address_str = "        {};\n"
    footer_str = "    }\n\n"

    file_header = """
/*
 * The below was auto-generated by netbox_build_prefix_lists.py on {date}.
 * To update the prefix lists, run netbox_build_prefix_lists.py again.
 *
 * This is built from Netbox prefixes with the custom field 'prefix_list_names'.
 * Each prefix list is named after the prefix list name in Netbox.
 * The format is:
 *   prefix-list <name> {{
 *       /* <dns> - <device>:<interface>  -- <description> */
 *       <address>;
 *   }}
 *
 */
"""

    file_footer = """/*
 * End of auto-generated prefix-lists.
 */
"""

    if len(prefix_list_dict.keys()) == 0:
        abort("No prefix lists to write, skipping file creation.")
        return

    with open(filename, "w") as f:
        str = file_header.format(date=os.popen("date").read().strip())
        f.write(str)
        for prefix_list, prefixes in sorted(prefix_list_dict.items()):
            f.write(header_str.format(prefix_list.upper()))
            for prex in prefixes:
                have_info = False
                comment = "/* "
                # Format the address and comment.
                address = prex.ip

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

    config = get_credentials(args.credentials)
    if not config.netbox_server:
        abort("No Netbox server specified in credentials file: %s" % args.credentials)
    if not config.netbox_token:
        abort("No Netbox token specified in credentials file: %s" % args.credentials)

    prefixes = []

    # token = util_token.get_token(args.server)

    if args.infile:
        # If we have an input file, read the prefixes from it.
        prefixes = get_prefixes_from_file(args.infile)

    else:
        # If we don't have an input file, get the prefixes from Netbox.
        nb = connect_to_netbox(config)
        if not nb:
            abort("Could not connect to Netbox server: %s" % config.netbox_server)
        logging.debug("Connected to Netbox server: %s" % config.netbox_server)

        prefixes = get_prefixes_from_netbox(nb)

    if args.dumpfile:
        # If we have an output file, write the prefixes to it.
        logging.debug("Writing prefixes to file: %s" % args.dumpfile)
        dump_prefixes_to_file(prefixes, args.dumpfile)
        logging.info("Wrote %d prefixes to file" % len(prefixes))
        logging.debug("Exiting after writing prefixes to file")
        sys.exit(1)

    logging.debug("Found %d prefixes" % len(prefixes))
    prefix_list_list = parse_prefixes(prefixes)
    prefix_list_dict = build_prefix_list_dict(prefix_list_list)

    if args.j2:
        write_prefix_list_file(prefix_list_dict, args.outfile)
    elif args.yaml:
        yaml_structure = build_yaml_structure(prefix_list_dict)
        yaml_file = args.outfile.replace(".j2", ".yaml")
        with open(yaml_file, "w") as f:
            yaml.dump(yaml_structure, f, indent=2)
        logging.info(
            "Wrote %d prefix lists containing %d entries to %s"
            % (
                len(yaml_structure["networks"]),
                sum(
                    [
                        len(yaml_structure["networks"][c]["values"])
                        for c in yaml_structure["networks"]
                    ]
                ),
                yaml_file,
            )
        )
    else:
        abort("No output format specified. Use -j for J2 or -y for YAML.")


if __name__ == "__main__":
    main()
    sys.exit(0)
