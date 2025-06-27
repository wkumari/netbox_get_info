#!/usr/bin/env python3


from collections import namedtuple
from netbox_build_prefix_lists import *
from types import SimpleNamespace
from unittest.mock import Mock, patch
import json
import pynetbox
import unittest
import shlex


TEST_PREFIXES_FILE = "./test_data/test_ip_prefixes.json"
TEST_CREDENTIALS_FILE = "./test_data/test_credentials.json"


# Test harness stuff...
def read_json_data(filename):
    prefixes = []
    try:
        with open(filename, "r") as jsonfile:
            data = json.load(jsonfile)
    except IOError as e:
        abort(e)
    for entry in data:

        # json.loads() does not actually read the json output from Netbox.
        # Specifically, we need to replace single quotes with double quotes and
        # convert None, True, and False to their JSON equivalents. This is
        # because the Netbox API returns a list of objects, not dictionaries.
        # If the entry is already a dictionary, this will do nothing.
        if not isinstance(entry, str):
            entry = json.dumps(entry)

        entry = str(entry)
        # Replace single quotes with double quotes
        entry = entry.replace("'", '"')
        # Replace None with null for JSON compatibility
        entry = entry.replace("None", "null")
        # Replace True with true for JSON compatibility
        entry = entry.replace("True", "true")
        # Replace False with false for JSON compatibility
        entry = entry.replace("False", "false")
        # Attributes cannot start with an underscore in JSON
        entry = entry.replace("_occupied", "occupied")

        prefix = json.loads(
            entry, object_hook=lambda d: namedtuple("Prefix", d.keys())(*d.values())
        )
        prefixes.append(prefix)
    return prefixes


def test_prefixes_from_file(filename):
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


class TestUtilityFunctions(unittest.TestCase):
    def test_get_credentials(self):
        (user, password) = get_credentials(TEST_CREDENTIALS_FILE)
        self.assertEqual(user, "testuser")
        self.assertEqual(password, "testpassword")

    def test_ParseOptions(self):
        cli_opts = shlex.split("-d --nologin --server http://localhost:8000")
        args = ParseOptions(cli_opts)
        self.assertEqual(args.server, "http://localhost:8000")
        self.assertTrue(args.nologin)
        self.assertTrue(args.debug)


class TestGetPrefixes(unittest.TestCase):
    # Note: This test assumes that the test data in TEST_PREFIXES_FILE is structured correctly
    # and contains the expected fields for the prefixes.
    # It does not test the actual connection to a Netbox instance,
    # but rather mocks the Netbox API call to return predefined data.
    def setUp(self):
        self.prefix_array = test_prefixes_from_file(TEST_PREFIXES_FILE)

    def test_get_prefixes_from_netbox(self):

        # We mock the pynetbox API call to return our test data
        netbox_mock = Mock()
        # We are using nb.ipam.ip_addresses.all, but mock filter in case we use it.
        netbox_mock.ipam.ip_addresses.filter.return_value = self.prefix_array
        netbox_mock.ipam.ip_addresses.all.return_value = self.prefix_array

        self.assertEqual(len(get_prefixes_from_netbox(netbox_mock)), 2)


class TestPrefixes(unittest.TestCase):
    def setUp(self):
        # self.prefix_array = read_json_data(TEST_PREFIXES_FILE)
        self.prefix_array = get_prefixes_from_file(TEST_PREFIXES_FILE)

    def test_parse_prefixes(self):
        parsed_prefixes = parse_prefixes(self.prefix_array)
        self.assertEqual(
            len(parsed_prefixes), 2
        )  # Assuming there are 2 prefixes in the test data
        self.assertEqual(parsed_prefixes[0].ip, "10.72.69.1/24")

    def build_prefix_list_dict(self):
        prefix_list = build_prefix_list_dict(self.prefix_array)
        self.assertIsInstance(prefix_list, dict)
        self.assertIn("BASTIONS", prefix_list)
        self.assertEqual(len(prefix_list["BASTIONS"]), 1)
        self.assertEqual(prefix_list["BASTIONS"][0].ip, "10.72.69.1/24")


if __name__ == "__main__":
    unittest.main()
