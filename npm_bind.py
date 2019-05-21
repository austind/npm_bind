#!/usr/bin/env python2.7

""" Reads network interface info from SolarWinds NPM to create DNS entries """

import re
import getpass
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from jinja2 import Environment, FileSystemLoader
import orionsdk
import requests
import yaml


def _read_yaml_file(file_name):
    """ Reads and parses YAML file """
    with open(file_name, "r") as fh:
        file_contents = fh.read()
        parsed_yaml = yaml.load(file_contents)
    return parsed_yaml


# Read config
CONFIG = _read_yaml_file("./config/config.yaml")

# Establish SolarWinds connection
if not CONFIG['npm_user']:
    USER = getpass.getuser()
    CONFIG['npm_user'] = raw_input("Orion username [{}]: ".format(USER)) \
        or USER
if not CONFIG['npm_pass']:
    CONFIG['npm_pass'] = getpass.getpass("Orion password: ")
if not CONFIG['npm_verify_cert']:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
SWIS = orionsdk.SwisClient(CONFIG['npm_server'], CONFIG['npm_user'],
                           CONFIG['npm_pass'])

# Initialize jinja2
ENV = Environment(loader=FileSystemLoader(CONFIG['template_dir']))


def get_manual_iface(manual_iface):
    """ Returns standardized interface dict based on manual_iface """
    iface_dict = {
        'node_id': 'manual',
        'node_uri': None,
        'node_name': None,
        'node_addr': None,
        'node_fqdn': None,
        'node_class': 'Network',
        'iface_id': 'manual',
        'iface_uri': None,
        'iface_name': None,
        'iface_addr': None,
        'iface_speed': None
    }
    iface_dict.update(manual_iface)
    return iface_dict


def get_iface_list(swis=SWIS, manual_ifaces=CONFIG['npm_manual_ifaces']):
    """ Returns list of layer 3 network interfaces in all nodes. """

    with open(CONFIG['npm_query_file'], "rb") as fh:
        query = fh.read()

    orion_results = swis.query(query)
    results = orion_results['results']

    # Add manually-defined interfaces
    if manual_ifaces:
        for manual_iface in manual_ifaces:
            result = get_manual_iface(manual_iface)
            results.append(result)

    # Sanitize results
    for result in results:
        # Hostnames
        # Replace any non-alphanumeric character with dash
        # (of course, should not happen, but happens :)
        pattern = r'[^A-Za-z0-9\-]'
        result['node_name'] = re.sub(pattern, "-", result['node_name'])

        # Interface names
        # Remove any whitespace characters from interface name
        pattern = r'\s+'
        result['iface_name'] = re.sub(pattern, "", result['iface_name'])
    return results


def get_iface_speed(iface):
    """ Converts iface speed from bps to DNS-friendly string """
    speed = iface['iface_speed']
    if speed:
        speed = int(iface['iface_speed'])
    else:
        return None

    if speed < 1536000:
        return None
    elif speed == 1536000 or speed == 1544000:
        return 't1'
    else:
        prefix = speed
        suffixes = ["k", "m", "g", "t", "p"]
        i = 0
        while prefix > 100:
            prefix = prefix / 1000
            i += 1
        return "{}{}".format(prefix, suffixes[i - 1])


def get_iface_hostname(iface):
    """ Returns DNS-friendly hostname from an interface dict
        as provided by get_iface_list()

        Example input from iface dict:
            - node_name: Example-IDF1
            - iface_name: TenGigabitEthernet1/1
        Example output:
            example-idf1-te-1-1

    """
    hostname = iface['node_name'].lower()
    interface = iface['iface_name'].strip().lower()
    speed = get_iface_speed(iface)
    # TODO: Can we shorten or otherwise simplify this?
    pattern = r'^(se|sc|fa|gi|te|tw|fo|hu|v|eth|lo|br|10|40|mgmt|bo)' \
              + r'\D*([\d\/\-\.:]+)\W*(.*)$'
    mobj = re.match(pattern, interface)
    if mobj:
        iface_type = mobj.group(1)
        # Brocade's interfaces are indexed with Arabic numerals
        # vs. Cisco's spelled out
        # e.g.: 10GigabitEthernet vs. TenGigabitEthernet
        if iface_type == '10':
            iface_type = 'te'
        if iface_type == '40':
            iface_type = 'fo'
        iface_num = re.sub(r'\D', '-', mobj.group(2))
        if speed:
            return "{}-{}-{}-{}".format(hostname, speed, iface_type, iface_num)
        else:
            return "{}-{}-{}".format(hostname, iface_type, iface_num)


def get_node_ids(iface_list):
    """ Returns a list of unique node_ids from the master list of
        interface dicts returned by get_iface_list()

    """
    # Casting as a set() removes duplicates
    # Casting back as list() for further use
    return list(set([i['node_id'] for i in iface_list]))


def get_node_ifaces(node_id, iface_list):
    """ Returns list of interfaces associated with a given node_id """
    return [i for i in iface_list if i['node_id'] == node_id]


def get_mgmt_iface(node_id, iface_list):
    """ Returns single interface dict of the node's management interface

        If node has one IP, that defaults to management interface.
        If node has more than one IP, defaults to node polling IP.
        If node has more than one IP but the polling IP does not
        correspond to any managed interface, chooses a management
        interface at random.

    """
    mgmt_iface = None
    ifaces = get_node_ifaces(node_id, iface_list)
    if len(ifaces) == 1:
        # If node only has one L3 interface, that's our mgmt int
        # Without [0] at the end, we get a single-item list instead
        # of a bare dict
        return ifaces[0]
    else:
        # If node has >1 L3 interface, try to match Orion polling IP
        mgmt_iface = [i for i in ifaces if i['iface_addr'] == i['node_addr']]
        if mgmt_iface:
            return mgmt_iface[0]
        else:
            # If the polling IP does not correlate to any managed interface,
            # just pick the first one (clean up your node in Orion!)
            return ifaces[0]


def get_domain_from_fqdn(fqdn):
    """ Returns domain name from a fully-qualified domain name
        (removes left-most period-delimited value)

    """
    if "." in fqdn:
        split = fqdn.split(".")
        split.reverse()
        del split[0]
        split.reverse()
        return ".".join(split)
    else:
        return None


def get_hostname_from_fqdn(fqdn):
    """ Returns hostname from a fully-qualified domain name
        (returns left-most period-delimited value)

    """
    if "." in fqdn:
        split = fqdn.split(".")
        split.reverse()
        return split.pop()
    else:
        return fqdn


def get_a_record(iface):
    """ Returns a formatted DNS A record for a given interface dict """
    iface_addr = iface['iface_addr']
    iface_hostname = get_iface_hostname(iface)
    if iface_hostname:
        return {
            'name': iface_hostname,
            'class': 'IN',
            'type': 'A',
            'rdata': iface_addr
        }


def get_cname_record(iface):
    """ Returns a formatted DNS CNAME record for a given interface dict """
    hostname = iface['node_name']
    iface_hostname = get_iface_hostname(iface)
    if iface_hostname:
        return {
            'name': hostname,
            'class': 'IN',
            'type': 'CNAME',
            'rdata': iface_hostname
        }


def get_ptr_record(iface, flz_name=CONFIG['flz_name']):
    """ Returns a formatted DNS PTR record for a given interface dict

        If NPM reports a FQDN in the SysName field (node_fqdn), that
        value is preferred. Otherwise, defaults to flz_name.

    """
    ptr_index = iface['iface_addr'].split('.')[-1]
    reverse_fqdn = ''
    if iface['node_class'] == 'Network':
        node_domain = flz_name
        iface_hostname = get_iface_hostname(iface)
        reverse_fqdn = "{}.{}.".format(iface_hostname, node_domain)
    else:
        node_hostname = get_hostname_from_fqdn(iface['node_fqdn'])
        node_domain = get_domain_from_fqdn(iface['node_fqdn'])
        if node_domain:
            reverse_fqdn = "{}.{}.".format(node_hostname, node_domain)

    # Some server nodes in NPM do not have a FQDN in any property,
    # therefore we cannot construct a valid PTR record
    if reverse_fqdn:
        return {
            'name': ptr_index,
            'class': 'IN',
            'type': 'PTR',
            'rdata': reverse_fqdn
        }
    else:
        return None


def get_iface_rlz(iface):
    """ Returns a string for the reverse lookup zone for an interface

        Example input:
            - iface_addr = "10.250.23.20"
        Example output:
            "23.250.10"

    """
    split = iface['iface_addr'].split(".")
    del split[0]
    split.reverse()
    return ".".join(split)


def save_template(file_path, render):
    """ Writes template output to file (overwrites existing) """
    with open(file_path, "wb") as fh:
        fh.write(render)


def get_all_rlz_records(iface_list):
    """ Returns list of reverse lookup zone info for each interface
        Dict schema:
        - zone_file: fully qualified reverse lookup zone file name
        - ptr_record: fully qualified/formatted PTR record for interface

    """
    zone_suffix = ".in-addr.arpa"
    rlz_records = []
    for iface in iface_list:
        iface_ptr_record = get_ptr_record(iface)
        if iface_ptr_record:
            iface_rlz = get_iface_rlz(iface)
            zone_file = "{}{}".format(iface_rlz, zone_suffix)
            record = {
                "zone_file": zone_file,
                "ptr_record": iface_ptr_record
            }
            rlz_records.append(record)
    return rlz_records


def get_rlz_records(rlz, all_rlz_records):
    """ Returns sorted list of all records associated with a
        reverse lookup zone

    """
    rlz_records = [i for i in all_rlz_records if i['zone_file'] == rlz]
    return rlz_records


def get_rlz_list(all_rlz_records):
    """ Returns list of unique reverse lookup zone files """
    # Casting as set() removes duplicates
    return list(set([i['zone_file'] for i in all_rlz_records]))


def generate_rlz_file(rlz_records):
    """ Generates reverse lookup zone file """
    rlz_file = rlz_records[0]['zone_file']
    zone = CONFIG['zone']
    zone['name'] = rlz_file
    # TODO: Auto-generate serial
    zone['serial'] = '2019030801'
    zone['rrset'] = sorted([i['ptr_record'] for i in rlz_records],
                           key=lambda rr: int(rr['name']))
    template = ENV.get_template(CONFIG['rlz_template'])
    render = template.render(zone=zone)
    file_path = "{}{}".format(CONFIG['zone_dir'], rlz_file)
    save_template(file_path, render)


def generate_rlz_files(iface_list):
    """ Generates and saves reverse lookup zone files """
    all_rlz_records = get_all_rlz_records(iface_list)
    rlz_list = get_rlz_list(all_rlz_records)
    generate_rlz_config(rlz_list)
    for rlz in rlz_list:
        rlz_records = get_rlz_records(rlz, all_rlz_records)
        generate_rlz_file(rlz_records)


def generate_rlz_config(rlz_list):
    """ Generates BIND config for reverse lookup zones """
    template = ENV.get_template(CONFIG['rlz_conf_template'])
    render = template.render(rlz_list=rlz_list)
    file_path = "{}{}".format(CONFIG['bind_conf_dir'],
                              CONFIG['rlz_conf_file'])
    save_template(file_path, render)


def get_flz_records(iface_list):
    """ Returns list of forward lookup zone records for each interface """
    flz_records = []

    # In our use case, only devices belonging to the "Network" class
    # get forward lookup entries. Devices belonging to the "Server"
    # class only get reverse entries, hence why I'm sifting out servers
    # here.
    iface_list = [i for i in iface_list if i['node_class'] == 'Network']
    node_list = get_node_ids(iface_list)
    for node_id in node_list:
        # Generate A records for each interface
        node_ifaces = get_node_ifaces(node_id, iface_list)
        for iface in node_ifaces:
            iface_a_record = get_a_record(iface)
            # Interfaces we can't properly parse don't get an A record
            if iface_a_record:
                flz_records.append(iface_a_record)
        # Generate CNAME record for management interface
        mgmt_iface = get_mgmt_iface(node_id, node_ifaces)
        iface_cname_record = get_cname_record(mgmt_iface)
        if iface_cname_record:
            flz_records.append(get_cname_record(mgmt_iface))

    # Sort alphabetically, ignoring case
    return sorted(flz_records, key=lambda rr: rr['name'].lower())


def generate_flz_file(iface_list):
    """ Generates forward lookup zone file """
    zone = CONFIG['zone']
    zone['name'] = CONFIG['flz_name']
    # TODO: Auto-generate serial
    zone['serial'] = '2019030501'
    zone['rrset'] = get_flz_records(iface_list)
    template = ENV.get_template(CONFIG['flz_template'])
    render = template.render(zone=zone)
    file_path = "{}{}".format(CONFIG['zone_dir'],
                              CONFIG['flz_file'])
    save_template(file_path, render)


def generate_zones():
    """ Generates all forward and reverse lookup zones """
    # Pull all L3 interfaces from Orion
    iface_list = get_iface_list()

    # Generate forward lookup zone
    generate_flz_file(iface_list)

    # Reverse lookup zones
    generate_rlz_files(iface_list)


if __name__ == "__main__":
    generate_zones()
