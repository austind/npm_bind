#!/usr/bin/env python2.7

import getpass
import jinja2
import orionsdk
import requests
import re
import yaml

def _read_yaml_file(file_name):
    """ Reads and parses YAML file """
    with open(file_name, "r") as f:
        file_contents = f.read()
        parsed_yaml = yaml.load(file_contents)
    return parsed_yaml

# Read config
config = _read_yaml_file("./config/config.yaml")

# Establish SolarWinds connection
if not config['npm_user']:
    curr_user = getpass.getuser()
    config['npm_user'] = raw_input("Orion username [{}]: ".format(curr_user)) or curr_user
if not config['npm_pass']:
    config['npm_pass'] = getpass.getpass("Orion password: ")
if not config['npm_verify_cert']:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
swis = orionsdk.SwisClient(config['npm_server'], config['npm_user'],
                           config['npm_pass'])

# Initialize jinja2
env = jinja2.Environment(loader=jinja2.FileSystemLoader(config['template_dir']))

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

def get_iface_list(swis=swis, manual_ifaces=config['npm_manual_ifaces']):
    """ Returns list of layer 3 network interfaces in all nodes.
        Dict schema:
        - node_id: Network node unique ID
        - node_uri: Network node SWIS URI
        - node_name: Network node hostname / caption
        - node_addr: Network node polling address
        - node_fqdn: Network node fully-qualified domain name
        - node_class: Node class as defined in custom properties
        - iface_id: Interface unique ID
        - iface_uri: Interface SWIS URI
        - iface_name: Interface description
            This includes both the device-given interface identifier
            as well as any administratively-defined description
        - iface_addr: IP address of interface
        - iface_speed: Interface speed in bits per second (bps)
            Note that NPM does not accurately query this value in all cases.

        TODO: Move query to separate file

    """

    # Orion NPM can query an interface's IP address via SNMP for many
    # devices, but certain vendors do not support that (notably: Palo
    # Alto). For such devices, their managed interfaces in Orion will
    # show as "Unknown" IP address.

    # To further complicate things, best I can tell, Orion does not
    # allow us to administratively set an interface's IP address, either
    # via the web GUI or SWIS.

    # The workaround here is to create an interface custom property called
    # IPAddress and manually set that in NPM. We then have two fields from which
    # we may obtain an interface's IP address.

    # If the interface's custom property IPAddress is set, that
    # takes precedence over an interface's SNMP address.

    # If an interface has neither an administratively-defined nor an SNMP-
    # queried IP address, it is not included in the result set at all.

    # Returns a list of all managed interfaces known by Orion NPM that
    # have the DeviceClass custom property set to "Network" and have either 
    # an SNMP-queried L3 address, or an administratively-set IP address via
    # an interface custom property called IPAddress.

    query = """
        SELECT
            N.NodeID AS node_id,
            N.URI AS node_uri,
            N.Caption AS node_name,
            N.IPAddress AS node_addr,
            N.SysName AS node_fqdn,
            N.CustomProperties.DeviceClass AS node_class,
            I.InterfaceID AS iface_id,
            I.URI AS iface_uri,
            I.IfName AS iface_name,
            CASE
                WHEN IC.IPAddress <> '' THEN IC.IPAddress
                ELSE IP.IPAddress
            END AS iface_addr,
            I.Speed AS iface_speed
        FROM
            Orion.Nodes N
        RIGHT JOIN
            Orion.NPM.Interfaces I ON
                N.NodeID = I.NodeID
        LEFT JOIN
            Orion.NodeIPAddresses IP ON (
                I.NodeID = IP.NodeID
                AND I.InterfaceIndex = IP.InterfaceIndex
            )
        LEFT JOIN
            Orion.NPM.InterfacesCustomProperties IC ON
                I.InterfaceID = IC.InterfaceID
        WHERE (
               N.CustomProperties.DeviceClass = 'Network'
            OR N.CustomProperties.DeviceClass = 'Server'
            )
            AND (
               IP.IPAddress <> ''
            OR IC.IPAddress <> ''
            )
    """
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
    s = iface['iface_speed']
    if s:
        s = int(iface['iface_speed'])
    else:
        return None

    if s < 1536000:
        return None
    elif s == 1536000 or s == 1544000:
        return 't1'
    else:
        prefix = s
        suffixes = ["k","m","g","t","p"]
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
        
        TODO: Might be nice to translate generic Ethernet interfaces
              into their actual L1 speed on N7K/N9K series, etc. Could be
              done by adding another property read from NPM.

    """
    hostname  = iface['node_name'].lower()
    interface = iface['iface_name'].strip().lower()
    speed = get_iface_speed(iface)
    r = r'^(ser|sc|fa|gi|te|tw|fo|hu|v|eth|lo|br|10|40|mgmt|bo)\D*([\d\/\-\.:]+)\W*(.*)$'
    m = re.match(r, interface)
    if m:
        iface_type = m.group(1)
        # Brocade's interfaces are indexed with Arabic numerals
        # vs. Cisco's spelled out
        # e.g.: 10GigabitEthernet vs. TenGigabitEthernet
        if iface_type == '10':
            iface_type = 'te'
        if iface_type == '40':
            iface_type = 'fo'
        iface_num  = re.sub(r'\D', '-', m.group(2))
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
    return list(set([ i['node_id'] for i in iface_list ]))

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
    # TODO: All of this looks like it could be cleaned up.
    mgmt_iface = None
    node_ifaces = get_node_ifaces(node_id, iface_list)
    if len(node_ifaces) == 1:
        # If node only has one L3 interface, that's our mgmt int
        # Without [0] at the end, we get a single-item list instead of a bare dict
        return node_ifaces[0]
    elif len(node_ifaces) > 1:
        # If node has >1 L3 interface, try to match Orion polling IP
        mgmt_iface = [i for i in node_ifaces if i['iface_addr'] == i['node_addr']]
        if mgmt_iface:
            return mgmt_iface[0]
        else:
            # If the polling IP does not correlate to any managed interface,
            # just pick the first one (clean up your node in Orion!)
            # TODO: May be better to just default to polling IP, even if it does
            # not correlate with any managed L3 interface.
            return node_ifaces[0]

def get_domain_from_fqdn(fqdn):
    """ Returns domain name from a fully-qualified domain name
        (removes left-most period-delimited value)

    """
    if "." in fqdn:
        split = fqdn.split(".")
        split.reverse()
        null = split.pop()
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
        return "{0:<32} {1:<8} {2:<8}".format(iface_hostname, 'A', iface_addr)

def get_cname_record(iface):
    """ Returns a formatted DNS CNAME record for a given interface dict """
    hostname = iface['node_name']
    iface_hostname = get_iface_hostname(iface)
    if iface_hostname:
        return "{0:<32} {1:<8} {2:<8}".format(hostname, 'CNAME', iface_hostname)

def get_ptr_record(iface, flz_name=config['flz_name']):
    """ Returns a formatted DNS PTR record for a given interface dict

        If NPM reports a FQDN in the SysName field (node_fqdn), that
        value is preferred. Otherwise, defaults to flz_name.
    """
    ptr_format = "{0:<8} {1:<8} {2:<8}."
    ptr_index = iface['iface_addr'].split('.')[-1]
    reverse_fqdn = ''
    if iface['node_class'] == 'Network':
        node_domain = flz_name
        iface_hostname = get_iface_hostname(iface)
        reverse_fqdn = "{}.{}".format(iface_hostname, node_domain)
    else:
        node_hostname = get_hostname_from_fqdn(iface['node_fqdn'])
        node_domain = get_domain_from_fqdn(iface['node_fqdn'])
        if node_domain:
            reverse_fqdn = "{}.{}".format(node_hostname, node_domain)
    
    # Some server nodes in NPM do not have a FQDN in any property,
    # therefore we cannot construct a valid PTR record
    if reverse_fqdn:
        return ptr_format.format(ptr_index, "PTR", reverse_fqdn)
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
    null = split.pop()
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
    return list(set([ i['zone_file'] for i in all_rlz_records ]))

def generate_rlz_file(rlz_records):
    """ Generates reverse lookup zone file """
    rlz_file = rlz_records[0]['zone_file']
    zone = config['zone']
    zone['name'] = rlz_file
    # TODO: Auto-generate serial
    zone['serial'] = '2019030501'
    zone['records'] = sorted(list(set([ i['ptr_record'] for i in rlz_records])),
                      key=lambda r: int(r.split()[0]))
    template = env.get_template(config['rlz_template'])
    render = template.render(zone=zone)
    file_path = "{}{}".format(config['zone_dir'], rlz_file)
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
    template = env.get_template(config['rlz_conf_template'])
    render = template.render(rlz_list=rlz_list)
    file_path = "{}{}".format(config['bind_conf_dir'],
                              config['rlz_conf_file'])
    save_template(file_path, render)

def get_flz_records(iface_list):
    """ Returns sorted list of forward lookup zone records for each interface """
    flz_records = []

    # In our use case, only devices belonging to the "Network" class
    # get forward lookup entries. Devices belonging to the "Server"
    # class only get reverse entries, hence why I'm sifting out servers
    # here.
    iface_list = [ i for i in iface_list if i['node_class'] == 'Network' ]
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
    return sorted(flz_records, key=lambda s: s.lower())

def generate_flz_file(iface_list):
    """ Generates forward lookup zone file """
    zone = config['zone']
    zone['name'] = config['flz_name']
    # TODO: Auto-generate serial
    zone['serial'] = '2019030501'
    zone['records'] = get_flz_records(iface_list)
    template = env.get_template(config['flz_template'])
    render = template.render(zone=zone)
    file_path = "{}{}".format(config['zone_dir'],
                              config['flz_file'])
    save_template(file_path, render)

def generate_zones(flz_file=config['flz_file']):
    """ Generates all forward and reverse lookup zones """
    # Pull all L3 interfaces from Orion
    iface_list = get_iface_list()
 
    # Generate forward lookup zone
    generate_flz_file(iface_list)

    # Reverse lookup zones
    generate_rlz_files(iface_list)

if __name__ == "__main__":
    generate_zones()

