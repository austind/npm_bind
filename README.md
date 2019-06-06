# npm_bind

**DISCLAIMER**: This is alpha code. Expect bugs, issues, and the likelihood of major behavioral changes.

## Overview

Auto-generates BIND9-compatible forward and reverse DNS zone / config files for all L3 interfaces in SolarWinds Orion NPM.

1. Queries the SolarWinds Information Service (SWIS) for a list of all managed layer 3 interfaces, using SolarWinds Query Language (similar syntax to native SQL)
1. Generates forward lookup records (A and CNAME)
1. Generates reverse lookup records (PTR)
1. Creates the appropriate BIND9 zone and configuration files

At this time, npm_bind does not automatically copy or enable the generated BIND9 config. This must be done manually for DNS changes to take effect.

## Setup

### Python

Required modules:
* [orionsdk](https://github.com/solarwinds/OrionSDK)
* jinja2
* yaml
* requests
* urllib3

### SolarWinds NPM

npm_bind depends on two custom fields added to NPM:
1. `IPAddress` interface custom field. This allows for manually-defined interface addresses in cases when the SNMP-queried address is incorrect or nonexistent.
1. `DeviceClass` node custom field. Helpful in differentiating types of nodes (e.g. network devices vs. servers)

### Script Config

All npm_bind config resides in `config/config.yaml`. Refer to inline comments for details.

### Templates

All BIND9 files are generated from jinja2 templates located in `config/templates`. They will need little or no modification.

## Source Data

npm_bind has two data sources:
1. SolarWinds NPM, as received by the SolarWinds API (SWIS)
1. Manual input, as defined in `config.yaml`.

The objective of this project is to rely as heavily as possible on NPM as the source of truth, using manual input as sparingly as possible. Ideally, npm_bind will need little or no post-deployment adjustment; all relevant changes occur directly in NPM.

#### Schema

Data begins as a list of dicts (`iface_list`) with the following schema:

* `node_id` - Node unique ID as assigned by NPM
* `node_uri` - Node SWIS URI (beginning with swis://)
* `node_name` - Node hostname (SWIS `caption` property)
* `node_addr` - Node polling IP address
* `node_fqdn` - Node fully-qualified domain name
* `node_class` - `DeviceClass` NPM custom property. I use this to differentiate between network nodes and servers.
* `iface_id` - Interface unique ID as assigned by NPM
* `iface_uri` - Interface SWIS URI (beginning with swis://)
* `iface_name` - Interface description, which includes both the device's interface name (e.g. Gi0/1) and any administratively assigned description string
* `iface_speed` - Interface's negotiated speed in bits per second (bps). Note: a) that NPM does not accurately query this value in all cases, and b) that the interface's negotiated speed may differ from its line speed.

#### SWQL Query

npm_bind ships with an example query in `config/query.swql`. This is tailored to our use-case, but will likely need minimal or no adjustment, as long as the custom fields described above are created and populated.

##### Query Details
Orion NPM can query an interface's IP address via SNMP for many devices, but certain vendors do not support that (notably: Palo Alto). For such devices, their managed interfaces in Orion will show as "Unknown" IP address.

To further complicate things, best I can tell, Orion does not allow us to administratively set an interface's IP address, either via the web GUI or SWIS.

The workaround here is to create an interface custom property called IPAddress and manually set that in NPM. We then have two fields from which we may obtain an interface's IP address.

If the interface's custom property IPAddress is set, that takes precedence over an interface's SNMP address.

If an interface has neither an administratively-defined nor an SNMP-queried IP address, it is not included in the result set at all.

Returns a list of all managed interfaces known by Orion NPM that have the DeviceClass custom property set to "Network" and have either  an SNMP-queried L3 address, or an administratively-set IP address via an interface custom property called IPAddress.

##### Documentation and References:
* [About SWIS](https://github.com/solarwinds/OrionSDK/wiki/About-SWIS)
* [Use SolarWinds Query Language](https://support.solarwinds.com/Success_Center/Network_Performance_Monitor_(NPM)/Knowledgebase_Articles/How_to_use_SolarWinds_Query_Language_SWQL)
* [SWIS 3.0 Schema](http://solarwinds.github.io/OrionSDK/schema/index.html)
