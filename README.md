# npm_bind

## Overview

Auto-generates BIND-compatible forward and reverse DNS zone files and configuration for all L3 interfaces in SolarWinds Orion NPM.

Required modules:
* jinja2
* orionsdk
* yaml

Features:
* YAML config
* Jinja2 templates for BIND zone & config files

## Operation

1. Queries the SolarWinds Information Service (SWIS) using SolarWinds Query Language (SWQL) for a list of all L3 interfaces
1. Creates A, CNAME, and PTR records
1. Generates the respective BIND config & zone files

**DISCLAIMER**: This is alpha code. Expect bugs, issues, and the likelihood of major behavioral changes.

## Roadmap

* Fully automated integration with BIND
* Python 3 testing/support

