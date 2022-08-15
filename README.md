check_routeros - Monitoring MikroTik devices
============================================

This is a monitoring plugin for [Icinga](https://icinga.com/), [Nagios](https://www.nagios.org/) and other compatible monitoring solutions to check [MikroTik](https://mikrotik.com/) devices running RouterOS.
It uses the API to fetch the required information.

Requirements
------------

- [Python](https://www.python.org/) >= 3.6
- Python Packages
    - [Click](https://pypi.org/project/click/)
    - [librouteros](https://pypi.org/project/librouteros/)
    - [nagiosplugin](https://pypi.org/project/nagiosplugin/)

Installation
------------

### PIP

If you want to use pip we recommend to use as virtualenv to install the dependencies.

```shell
pip install -r requirements.txt
```

Copy the script ```check_routeros.py``` into your plugin directory.

### Debian/Ubuntu

Install the required packages

```shell
sudo apt-get install python3 python3-click python3-librouteros python3-nagiosplugin
```

Copy the script ```check_routeros.py``` into your plugin directory.

Usage
-----

To get the latest help just run the following command.

```shell
./check_routeros.py --help
```

To get help for a subcommand just extend the previous command with the subcommand.
In the example below you will see how to get help for the ```tool.ping``` subcommand.

```shell
./check_routeros.py tool.ping --help
```

Subcommands/Checks
------------------

All commands require at least `api` and `read` permissions.
The permissions documented in the table are additional permissions.

| Subcommand             | Permissions | Description                                     |
|------------------------|-------------|-------------------------------------------------|
| interface.vrrp         | -           | Check the state of an VRRP interface            |
| routing.ospf.neighbors | -           | Check if ospf neigbhors are reachable           |
| routing.bgp.peers      | -           | Check if connection to BGP peers is established |
| system.memory          | -           | Check system memory                             |
| system.uptime          | -           | Check the uptime                                |
| tool.ping              | test        | Run the ping command on the device              |

Resources
---------

- Git-Repository: https://github.com/DinoTools/monitoring-check_routeros
- Issues: https://github.com/DinoTools/monitoring-check_routeros/issues

License
-------

GPLv3+
