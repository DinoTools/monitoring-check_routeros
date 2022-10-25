Changelog
=========

0.5 - 2022-10-25
----------------

- Add changelog
- Add checks
  - system.cpu
  - system.fan
  - system.power
  - system.psu
  - system.temperature

0.4.1 - 2022-10-13
------------------

- Update verbose mode handling
- Fix issues while reading license information

0.4 - 2022-08-17
----------------

- Add function to parse datetime
- Add checks
  - interface.gre
  - routing.bgp.peers
  - system.license
- Add CI task to check icinga2 config

0.3.1 - 2022-01-13
------------------

- Improve time parsing
- Add initial icinga2 config example

0.3 - 2021-12-30
----------------

- Add checks
  - routing.ospf.neighbors
  - system.memory
  - system.uptime
- Add initial tests for base functions

0.2.1 - 2021-12-26
------------------

- Add CI tests

0.2 - 2021-12-26
----------------

- Add SSL support
- Add verbose output
- Add logging
- Add additional license info
- Add pre-commit and flake8 configs

0.1 - 2021-12-25
----------------

- Initial release
- Add checks
  - interface.vrrp
  - tool.ping