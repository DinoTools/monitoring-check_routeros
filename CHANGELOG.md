Changelog
=========

0.10.0 - 2024-06-11
-------------------

### Added

- * - Add cli option to specify connection timeout
- system.disk - Add initial check

### Changed

- Update icinga2 config to reflect latest changes
- interface - Add option for default values
- routing.ospf.neighbors - Improve output
- system.uptime - Improve output

### Fixed

- interface - Fix issue with getting the interface speed
- routing.ospf.neighbors - Fix issue with adjacency
- system.license - Fix license date parsing
- system.uptime - Add warning and critical thresholds


0.9.3 - 2023-12-27
------------------

- Add parsing of iso dates since RouterOS 7.11

0.9.2 - 2023-06-22
------------------

- Fix checks
  - system.ntp.client - Fix issue with offset on RouterOS 7.x

0.9.1 - 2023-06-07
------------------

- Fix checks
  - interface - Fix l2mtu issue on CHR devices
- Update icinga2 example config

0.9.0 - 2023-06-02
------------------

- Add checks
  - system.clock
  - system.ntp.client
- Update checks to support RouterOS 7.x
  - routing.ospf.neighbor

0.8.1 - 2023-03-29
------------------

- Fix issues introduced in 0.8.0
  - routing.bgp.peer
  - routing.ospf.neighbor

0.8.0 - 2023-03-28
------------------

- Add initial support for RouterOS v7
- Add auto detection of RouterOS version
- Add checks
  - system.update

0.7.2 - 2023-03-23
------------------

- Fix release pipeline

0.7.1 - 2023-03-23
------------------

- Fix issues with the mkdocs pipeline
- Fix issues with the new module name
- Update docs and badges

0.7.0 - 2023-03-16
------------------

- Split single file check into python package and publish on PyPI

0.6.0 - 2023-03-16
------------------

- Add checks
  - interface

0.5.1 - 2023-03-06
------------------

- Add help text for command options
- Add script to generate documention
- Fix typo in name of month

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
