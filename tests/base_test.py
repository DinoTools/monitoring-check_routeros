# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

import check_routeros


class TestBase:
    def test_parse_routeros_time(self):
        check = check_routeros.RouterOSCheckResource(cmd_options={})
        assert check.parse_routeros_time("1s") == 1
        assert check.parse_routeros_time("2m1s") == 121
        assert check.parse_routeros_time("3h2m1s") == 10921
        assert check.parse_routeros_time("4d3h2m1s") == 356521
