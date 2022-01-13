# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

import check_routeros


class TestBase:
    def test_parse_routeros_time(self):
        check = check_routeros.RouterOSCheckResource(cmd_options={})
        assert check.parse_routeros_time("1s") == 1
        assert check.parse_routeros_time("2m1s") == 1 + 2 * 60
        assert check.parse_routeros_time("3h2m1s") == 1 + 2 * 60 + 3 * 60 * 60
        assert check.parse_routeros_time("4d3h2m1s") == 1 + 2 * 60 + 3 * 60 * 60 + 4 * 24 * 60 * 60
        assert check.parse_routeros_time("5w4d3h2m1s") == (
            1 +
            2 * 60 +
            3 * 60 * 60 +
            4 * 24 * 60 * 60 +
            5 * 7 * 24 * 60 * 60
        )
