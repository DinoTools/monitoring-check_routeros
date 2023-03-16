# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later
from datetime import datetime

from routeros_check.resource import RouterOSCheckResource


class TestBase:
    def test_parse_routeros_datetime(self):
        check = RouterOSCheckResource(cmd_options={})

        parsed_datetime = check.parse_routeros_datetime("sep/20/2021 13:43:12")
        assert parsed_datetime == datetime(year=2021, month=9, day=20, hour=13, minute=43, second=12)

        parsed_datetime = check.parse_routeros_datetime("oct/13/2022 22:59:59")
        assert parsed_datetime == datetime(year=2022, month=10, day=13, hour=22, minute=59, second=59)

        parsed_datetime = check.parse_routeros_datetime("Apr/05/2023 23:59:59")
        assert parsed_datetime == datetime(year=2023, month=4, day=5, hour=23, minute=59, second=59)

        parsed_datetime = check.parse_routeros_datetime("May/07/2023 22:59:59")
        assert parsed_datetime == datetime(year=2023, month=5, day=7, hour=22, minute=59, second=59)

        # Build Time 6.47.9 (long-term)
        parsed_datetime = check.parse_routeros_datetime("Feb/08/2021 12:48:33")
        assert parsed_datetime == datetime(year=2021, month=2, day=8, hour=12, minute=48, second=33)

    def test_parse_routeros_time(self):
        check = RouterOSCheckResource(cmd_options={})
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
