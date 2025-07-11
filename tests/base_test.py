# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later
from datetime import date, datetime

import nagiosplugin
from routeros_check.resource import RouterOSCheckResource


class TestBase:
    def test_parse_date(self):
        check = nagiosplugin.Check()
        resource = RouterOSCheckResource(cmd_options={}, check=check)
        expected_date = date(year=2021, month=9, day=20)
        assert resource.parse_routeros_date("sep/20/2021") == expected_date
        assert resource.parse_routeros_date("2021-09-20") == expected_date

        expected_date = date(year=2022, month=10, day=13)
        assert resource.parse_routeros_date("oct/13/2022") == expected_date
        assert resource.parse_routeros_date("2022-10-13") == expected_date

        expected_date = date(year=2023, month=4, day=5)
        assert resource.parse_routeros_date("Apr/05/2023") == expected_date
        assert resource.parse_routeros_date("2023-04-05") == expected_date

        expected_date = date(year=2023, month=5, day=7)
        assert resource.parse_routeros_date("May/07/2023") == expected_date
        assert resource.parse_routeros_date("2023-05-07") == expected_date

        expected_date = date(year=2021, month=2, day=8)
        assert resource.parse_routeros_date("Feb/08/2021") == expected_date
        assert resource.parse_routeros_date("2021-02-08") == expected_date

    def test_parse_routeros_datetime(self):
        check = nagiosplugin.Check()

        resource = RouterOSCheckResource(cmd_options={}, check=check)

        parsed_datetime = resource.parse_routeros_datetime("sep/20/2021 13:43:12")
        assert parsed_datetime == datetime(year=2021, month=9, day=20, hour=13, minute=43, second=12)

        parsed_datetime = resource.parse_routeros_datetime("oct/13/2022 22:59:59")
        assert parsed_datetime == datetime(year=2022, month=10, day=13, hour=22, minute=59, second=59)

        parsed_datetime = resource.parse_routeros_datetime("Apr/05/2023 23:59:59")
        assert parsed_datetime == datetime(year=2023, month=4, day=5, hour=23, minute=59, second=59)

        parsed_datetime = resource.parse_routeros_datetime("May/07/2023 22:59:59")
        assert parsed_datetime == datetime(year=2023, month=5, day=7, hour=22, minute=59, second=59)

        # Build Time 6.47.9 (long-term)
        parsed_datetime = resource.parse_routeros_datetime("Feb/08/2021 12:48:33")
        assert parsed_datetime == datetime(year=2021, month=2, day=8, hour=12, minute=48, second=33)

        parsed_datetime = resource.parse_routeros_datetime("2024-05-09 11:23:55")
        assert parsed_datetime == datetime(year=2024, month=5, day=9, hour=11, minute=23, second=55)

    def test_parse_routeros_time(self):
        check = nagiosplugin.Check()

        resource = RouterOSCheckResource(cmd_options={}, check=check)

        assert resource.parse_routeros_time_duration("-8ms15us") == -0.008015
        assert resource.parse_routeros_time_duration("13m53s460ms") == 833.46
        assert resource.parse_routeros_time_duration("1s") == 1
        assert resource.parse_routeros_time_duration("2m1s") == 1 + 2 * 60
        assert resource.parse_routeros_time_duration("3h2m1s") == 1 + 2 * 60 + 3 * 60 * 60
        assert resource.parse_routeros_time_duration("4d3h2m1s") == 1 + 2 * 60 + 3 * 60 * 60 + 4 * 24 * 60 * 60
        assert resource.parse_routeros_time_duration("5w4d3h2m1s") == (
            1 +
            2 * 60 +
            3 * 60 * 60 +
            4 * 24 * 60 * 60 +
            5 * 7 * 24 * 60 * 60
        )
