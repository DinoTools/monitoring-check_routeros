# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

from routeros_check import helper


class TestRouterOSVersion:
    _CMP_EQ_ITEMS = (
        ("7.8", "7.8"),
        ("6.44beta41", "6.44beta41"),
        ("6.47.9", "6.47.9"),
        ("7.8", "7.8.0"),
    )
    _CMP_GT_ITEMS = (
        ("7.8", "6.47.9"),
    )
    _CMP_LT_ITEMS = (
        ("6.47.9", "7.8"),
    )
    _CMP_NE_ITEMS = (
        ("7.8", "6.44beta41"),
        ("6.44beta41", "6.47.9"),
        ("6.47.9", "7.8"),
        ("7.8", "7.8.1"),
        ("7.8", "7.9"),
        ("7.8.1", "7.7.1"),
        ("6.8.1", "7.8.1"),
    )

    def test_compare_routeros_version_eq(self):
        cmp_items = self._CMP_EQ_ITEMS
        for item in cmp_items:
            assert helper.RouterOSVersion(item[0]) == helper.RouterOSVersion(item[1])

        cmp_items = self._CMP_NE_ITEMS + self._CMP_GT_ITEMS + self._CMP_LT_ITEMS
        for item in cmp_items:
            assert not helper.RouterOSVersion(item[0]) == helper.RouterOSVersion(item[1])

    def test_compare_routeros_version_ge(self):
        cmp_items = self._CMP_GT_ITEMS + self._CMP_EQ_ITEMS
        for item in cmp_items:
            assert helper.RouterOSVersion(item[0]) >= helper.RouterOSVersion(item[1])

        cmp_items = self._CMP_LT_ITEMS
        for item in cmp_items:
            assert not helper.RouterOSVersion(item[0]) >= helper.RouterOSVersion(item[1])

    def test_compare_routeros_version_gt(self):
        cmp_items = self._CMP_GT_ITEMS
        for item in cmp_items:
            assert helper.RouterOSVersion(item[0]) > helper.RouterOSVersion(item[1])

        cmp_items = self._CMP_LT_ITEMS + self._CMP_EQ_ITEMS
        for item in cmp_items:
            assert not helper.RouterOSVersion(item[0]) > helper.RouterOSVersion(item[1])

    def test_compare_routeros_version_le(self):
        cmp_items = self._CMP_LT_ITEMS + self._CMP_EQ_ITEMS
        for item in cmp_items:
            assert helper.RouterOSVersion(item[0]) <= helper.RouterOSVersion(item[1])

        cmp_items = self._CMP_GT_ITEMS
        for item in cmp_items:
            assert not helper.RouterOSVersion(item[0]) <= helper.RouterOSVersion(item[1])

    def test_compare_routeros_version_lt(self):
        cmp_items = self._CMP_LT_ITEMS
        for item in cmp_items:
            assert helper.RouterOSVersion(item[0]) < helper.RouterOSVersion(item[1])

        cmp_items = self._CMP_EQ_ITEMS + self._CMP_GT_ITEMS
        for item in cmp_items:
            assert not helper.RouterOSVersion(item[0]) < helper.RouterOSVersion(item[1])

    def test_humanize_time_with_int(self):
        assert helper.humanize_time(10) == "10s"
        assert helper.humanize_time(75) == "1m 15s"
        assert helper.humanize_time(3601) == "1h 0m 1s"
        assert helper.humanize_time(
            60 * 60 * 24 +
            60 * 60 * 1 +
            60 * 13 +
            44
        ) == "1d 1h 13m 44s"

    def test_humanize_time_with_timedelta(self):
        from datetime import timedelta
        assert helper.humanize_time(
            timedelta(
                days=2,
                hours=12,
                minutes=33,
                seconds=56
            )
        ) == "2d 12h 33m 56s"

    def test_parse_routeros_version(self):
        a = helper.RouterOSVersion("7.8")
        assert a.major == 7
        assert a.minor == 8
        assert a.patch == 0

        b = helper.RouterOSVersion("6.44beta41")
        assert b.major == 6
        assert b.minor == 44
        assert b.patch == 0

        c = helper.RouterOSVersion("6.47.9")
        assert c.major == 6
        assert c.minor == 47
        assert c.patch == 9
