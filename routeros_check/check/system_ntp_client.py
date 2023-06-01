# SPDX-FileCopyrightText: PhiBo DinoTools (2023)
# SPDX-License-Identifier: GPL-3.0-or-later

from pprint import pformat
from typing import List, Optional

import click
import nagiosplugin

from ..cli import cli
from ..context import BooleanContext, PerfdataScalarContext
from ..helper import logger, RouterOSVersion
from ..resource import RouterOSCheckResource


class SystemNtpClientResource(RouterOSCheckResource):
    name = "NTP"

    def __init__(
        self,
        cmd_options,
        check: nagiosplugin.Check,
        last_update_before_warning: Optional[float] = None,
        last_update_before_critical: Optional[float] = None,
        offset_warning: Optional[float] = None,
        offset_critical: Optional[float] = None,
        stratum_warning: Optional[int] = None,
        stratum_critical: Optional[int] = None,
    ):
        super().__init__(cmd_options=cmd_options)

        self._check = check

        self._offset_warning = offset_warning
        self._offset_critical = offset_critical
        self._last_update_before_warning = last_update_before_warning
        self._last_update_before_critical = last_update_before_critical
        self._stratum_warning = stratum_warning
        self._stratum_critical = stratum_critical

    def probe(self):
        logger.info("Fetching ntp client data ...")
        call = self.api.path(
            "/system/ntp/client"
        )

        results = tuple(call)

        result = results[0]
        logger.debug(f"Extracted values {pformat(result)}")

        self._routeros_metric_values += [
            {"name": "enabled", "type": bool},
        ]

        if not result["enabled"]:
            self._check.results.add(
                nagiosplugin.Result(
                    nagiosplugin.Critical,
                    "NTP Client not enabled"
                )
            )
            return self.get_routeros_metric_item(result)

        if self.routeros_version < RouterOSVersion("7"):
            metric_values = [
                {"name": "last-adjustment", "dst": "offset", "type": self.parse_routeros_time_duration, "uom": "s"},
                {"name": "last-update-before", "type": self.parse_routeros_time_duration, "uom": "s"},
            ]
            metric_value_names_not_found = []
            for metric_value in metric_values:
                if metric_value["name"] not in result:
                    metric_value_names_not_found.append(metric_value["name"])

            if len(metric_value_names_not_found) > 0:
                self._check.results.add(
                    nagiosplugin.Result(
                        nagiosplugin.state.Critical,
                        (
                            f"Looks like NTP client not running. "
                            f"Unable to find values for {', '.join(metric_value_names_not_found)}"
                        )
                    )
                )
            else:
                self._routeros_metric_values += metric_values
                self._check.add(
                    nagiosplugin.ScalarContext(
                        name="last-update-before",
                        warning=self._last_update_before_warning,
                        critical=self._last_update_before_critical,
                    ),
                    nagiosplugin.ScalarContext(
                        name="offset",
                        warning=f"-{self._offset_warning}:{self._offset_warning}" if self._offset_warning else None,
                        critical=f"-{self._offset_critical}:{self._offset_critical}" if self._offset_critical else None,
                    ),
                )
        else:
            self._routeros_metric_values += [
                {"name": "freq-drift", "type": float},
                {"name": "synced-stratum", "dst": "stratum", "type": int},
                {"name": "system-offset", "dst": "offset", "type": float, "uom": "s"},
            ]
            self._check.add(
                PerfdataScalarContext(
                    name="freq-drift",
                ),
                nagiosplugin.ScalarContext(
                    name="offset",
                    warning=f"-{self._offset_warning}:{self._offset_warning}" if self._offset_warning else None,
                    critical=f"-{self._offset_critical}:{self._offset_critical}" if self._offset_critical else None,
                ),
                nagiosplugin.ScalarContext(
                    name="stratum",
                    warning=self._stratum_warning,
                    critical=self._stratum_critical,
                ),
            )

        return self.get_routeros_metric_item(result)


class SystemNtpClientSummary(nagiosplugin.Summary):
    def ok(self, results: List[nagiosplugin.Result]):
        messages: List[str] = []
        for result in results:
            if result.metric and result.metric.name == "stratum":
                messages.append(f"Stratum is {result.metric.value}")
            if result.metric and result.metric.name == "offset":
                messages.append(f"Offset is {result.metric.value:.2f}s")

        return ", ".join(messages)


@cli.command("system.ntp.client")
@click.option(
    "--last-update-before-warning",
    help="Warning threshold for time diff in seconds",
    type=float,
    default=60 * 30,
)
@click.option(
    "--last-update-before-critical",
    help="Critical threshold for time diff in seconds",
    type=float,
    default=60 * 60,
)
@click.option(
    "--offset-warning",
    help="Warning threshold for time diff in seconds",
    type=float,
    default=10.0,
)
@click.option(
    "--offset-critical",
    help="Critical threshold for time diff in seconds",
    type=float,
    default=30.0,
)
@click.option(
    "--stratum-warning",
    help="",
    type=int,
)
@click.option(
    "--stratum-critical",
    help="",
    type=int,
)
@click.pass_context
@nagiosplugin.guarded
def system_clock(ctx, last_update_before_warning, last_update_before_critical, offset_warning, offset_critical,
                 stratum_warning, stratum_critical):
    """This command reads the information from /system/ntp/client to extract the required information."""
    check = nagiosplugin.Check()

    resource = SystemNtpClientResource(
        cmd_options=ctx.obj,
        check=check,
        last_update_before_warning=last_update_before_warning,
        last_update_before_critical=last_update_before_critical,
        offset_warning=offset_warning,
        offset_critical=offset_critical,
        stratum_warning=stratum_warning,
        stratum_critical=stratum_critical,
    )
    check.add(
        resource,
        SystemNtpClientSummary(),
        BooleanContext(
            name="enabled",
        )
    )

    check.main(verbose=ctx.obj["verbose"])
