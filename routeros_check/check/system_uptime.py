# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

import click
import librouteros
import librouteros.query
import nagiosplugin
from nagiosplugin.state import Ok as STATE_Ok, Warn as STATE_Warn, Critical as STATE_Critical

from ..cli import cli
from ..helper import humanize_time, logger
from ..resource import RouterOSCheckResource


class SystemUptimeResource(RouterOSCheckResource):
    name = "UPTIME"

    def __init__(self, cmd_options):
        super().__init__(cmd_options=cmd_options)

    def probe(self):
        api = self._connect_api()

        logger.info("Fetching data ...")
        call = api.path(
            "/system/resource"
        ).select(
            librouteros.query.Key("uptime"),
        )
        results = tuple(call)
        result = results[0]

        yield nagiosplugin.Metric(
            name="uptime",
            value=self.parse_routeros_time_duration(result["uptime"]),
            uom="s",
            min=0,
        )


class UptimeSimpleScalarContext(nagiosplugin.ScalarContext):
    def describe(self, metric):
        return humanize_time(metric.value)

    def evaluate(self, metric, resource):
        if str(self.critical) != "" and metric.value in self.critical:
            return self.result_cls(
                STATE_Critical,
                None,
                metric
            )

        if str(self.warning) != "" and metric.value in self.warning:
            return self.result_cls(
                STATE_Warn,
                None,
                metric
            )
        return self.result_cls(STATE_Ok, None, metric)


@cli.command("system.uptime")
@click.option(
    "--warning",
    help="State WARNING if current uptime is below this threshold",
)
@click.option(
    "--critical",
    help="State CRITICAL if current uptime is below this threshold",
    default=None,
)
@click.pass_context
@nagiosplugin.guarded
def system_uptime(ctx, warning, critical):
    """Get Uptime of a device"""
    check = nagiosplugin.Check(
        SystemUptimeResource(
            cmd_options=ctx.obj,
        ),
        UptimeSimpleScalarContext(
            name="uptime",
            warning=float(warning) if warning else None,
            critical=float(critical) if critical else None,
        )
    )

    check.main(verbose=ctx.obj["verbose"])
