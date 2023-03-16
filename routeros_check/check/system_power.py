# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

import click
import nagiosplugin

from ..cli import cli
from ..helper import logger
from ..resource import RouterOSCheckResource


class SystemPowerResource(RouterOSCheckResource):
    name = "Power"

    def __init__(
        self,
        cmd_options,
    ):
        super().__init__(cmd_options=cmd_options)

        self._routeros_metric_values = [
            {"name": "power-consumption", "type": float},
        ]

    def probe(self):
        api = self._connect_api()

        logger.info("Fetching data ...")
        call = api.path(
            "/system/health"
        ).select(
            *self.get_routeros_select_keys()
        )
        results = tuple(call)
        if len(results) > 0:
            result = results[0]
            return self.get_routeros_metrics(result)
        return []


@cli.command("system.power")
@click.option(
    "--warning",
    help="Warning threshold for total power consumption",
)
@click.option(
    "--critical",
    help="Critical threshold for total power consumption",
)
@click.pass_context
@nagiosplugin.guarded
def system_power(ctx, warning, critical):
    """Check the total power consumption of a device. This might not be available on all devices"""
    check = nagiosplugin.Check(
        SystemPowerResource(
            cmd_options=ctx.obj,
        ),
        nagiosplugin.ScalarContext(
            "power-consumption",
            warning=warning,
            critical=critical,
            fmt_metric="Power consumption {value}W",
        ),
    )

    check.main(verbose=ctx.obj["verbose"])
