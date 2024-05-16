# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import List, Optional

import click
import librouteros
import librouteros.query
import nagiosplugin

from ..cli import cli
from ..context import ScalarPercentContext
from ..helper import logger
from ..resource import RouterOSCheckResource


class SystemDiskResource(RouterOSCheckResource):
    name = "DISK"

    def __init__(self, cmd_options):
        super().__init__(cmd_options=cmd_options)

        self.total_hdd_space: Optional[int] = None
        self._routeros_metric_values = [
            {"name": "write-sect-since-reboot", "type": int, "min": 0},
            {"name": "write-sect-total", "type": int, "min": 0},
            {"name": "bad-blocks", "type": float, "min": 0, "max": 100, "missing_ok": True},
        ]

    def probe(self):
        api = self._connect_api()

        logger.info("Fetching data ...")
        call = api.path(
            "/system/resource"
        ).select(
            librouteros.query.Key("free-hdd-space"),
            librouteros.query.Key("total-hdd-space"),
            *self.get_routeros_select_keys()
        )
        api_result_items = tuple(call)

        free_hdd_space = api_result_items[0]["free-hdd-space"]
        self.total_hdd_space = api_result_items[0]["total-hdd-space"]
        results = self.get_routeros_metric_item(api_result_items[0])

        results.append(
            nagiosplugin.Metric(
                name="free",
                value=free_hdd_space,
                uom="B",
                min=0,
                max=self.total_hdd_space,
            )
        )

        results.append(
            nagiosplugin.Metric(
                name="used",
                value=self.total_hdd_space - free_hdd_space,
                uom="B",
                min=0,
                max=self.total_hdd_space,
            )
        )

        return results


class SystemDiskSummary(nagiosplugin.summary.Summary):
    def __init__(self, result_names: List[str]):
        super().__init__()
        self._result_names = result_names

    def ok(self, results):
        msgs = []
        for result_name in self._result_names:
            msgs.append(str(results[result_name]))
        return " ".join(msgs)


@cli.command("system.disk")
@click.option(
    "--used/--free",
    is_flag=True,
    default=True,
    help="Set if used or free memory should be checked. (Default: used)",
)
@click.option(
    "--warning",
    required=True,
    help="Warning threshold in % or MB. Example (20% oder 20 = 20MB)",
)
@click.option(
    "--critical",
    required=True,
    help="Critical threshold in % or MB. Example (20% oder 20 = 20MB)",
)
@click.option(
    "--bad-blocks-warning",
    help="Warning threshold for bad blocks. Example: 20 -> 20% bad blocks",
)
@click.option(
    "--bad-blocks-critical",
    help="Critical threshold for bad blocks",
)
@click.pass_context
@nagiosplugin.guarded
def system_disk(ctx, used, warning, critical, bad_blocks_warning, bad_blocks_critical):
    check = nagiosplugin.Check(
        SystemDiskResource(
            cmd_options=ctx.obj,
        )
    )

    if used:
        check.add(nagiosplugin.ScalarContext(
            name="free",
        ))
        check.add(ScalarPercentContext(
            name="used",
            total_name="total_hdd_space",
            warning=warning,
            critical=critical
        ))
    else:
        check.add(ScalarPercentContext(
            name="free",
            total_name="total_hdd_space",
            warning=f"{warning}:",
            critical=f"{critical}:"
        ))
        check.add(nagiosplugin.ScalarContext(
            name="used",
        ))

    check.add(nagiosplugin.ScalarContext(
        name="bad-blocks",
        warning=bad_blocks_warning,
        critical=bad_blocks_critical,
    ))

    check.add(nagiosplugin.ScalarContext(
        name="write-sect-since-reboot",
    ))

    check.add(nagiosplugin.ScalarContext(
        name="write-sect-total",
    ))

    check.add(SystemDiskSummary(
        result_names=["used"] if used else ["free"]
    ))

    check.main(verbose=ctx.obj["verbose"])
