# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

from pprint import pformat
import re
from typing import Dict, List

import click
import nagiosplugin

from ..cli import cli
from ..helper import logger
from ..resource import RouterOSCheckResource


class SystemTemperatureResource(RouterOSCheckResource):
    name = "Temperature"

    def __init__(
        self,
        cmd_options,
        check: nagiosplugin.Check,
        warning_values: List[str],
        critical_values: List[str],
        use_regex: bool
    ):
        super().__init__(cmd_options=cmd_options)

        self._check = check

        self.values: Dict[str, float] = {}
        self.use_regex: bool = use_regex

        self.warning_values: Dict[str, str] = {}
        self.critical_values: Dict[str, str] = {}
        self.warning_regex_values: Dict[re.Pattern, str] = {}
        self.critical_regex_values: Dict[re.Pattern, str] = {}

        if self.use_regex:
            self.warning_regex_values = self.prepare_regex_thresholds(warning_values)
            self.critical_regex_values = self.prepare_regex_thresholds(critical_values)
        else:
            self.warning_values = self.prepare_thresholds(warning_values)
            self.critical_values = self.prepare_thresholds(critical_values)

    def probe(self):
        api = self._connect_api()

        logger.info("Fetching data ...")
        call = api.path(
            "/system/health"
        )
        results = tuple(call)
        result = results[0]
        logger.debug(f"Extracted values {pformat(result)}")

        regex_name = re.compile(r".*temperature.*")
        for name, value in result.items():
            m = regex_name.match(name)
            if not m:
                continue

            if self.use_regex:
                for regex, threshold in self.warning_regex_values.items():
                    if regex.match(name):
                        self.warning_values[name] = threshold
                        break

                for regex, threshold in self.critical_regex_values.items():
                    if regex.match(name):
                        self.critical_values[name] = threshold
                        break

            self.values[name] = float(value)

        for name, value in self.values.items():
            self._check.add(nagiosplugin.ScalarContext(
                name=name,
                warning=self.warning_values.get(name),
                critical=self.critical_values.get(name),
            ))
            yield nagiosplugin.Metric(
                name=name,
                value=value,
            )


@cli.command("system.temperature")
@click.option(
    "warning_values",
    "--value-warning",
    multiple=True,
    help=(
        "Set a warning threshold for a value. "
        "Example: If cpu-temperature should be in the range of 40 and 60°C you can set "
        "--value-warning cpu-temperature:40:60 "
        "If cpu-temperature should not be higher than 50.5°C you can set "
        "--value-warning cpu-temperature:50.5 "
        "Can be specified multiple times"
    )
)
@click.option(
    "critical_values",
    "--value-critical",
    multiple=True,
    help=(
        "Set a critical threshold for a value. "
        "Example: If cpu-temperature should be in the range of 40 and 60°C you can set "
        "--value-critical cpu-temperature:40:60 "
        "If cpu-temperature should not be higher than 50.5°C you can set "
        "--value-critical cpu-temperature:50.5 "
        "Can be specified multiple times"
    )
)
@click.option(
    "--regex",
    "use_regex",
    default=False,
    is_flag=True,
    help="Treat values from --value-warning and --value-critical as regex to find all matching values"
)
@click.pass_context
@nagiosplugin.guarded
def system_temperature(ctx, warning_values, critical_values, use_regex):
    """This command reads the information from /system/health and extracts all values containing the
    word temperature in its name. Like 'board-temperature', 'board-temperature1', 'cpu-temperature', ...

    Be aware that not all devices return the same values.
    """
    check = nagiosplugin.Check()

    temperature_resource = SystemTemperatureResource(
        cmd_options=ctx.obj,
        check=check,
        warning_values=warning_values,
        critical_values=critical_values,
        use_regex=use_regex,
    )
    check.add(temperature_resource)

    check.results.add(
        nagiosplugin.Result(
            nagiosplugin.state.Ok,
            hint="Looks like all temperatures are OK"
        )
    )

    check.main(verbose=ctx.obj["verbose"])
