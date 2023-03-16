# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later
from datetime import datetime
import re
import ssl
from typing import Any, Dict, List, Optional

import librouteros
import librouteros.query
import nagiosplugin

from .helper import logger
from .exeption import MissingValue


class RouterOSCheckResource(nagiosplugin.Resource):
    regex_datetime = re.compile(
        r"(?P<month>[a-z]{3})/(?P<day>\d+)/(?P<year>\d{4})\s+(?P<hour>\d+):(?P<minute>\d+):(?P<second>\d+)",
        flags=re.IGNORECASE
    )

    def __init__(self, cmd_options: Dict[str, Any]):
        self._cmd_options = cmd_options
        self._routeros_metric_values: List[Dict[str, Any]] = []
        self.current_time = datetime.now()

    @staticmethod
    def _calc_rate(
            cookie: nagiosplugin.Cookie,
            name: str,
            cur_value: int,
            elapsed_seconds: Optional[float],
            factor: int
    ) -> float:
        old_value: Optional[int] = cookie.get(name)
        cookie[name] = cur_value
        if old_value is None:
            raise MissingValue(f"Unable to find old value for '{name}'")
        if elapsed_seconds is None:
            raise MissingValue("Unable to get elapsed seconds")
        return (cur_value - old_value) / elapsed_seconds * factor

    def _connect_api(self) -> librouteros.api.Api:
        def wrap_socket(socket):
            server_hostname: Optional[str] = self._cmd_options["hostname"]
            if server_hostname is None:
                server_hostname = self._cmd_options["host"]
            return ssl_ctx.wrap_socket(socket, server_hostname=server_hostname)

        logger.info("Connecting to device ...")
        port = self._cmd_options["port"]
        extra_kwargs = {}
        if self._cmd_options["ssl"]:
            if port is None:
                port = 8729

            context_kwargs = {}
            if self._cmd_options["ssl_cafile"]:
                context_kwargs["cafile"] = self._cmd_options["ssl_cafile"]
            if self._cmd_options["ssl_capath"]:
                context_kwargs["capath"] = self._cmd_options["ssl_capath"]

            ssl_ctx = ssl.create_default_context(**context_kwargs)

            if self._cmd_options["ssl_force_no_certificate"]:
                ssl_ctx.check_hostname = False
                ssl_ctx.set_ciphers("ADH:@SECLEVEL=0")
            elif not self._cmd_options["ssl_verify"]:
                # We have do disable hostname check if we disable certificate verification
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            elif not self._cmd_options["ssl_verify_hostname"]:
                ssl_ctx.check_hostname = False

            extra_kwargs["ssl_wrapper"] = wrap_socket
        else:
            if port is None:
                port = 8728

        api = librouteros.connect(
            host=self._cmd_options["host"],
            username=self._cmd_options["username"],
            password=self._cmd_options["password"],
            port=port,
            **extra_kwargs
        )
        return api

    @classmethod
    def parse_routeros_datetime(cls, datetime_string: str) -> datetime:
        month_mapping: Dict[str, int] = {
            "jan": 1,
            "feb": 2,
            "mar": 3,
            "apr": 4,
            "may": 5,
            "jun": 6,
            "jul": 7,
            "aug": 8,
            "sep": 9,
            "oct": 10,
            "nov": 11,
            "dec": 12,
        }

        m = cls.regex_datetime.match(datetime_string)
        if not m:
            raise ValueError("Unable to parse datetime string")

        return datetime(
            year=int(m.group("year")),
            month=month_mapping[m.group("month").lower()],
            day=int(m.group("day")),
            hour=int(m.group("hour")),
            minute=int(m.group("minute")),
            second=int(m.group("second"))
        )

    @staticmethod
    def parse_routeros_speed(value_string: str) -> int:
        factors = {
            "": 1,
            "K": 1000,
            "M": 1000 * 1000,
            "G": 1000 * 1000 * 1000,
        }

        m = re.compile(r"(?P<value>\d+)(?P<factor>[A-Z]*)bps").match(value_string)
        if not m:
            raise ValueError(f"Unable to parse speed string: '{value_string}'")

        factor = factors.get(m.group("factor"))

        if factor is None:
            raise ValueError(f"Unable to parse element '{m.group()}' of speed string: '{value_string}'")

        return int(m.group("value")) * factor

    @staticmethod
    def parse_routeros_time(time_string: str) -> int:
        factors = {
            "s": 1,
            "m": 60,
            "h": 60 * 60,
            "d": 24 * 60 * 60,
            "w": 7 * 24 * 60 * 60,
        }

        seconds = 0
        for m in re.compile(r"(?P<value>\d+)(?P<type>[a-z]+)").finditer(time_string):
            factor = factors.get(m.group("type"))
            if factor is None:
                raise ValueError(f"Unable to parse element '{m.group()}' of time string: '{time_string}'")
            seconds += int(m.group("value")) * factor

        return seconds

    @staticmethod
    def prepare_override_values(override_values: List[str]) -> Dict[str, str]:
        results: Dict[str, str] = {}
        for override_value in override_values:
            name, _, value = override_value.partition(":")
            if value is None or value == "":
                logger.warning(f"Unable to parse override value for {name}")
            results[name] = value
        return results

    @staticmethod
    def prepare_thresholds(thresholds: List[str]) -> Dict[str, str]:
        results: Dict[str, str] = {}
        for threshold in thresholds:
            name, _, value = threshold.partition(":")
            if value is None or value == "":
                logger.warning(f"Unable to parse threshold for {name}")
            results[name] = value
        return results

    @staticmethod
    def prepare_regex_thresholds(thresholds: List[str]) -> Dict[re.Pattern, str]:
        results: Dict[re.Pattern, str] = {}
        for threshold in thresholds:
            name, _, value = threshold.partition(":")
            if value is None or value == "":
                logger.warning(f"Unable to parse threshold for {name}")
            results[re.compile(name)] = value
        return results

    def get_routeros_select_keys(self) -> List[librouteros.query.Key]:
        keys = []
        for metric_value in self._routeros_metric_values:
            keys.append(librouteros.query.Key(metric_value["name"]))
        return keys

    def get_routeros_metrics(self, result: Dict[str, Any], name_prefix="", cookie=None) -> List[nagiosplugin.Metric]:
        metrics = []

        elapsed_seconds = None
        if cookie:
            last_time_tuple = cookie.get("last_time")
            if isinstance(last_time_tuple, (list, tuple)):
                last_time = datetime(*last_time_tuple[0:6])
                delta_time = self.current_time - last_time
                elapsed_seconds = delta_time.total_seconds()

        #
        for metric_value in self._routeros_metric_values:
            metric_value_name = metric_value["name"]
            if metric_value.get("missing_ok", False) and metric_value_name not in result:
                continue

            value = result[metric_value_name]
            metric_value_type = metric_value.get("type")
            if callable(metric_value_type):
                try:
                    value = metric_value_type(value)
                except ValueError as e:
                    logger.warning(f"Error parsing value with name {metric_value_name}", exc_info=True)
                    raise e

            value = value * metric_value.get("factor", 1)

            extra_kwargs = {}
            for n in ("min", "max", "uom"):
                if n in metric_value:
                    extra_kwargs[n] = metric_value[n]

            dst_value_name = metric_value.get("dst_value_name")
            if isinstance(dst_value_name, str):
                result[dst_value_name] = value

            if not metric_value.get("no_metric"):
                metrics.append(
                    nagiosplugin.Metric(
                        name=name_prefix + metric_value.get("dst", metric_value_name),
                        value=value,
                        **extra_kwargs,
                    )
                )

            if metric_value.get("rate"):
                try:
                    rate_value = self._calc_rate(
                        cookie=cookie,
                        name=metric_value_name,
                        cur_value=value,
                        elapsed_seconds=elapsed_seconds,
                        factor=metric_value.get("rate_factor", 1)
                    )
                    metrics.append(
                        nagiosplugin.Metric(
                            name=f"{name_prefix}{metric_value.get('dst', metric_value_name)}_rate",
                            value=rate_value,
                            uom=metric_value.get("rate_uom"),
                            min=metric_value.get("rate_min"),
                            max=metric_value.get("rate_max"),
                        )
                    )
                except MissingValue as e:
                    logger.debug(f"{e}", exc_info=e)

        if cookie:
            cookie["last_time"] = self.current_time.timetuple()

        return metrics
