#!/usr/bin/env python3
# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later
from datetime import datetime
import logging
import re
import ssl
from typing import Any, Dict, List, Optional, Tuple, Union

import click
import librouteros
import librouteros.query
import nagiosplugin

logger = logging.getLogger('nagiosplugin')


class BooleanContext(nagiosplugin.Context):
    def performance(self, metric, resource):
        return nagiosplugin.performance.Performance(
            label=metric.name,
            value=1 if metric.value else 0
        )


class RouterOSCheckResource(nagiosplugin.Resource):
    regex_datetime = re.compile(
        r"(?P<month>[a-z]{3})/(?P<day>\d+)/(?P<year>\d{4})\s+(?P<hour>\d+):(?P<minute>\d+):(?P<second>\d+)",
        flags=re.IGNORECASE
    )

    def __init__(self, cmd_options: Dict[str, Any]):
        self._cmd_options = cmd_options
        self._routeros_metric_values: List[Dict[str, Any]] = []

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
            "mai": 5,
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

    def get_routeros_select_keys(self) -> List[librouteros.query.Key]:
        keys = []
        for metric_value in self._routeros_metric_values:
            keys.append(librouteros.query.Key(metric_value["name"]))
        return keys

    def get_routeros_metrics(self, result: Dict[str, Any], name_prefix="") -> List[nagiosplugin.Metric]:
        metrics = []
        for metric_value in self._routeros_metric_values:
            value = result[metric_value["name"]]
            if metric_value["type"] is not None:
                value = metric_value["type"](value)

            extra_kwargs = {}
            for n in ("min", "max", "uom"):
                if n in metric_value:
                    extra_kwargs[n] = metric_value[n]

            metrics.append(
                nagiosplugin.Metric(
                    name=name_prefix + metric_value.get("dst", metric_value["name"]),
                    value=value,
                    **extra_kwargs,
                )
            )
        return metrics


class ScalarPercentContext(nagiosplugin.ScalarContext):
    def __init__(self, name, total_name: str, warning=None, critical=None,
                 fmt_metric='{name} is {valueunit}', result_cls=nagiosplugin.Result):
        super(ScalarPercentContext, self).__init__(name, fmt_metric=fmt_metric, result_cls=result_cls)

        self._warning = warning
        self._critical = critical
        self._total_name = total_name
        self.warning = None
        self.critical = None

    def _prepare_ranges(self, metric, resource):
        def replace(m):
            if m.group("unit") == "%":
                return str(float(total_value) * (float(m.group("value")) / 100))
            else:
                raise ValueError("Unable to convert type")

        if self.warning is not None and self.critical is not None:
            return

        total_value = getattr(resource, self._total_name)
        regex = re.compile(r"(?P<value>\d+)(?P<unit>[%])")

        print(regex.sub(replace, self._warning))
        print(regex.sub(replace, self._critical))

        self.warning = nagiosplugin.Range(regex.sub(replace, self._warning))
        self.critical = nagiosplugin.Range(regex.sub(replace, self._critical))

    def evaluate(self, metric, resource):
        self._prepare_ranges(metric, resource)
        return super(ScalarPercentContext, self).evaluate(metric, resource)

    def performance(self, metric, resource):
        self._prepare_ranges(metric, resource)
        return super(ScalarPercentContext, self).performance(metric, resource)


@click.group()
@click.option("--host", required=True)
@click.option("--hostname")
@click.option("--port", default=None)
@click.option("--username", required=True)
@click.option("--password", required=True)
@click.option("--ssl/--no-ssl", "use_ssl", default=True)
@click.option("--ssl-cafile")
@click.option("--ssl-capath")
@click.option("--ssl-force-no-certificate", is_flag=True, default=False)
@click.option("--ssl-verify/--no-ssl-verify", default=True)
@click.option("--ssl-verify-hostname/--no-ssl-verify-hostname", default=True)
@click.option("-v", "--verbose", count=True)
@click.pass_context
def cli(ctx, host: str, hostname: Optional[str], port: int, username: str, password: str,
        use_ssl: bool, ssl_cafile: Optional[str], ssl_capath: Optional[str], ssl_force_no_certificate: bool,
        ssl_verify: bool, ssl_verify_hostname: bool, verbose: int):
    ctx.ensure_object(dict)
    ctx.obj["host"] = host
    ctx.obj["hostname"] = hostname
    ctx.obj["port"] = port
    ctx.obj["username"] = username
    ctx.obj["password"] = password
    ctx.obj["ssl"] = use_ssl
    ctx.obj["ssl_cafile"] = ssl_cafile
    ctx.obj["ssl_capath"] = ssl_capath
    ctx.obj["ssl_force_no_certificate"] = ssl_force_no_certificate
    ctx.obj["ssl_verify"] = ssl_verify
    ctx.obj["ssl_verify_hostname"] = ssl_verify_hostname
    ctx.obj["verbose"] = verbose


#########################
# Check: Interface VRRP #
#########################
class InterfaceVrrpCheck(RouterOSCheckResource):
    name = "VRRP"

    def __init__(self, cmd_options, name, master_must):
        super().__init__(cmd_options=cmd_options)

        self._name = name
        self.backup = None
        self.disabled = None
        self.enabled = None
        self.invalid = None
        self.master = None
        self.master_must = master_must
        self.running = None

    def probe(self):
        key_name = librouteros.query.Key("name")
        api = self._connect_api()

        logger.info("Fetching data ...")
        call = api.path(
            "/interface/vrrp"
        ).select(
            key_name,
            librouteros.query.Key("backup"),
            librouteros.query.Key("disabled"),
            librouteros.query.Key("invalid"),
            librouteros.query.Key("master"),
            librouteros.query.Key("running"),
        ).where(
            key_name == self._name
        )
        results = tuple(call)
        result = results[0]

        self.disabled = result["disabled"]
        self.enabled = not self.disabled

        yield nagiosplugin.Metric(
            name="disabled",
            value=self.disabled,
        )

        if self.enabled:
            for n in ("backup", "invalid", "master", "running"):
                if n not in result:
                    continue

                setattr(self, n, result[n])
                yield nagiosplugin.Metric(
                    name=n,
                    value=result[n],
                )


class InterfaceVrrpDisabled(BooleanContext):
    def evaluate(self, metric, resource: InterfaceVrrpCheck):
        if metric.value is True:
            return self.result_cls(nagiosplugin.state.Warn, "VRRP is disabled", metric)
        return self.result_cls(nagiosplugin.state.Ok)


class InterfaceVrrpInvalid(BooleanContext):
    def evaluate(self, metric, resource: InterfaceVrrpCheck):
        if metric.value is True:
            return self.result_cls(
                state=nagiosplugin.state.Warn,
                hint="VRRP config is invalid"
            )
        return self.result_cls(nagiosplugin.state.Ok)


class InterfaceVrrpMaster(BooleanContext):
    def evaluate(self, metric, resource: InterfaceVrrpCheck):
        if not metric.value and resource.master_must:
            return self.result_cls(
                state=nagiosplugin.state.Warn,
                hint="VRRP interface is not master"
            )
        return self.result_cls(nagiosplugin.state.Ok)


@cli.command("interface.vrrp")
@click.option("--name", required=True)
@click.option("--master", default=False)
@click.pass_context
def interface_vrrp(ctx, name, master):
    check = nagiosplugin.Check(
        InterfaceVrrpCheck(
            cmd_options=ctx.obj,
            name=name,
            master_must=master,
        ),
        BooleanContext("backup"),
        InterfaceVrrpDisabled("disabled"),
        InterfaceVrrpInvalid("invalid"),
        InterfaceVrrpMaster("master"),
        BooleanContext("running")
    )

    check.main(verbose=ctx.obj["verbose"])


################################
# Check: Routing BGP Peers     #
################################
class RoutingBGPPeerResource(RouterOSCheckResource):
    name = "BGP Peer"

    def __init__(
            self,
            cmd_options: Dict[str, Any],
            names: List[str],
            regex: bool,
            single_peer: bool,
    ):
        super().__init__(cmd_options=cmd_options)

        self._peer_data: Optional[Dict[str, Any]] = None
        self.names: List[Union[Any]] = names
        self.regex = regex
        if self.regex:
            regex_names = []
            for name in names:
                regex_names.append(re.compile(name))
            self.names = regex_names
        self.single_peer = single_peer
        self.state: Optional[str] = None

        self._routeros_metric_values = [
            {"name": "disabled", "type": bool},
            {"name": "prefix-count", "dst": "prefix_count", "type": int},
            {"name": "state", "type": str},
            {"name": "updates-received", "dst": "updates_received", "type": int},
            {"name": "updates-sent", "dst": "updates_sent", "type": int},
            {"name": "uptime", "type": self.parse_routeros_time, "min": 0, "uom": "s"},
        ]

    def fetch_data(self) -> Dict[str, Dict]:
        if self._peer_data:
            return self._peer_data

        api = self._connect_api()

        logger.info("Fetching data ...")
        call = api.path(
            "/routing/bgp/peer"
        )
        call_results = tuple(call)

        self._peer_data = {}
        for result in call_results:
            if self.regex:
                for name in self.names:
                    if name.match(result["name"]):
                        self._peer_data[result["name"]] = result
            elif result["name"] in self.names:
                self._peer_data[result["name"]] = result
        return self._peer_data

    @property
    def peer_names(self):
        return tuple(self.fetch_data().keys())

    def probe(self):
        routeros_metrics = []
        data = self.fetch_data()

        if self.single_peer:
            if len(self.peer_names) == 1:
                return self.get_routeros_metrics(data[self.peer_names[0]])
        else:
            for name in self.peer_names:
                routeros_metrics += self.get_routeros_metrics(data[name], name_prefix=f"{name} ")

        return routeros_metrics


class RoutingBGPPeerState(BooleanContext):
    def __init__(self, *args, **kwargs):
        super(RoutingBGPPeerState, self).__init__(*args, **kwargs)
        self.fmt_metric = "{name} is {valueunit}"

    def evaluate(self, metric, resource: RoutingBGPPeerResource):
        if metric.value is None:
            return nagiosplugin.Result(
                state=nagiosplugin.state.Critical,
                # hint=f"Neighbor for instance '{resource.instance}' and router-id '{resource.router_id}' not found"
            )

        value = metric.value
        if value in ("established",):
            return self.result_cls(
                state=nagiosplugin.state.Ok,
                hint="Connection with peer established",
            )

        elif value in ("idle", "connect", "active", "opensent", "openconfirm"):
            return self.result_cls(
                state=nagiosplugin.state.Critical,
                hint=f"Connection to peer not established (State: {value})"
            )
        else:
            return self.result_cls(
                state=nagiosplugin.state.Unknown,
                hint=f"Unable to find peer state (State: {value})"
            )


class RoutingBGPPeerSummary(nagiosplugin.Summary):
    def ok(self, results: List[nagiosplugin.Result]):
        for result in results:
            if isinstance(result.resource, RoutingBGPPeerResource):
                data = result.resource.fetch_data()
                texts = []
                for name in result.resource.peer_names:
                    texts.append(f"Connection to {name} is {data[name]['state']}")
                return ", ".join(texts)

        return ""


@cli.command("routing.bgp.peers")
@click.option("--name", "names", default=[], multiple=True)
@click.option("--regex", "regex", default=False, is_flag=True)
@click.option("--single", "single", default=False, is_flag=True)
@click.pass_context
def routing_bgp_peer(ctx, names, regex, single):
    resource = RoutingBGPPeerResource(
        cmd_options=ctx.obj,
        names=names,
        regex=regex,
        single_peer=single,
    )
    check = nagiosplugin.Check(
        resource,
        RoutingBGPPeerSummary(),
    )

    if single:
        if len(resource.peer_names) == 1:
            check.add(
                BooleanContext("disabled"),
                RoutingBGPPeerState("state"),
                nagiosplugin.ScalarContext("prefix_count"),
                nagiosplugin.ScalarContext("uptime"),
                nagiosplugin.ScalarContext("updates_received"),
                nagiosplugin.ScalarContext("updates_sent"),
            )
        else:
            check.results.add(
                nagiosplugin.Result(
                    nagiosplugin.state.Unknown,
                    f"Only one matching peer is allowed. Found {len(resource.peer_names)}"
                )
            )
    else:
        for name in resource.peer_names:
            check.add(
                BooleanContext(f"{name} disabled"),
                RoutingBGPPeerState(f"{name} state"),
                nagiosplugin.ScalarContext(f"{name} prefix_count"),
                nagiosplugin.ScalarContext(f"{name} uptime"),
                nagiosplugin.ScalarContext(f"{name} updates_received"),
                nagiosplugin.ScalarContext(f"{name} updates_sent"),
            )

    check.main(verbose=ctx.obj["verbose"])


################################
# Check: Routing OSPF Neighbor #
################################
class RoutingOSPFNeighborResource(RouterOSCheckResource):
    name = "OSPF NEIGHBOR"

    def __init__(
            self,
            cmd_options: Dict[str, Any],
            instance: str,
            router_id: str,
            area: Optional[str] = None
    ):
        super().__init__(cmd_options=cmd_options)

        self.area = area
        self.instance = instance
        self.router_id = router_id

        self.state: Optional[str] = None

        self._routeros_metric_values = [
            {"name": "priority", "type": int},
            {"name": "adjacency", "type": self.parse_routeros_time, "min": 0, "uom": "s"},
            {"name": "state", "type": None},
            {"name": "state-changes", "dst": "state_changes", "type": int},
            {"name": "ls-retransmits", "dst": "ls_retransmits", "type": int},
            {"name": "ls-requests", "dst": "ls_requests", "type": int},
            {"name": "db-summaries", "dst": "db_summaries", "type": int},
        ]

    def probe(self):
        # ToDo: Only available in v7.x
        # key_area = librouteros.query.Key("area")
        key_instance = librouteros.query.Key("instance")
        key_router_id = librouteros.query.Key("router-id")

        api = self._connect_api()

        logger.info("Fetching data ...")

        call = api.path(
            "/routing/ospf/neighbor"
        ).select(
            key_instance,
            # key_area,
            key_router_id,
            *self.get_routeros_select_keys()
        ).where(
            key_instance == self.instance,
            # key_area == self._area,
            key_router_id == self.router_id
        )
        results = tuple(call)
        if len(results) == 0:
            return nagiosplugin.Metric(
                name="state",
                value=None
            )

        result = results[0]

        return self.get_routeros_metrics(result)


class RoutingOSPFNeighborState(BooleanContext):
    def evaluate(self, metric, resource: InterfaceVrrpCheck):
        if metric.value is None:
            return nagiosplugin.Result(
                state=nagiosplugin.state.Critical,
                hint=f"Neighbor for instance '{resource.instance}' and router-id '{resource.router_id}' not found"
            )
        elif metric.value in ("Down",):
            return self.result_cls(
                state=nagiosplugin.state.Critical,
                hint="Linkt to neighbor down"
            )
        elif metric.value in ("Full",):
            return self.result_cls(
                state=nagiosplugin.state.Ok,
                hint="Communicating with neighbor"
            )
        else:
            return self.result_cls(
                state=nagiosplugin.state.Warn,
                hint=f"Link to neighbor not fully up, state: {metric.value}"
            )


@cli.command("routing.ospf.neighbors")
@click.option("--instance", required=True)
@click.option("--router-id", required=True)
@click.pass_context
def routing_ospf_neighbors(ctx, instance, router_id):
    resource = RoutingOSPFNeighborResource(
        cmd_options=ctx.obj,
        instance=instance,
        router_id=router_id,
    )
    check = nagiosplugin.Check(
        resource,
        nagiosplugin.ScalarContext("priority"),
        nagiosplugin.ScalarContext("adjacency"),
        nagiosplugin.ScalarContext("state_changes"),
        nagiosplugin.ScalarContext("ls_retransmits"),
        nagiosplugin.ScalarContext("ls_requests"),
        nagiosplugin.ScalarContext("db_summaries"),
        RoutingOSPFNeighborState("state")
    )

    check.main(verbose=ctx.obj["verbose"])


#########################
# System License        #
#########################
class SystemLicenseResource(RouterOSCheckResource):
    name = "License"

    def __init__(self, cmd_options):
        super().__init__(cmd_options=cmd_options)

        def days_left(value):
            time_delta = self.parse_routeros_datetime(value) - datetime.now()
            return int(time_delta.total_seconds()) / 60 / 60 / 24

        self.api = self._connect_api()

        logger.info("Fetching information ...")
        call = self.api.path(
            "/system/resource"
        )
        result = tuple(call)[0]

        self.has_renewal = result["board-name"].lower() == "chr"

        self.deadline_datetime: Optional[datetime] = None
        self.next_renewal_datetime: Optional[datetime] = None

        self._routeros_metric_values = []

        if self.has_renewal:
            self._routeros_metric_values += [
                {"name": "level", "type": None},
                {"name": "deadline-at", "dst": "deadline-in", "type": days_left},
                {"name": "next-renewal-at", "dst": "next-renewal-in", "type": days_left},
            ]
        else:
            self._routeros_metric_values += [
                {"name": "nlevel", "dst": "level", "type": None},
            ]

    def probe(self):
        logger.info("Fetching data ...")
        call = self.api.path(
            "/system/license"
        )
        result = tuple(call)[0]

        if self.has_renewal:
            if "deadline-at" in result:
                self.deadline_datetime = self.parse_routeros_datetime(result["deadline-at"])
            if "next-renewal-at" in result:
                self.next_renewal_datetime = self.parse_routeros_datetime(result["next-renewal-at"])

        return self.get_routeros_metrics(result)


class SystemLicenseRenewSummary(nagiosplugin.Summary):
    def ok(self, results: List[nagiosplugin.Result]):
        hints = []
        resource: Optional[SystemLicenseResource] = None
        for result in results:
            if result.resource:
                resource = result.resource
            if result.hint:
                hints.append(result.hint)

        if resource and resource.has_renewal:
            if resource.next_renewal_datetime:
                time_delta = resource.next_renewal_datetime - datetime.now()
                hints.append(f"Next renewal in {time_delta.days} day(s) ({resource.next_renewal_datetime})")
            if resource.deadline_datetime:
                time_delta = resource.deadline_datetime - datetime.now()
                hints.append(f"Deadline in {time_delta.days} day(s) ({resource.deadline_datetime})")

        return ", ".join(hints)


class SystemLicenseLevelContext(nagiosplugin.Context):
    def __init__(self, *args, levels=None, **kwargs):
        self._levels = levels
        super(SystemLicenseLevelContext, self).__init__(*args, **kwargs)

    def evaluate(self, metric, resource):
        if self._levels is None or str(metric.value) in self._levels:
            return nagiosplugin.Result(
                nagiosplugin.Ok,
                hint=f"License level is '{metric.value}'"
            )

        return nagiosplugin.Result(
            nagiosplugin.Warn,
            hint=f"License level '{metric.value}' not in list with allowed levels: {', '.join(self._levels)}"
        )


@cli.command("system.license")
@click.option("--deadline-warning", default="28:", help="Number of days until deadline is reached (Default: '28:')")
@click.option("--deadline-critical", default="14:", help="Number of days until deadline is reached (Default: '14:')")
@click.option(
    "--next-renewal-warning",
    default=None,
    help="Number of days until renewal is done (Default: None, Example: '-14:')"
)
@click.option("--next-renewal-critical", default=None, help="Number of days until renewal is done (Default: None)")
@click.option(
    "--level",
    "levels",
    default=None,
    multiple=True,
    help="Allowed license levels. Repeat to use multiple values."
)
@click.pass_context
@nagiosplugin.guarded
def system_license(ctx, deadline_warning, deadline_critical, next_renewal_warning, next_renewal_critical, levels):
    resource = SystemLicenseResource(
        cmd_options=ctx.obj,
    )
    check = nagiosplugin.Check(resource)

    if resource.has_renewal:
        check.add(
            nagiosplugin.ScalarContext(
                name="deadline-in",
                warning=deadline_warning,
                critical=deadline_critical,
            ),
            nagiosplugin.ScalarContext(
                name="next-renewal-in",
                warning=next_renewal_warning,
                critical=next_renewal_critical,
            ),
            SystemLicenseRenewSummary(),
        )

    check.add(
        SystemLicenseLevelContext(
            name="level",
            levels=levels,
        )
    )

    check.main(verbose=ctx.obj["verbose"])


#########################
# System Memory         #
#########################
class SystemMemoryResource(RouterOSCheckResource):
    name = "MEMORY"

    def __init__(self, cmd_options):
        super().__init__(cmd_options=cmd_options)

        self.memory_total = None

    def probe(self):
        api = self._connect_api()

        logger.info("Fetching data ...")
        call = api.path(
            "/system/resource"
        ).select(
            librouteros.query.Key("free-memory"),
            librouteros.query.Key("total-memory")
        )
        results = tuple(call)
        result = results[0]

        memory_free = result["free-memory"]
        self.memory_total = result["total-memory"]

        yield nagiosplugin.Metric(
            name="free",
            value=memory_free,
            uom="B",
            min=0,
            max=self.memory_total,
        )

        yield nagiosplugin.Metric(
            name="used",
            value=self.memory_total - memory_free,
            uom="B",
            min=0,
            max=self.memory_total,
        )


class SystemMemorySummary(nagiosplugin.summary.Summary):
    def __init__(self, result_names: List[str]):
        super().__init__()
        self._result_names = result_names

    def ok(self, results):
        msgs = []
        for result_name in self._result_names:
            msgs.append(str(results[result_name]))
        return " ".join(msgs)


@cli.command("system.memory")
@click.option("--used/--free", is_flag=True, default=True)
@click.option("--warning", required=True)
@click.option("--critical", required=True)
@click.pass_context
@nagiosplugin.guarded
def system_memory(ctx, used, warning, critical):
    check = nagiosplugin.Check(
        SystemMemoryResource(
            cmd_options=ctx.obj,
        )
    )

    if used:
        check.add(nagiosplugin.ScalarContext(
            name="free",
        ))
        check.add(ScalarPercentContext(
            name="used",
            total_name="memory_total",
            warning=warning,
            critical=critical
        ))
    else:
        check.add(ScalarPercentContext(
            name="free",
            total_name="memory_total",
            warning=f"{warning}:",
            critical=f"{critical}:"
        ))
        check.add(nagiosplugin.ScalarContext(
            name="used",
        ))

    check.add(SystemMemorySummary(
        result_names=["used"] if used else ["free"]
    ))

    check.main(verbose=ctx.obj["verbose"])


#########################
# System Uptime         #
#########################
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
            value=self.parse_routeros_time(result["uptime"]),
            uom="s",
            min=0,
        )


@cli.command("system.uptime")
@click.pass_context
@nagiosplugin.guarded
def system_uptime(ctx):
    check = nagiosplugin.Check(
        SystemUptimeResource(
            cmd_options=ctx.obj,
        ),
        nagiosplugin.ScalarContext(
            name="uptime",
        )
    )

    check.main(verbose=ctx.obj["verbose"])


#########################
# Tool Ping Check       #
#########################
class ToolPingCheck(RouterOSCheckResource):
    name = "PING"

    def __init__(self, cmd_options, address):
        super().__init__(cmd_options=cmd_options)

        self._address = address
        self._max_packages = 1

    def probe(self):
        def strip_time(value) -> Tuple[Optional[int], Optional[str]]:
            m = re.compile(r"^(?P<time>[0-9]+)(?P<uom>.*)$").match(value)
            if m:
                return int(m.group("time")), m.group("uom")
            return None, None

        params = {"address": self._address, "count": self._max_packages}
        api = self._connect_api()

        logger.info("Call /ping command ...")
        call = api("/ping", **params)
        results = tuple(call)
        result = results[-1]

        yield nagiosplugin.Metric(
            name="packet_loss",
            value=result["packet-loss"],
            uom="%",
            min=0,
            max=100,
        )
        yield nagiosplugin.Metric(
            name="sent",
            value=result["sent"],
            min=0,
            max=self._max_packages,
        )
        yield nagiosplugin.Metric(
            name="received",
            value=result["received"],
            min=0,
            max=self._max_packages,
        )

        if result["received"] > 0:
            yield nagiosplugin.Metric(
                name="rtt_min",
                value=strip_time(result["min-rtt"])[0],
                min=0,
            )
            yield nagiosplugin.Metric(
                name="rtt_max",
                value=strip_time(result["max-rtt"])[0],
                min=0,
            )
            yield nagiosplugin.Metric(
                name="rtt_avg",
                value=strip_time(result["avg-rtt"])[0],
                min=0,
            )
            yield nagiosplugin.Metric(
                name="size",
                value=result["size"]
            )
            yield nagiosplugin.Metric(
                name="ttl",
                value=result["ttl"],
                min=0,
                max=255,
            )


@cli.command("tool.ping")
@click.option("--address", required=True)
@click.option("--packet-loss-warning")
@click.option("--packet-loss-critical")
@click.option("--ttl-warning")
@click.option("--ttl-critical")
@click.pass_context
def tool_ping(ctx, address, packet_loss_warning, packet_loss_critical, ttl_warning, ttl_critical):
    check = nagiosplugin.Check(
        ToolPingCheck(
            cmd_options=ctx.obj,
            address=address
        )
    )

    check.add(nagiosplugin.ScalarContext(
        name="packet_loss",
        warning=packet_loss_warning,
        critical=packet_loss_critical
    ))
    check.add(nagiosplugin.ScalarContext(
        name="sent"
    ))
    check.add(nagiosplugin.ScalarContext(
        name="received"
    ))

    check.add(nagiosplugin.ScalarContext(
        name="rtt_avg"
    ))
    check.add(nagiosplugin.ScalarContext(
        name="rtt_min"
    ))
    check.add(nagiosplugin.ScalarContext(
        name="rtt_max"
    ))

    check.add(nagiosplugin.ScalarContext(
        name="size"
    ))
    check.add(nagiosplugin.ScalarContext(
        name="ttl",
        warning=ttl_warning,
        critical=ttl_critical
    ))

    check.main(verbose=ctx.obj["verbose"])


if __name__ == "__main__":
    cli()
