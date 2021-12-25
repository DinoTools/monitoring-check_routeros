#!/usr/bin/env python3
import re
import ssl
from typing import Any, Dict, Optional, Tuple, Type

import click
import librouteros
import librouteros.query
import nagiosplugin


class BooleanContext(nagiosplugin.Context):
    def performance(self, metric, resource):
        return nagiosplugin.performance.Performance(
            label=metric.name,
            value=1 if metric.value else 0
        )


class RouterOSCheckResource(nagiosplugin.Resource):
    def __init__(self, cmd_options: Dict[str, Any]):
        self._cmd_options = cmd_options

    def _connect_api(self) -> librouteros.api.Api:
        def wrap_socket(socket):
            server_hostname: Optional[str] = self._cmd_options["hostname"]
            if server_hostname is None:
                server_hostname = self._cmd_options["host"]
            return ssl_ctx.wrap_socket(socket, server_hostname=server_hostname)

        port = self._cmd_options["port"]
        extra_kwargs = {}
        if self._cmd_options["ssl"]:
            if port is None:
                port = 8729
            ssl_ctx = ssl.create_default_context()

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


@click.group()
@click.option("--host", required=True)
@click.option("--hostname")
@click.option("--port", default=None)
@click.option("--username", required=True)
@click.option("--password", required=True)
@click.option("--ssl/--no-ssl", "use_ssl", default=True)
@click.option("--ssl-force-no-certificate", is_flag=True, default=False)
@click.option("--ssl-verify/--no-ssl-verify", default=True)
@click.option("--ssl-verify-hostname/--no-ssl-verify-hostname", default=True)
@click.option("-v", "--verbose", count=True)
@click.pass_context
def cli(ctx, host: str, hostname: Optional[str], port: int, username: str, password: str,
        use_ssl: bool, ssl_force_no_certificate: bool, ssl_verify: bool,
        ssl_verify_hostname: bool, verbose: int):
    ctx.ensure_object(dict)
    ctx.obj["host"] = host
    ctx.obj["hostname"] = hostname
    ctx.obj["port"] = port
    ctx.obj["username"] = username
    ctx.obj["password"] = password
    ctx.obj["ssl"] = use_ssl
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
