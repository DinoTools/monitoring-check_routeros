# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any, Dict, Optional

import click
import librouteros
import librouteros.query
import nagiosplugin

from ..cli import cli
from ..context import BooleanContext
from ..helper import logger
from ..resource import RouterOSCheckResource


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
    def evaluate(self, metric, resource: RoutingOSPFNeighborResource):
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
@click.option(
    "--instance",
    required=True,
    help="The name of the OSPF instance",
)
@click.option(
    "--router-id",
    required=True,
    help="The ID of the neighbor router",
)
@click.pass_context
def routing_ospf_neighbors(ctx, instance, router_id):
    """Check the state of an OSPF neighbor"""
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
