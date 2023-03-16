# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from typing import Optional, Union

import nagiosplugin


class BooleanContext(nagiosplugin.Context):
    def performance(self, metric, resource):
        return nagiosplugin.performance.Performance(
            label=metric.name,
            value=1 if metric.value else 0
        )


class ScalarPercentContext(nagiosplugin.ScalarContext):
    def __init__(self, name, total_name: Optional[str] = None, total_value: Optional[Union[int, float]] = None,
                 warning=None, critical=None, fmt_metric='{name} is {valueunit}', result_cls=nagiosplugin.Result):
        super(ScalarPercentContext, self).__init__(name, fmt_metric=fmt_metric, result_cls=result_cls)

        self._warning = warning
        self._critical = critical
        self._total_name = total_name
        self._total_value = total_value
        if self._total_value is None and self._total_name is None:
            raise ValueError("At least total_value or total_name must be given.")
        self.warning = nagiosplugin.Range(None)
        self.critical = nagiosplugin.Range(None)

    def _prepare_ranges(self, metric, resource):
        def replace(m):
            if m.group("unit") == "%":
                return str(float(total_value) * (float(m.group("value")) / 100))
            else:
                raise ValueError("Unable to convert type")

        if self._total_value is not None:
            total_value = self._total_value
        else:
            total_value = getattr(resource, self._total_name)
        regex = re.compile(r"(?P<value>[\d.]+)(?P<unit>[%])")

        if self._warning is not None:
            self.warning = nagiosplugin.Range(regex.sub(replace, self._warning))
        if self._critical is not None:
            self.critical = nagiosplugin.Range(regex.sub(replace, self._critical))

    def evaluate(self, metric, resource):
        self._prepare_ranges(metric, resource)
        return super(ScalarPercentContext, self).evaluate(metric, resource)

    def performance(self, metric, resource):
        self._prepare_ranges(metric, resource)
        return super(ScalarPercentContext, self).performance(metric, resource)
