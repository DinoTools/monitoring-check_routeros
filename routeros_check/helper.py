# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib
import logging
import os
import re
from typing import List, Optional

logger = logging.getLogger('nagiosplugin')


def escape_filename(value):
    value = re.sub(r"[^\w\s-]", "_", value).strip().lower()
    return re.sub(r"[-\s]+", '-', value)


def load_modules(pkg_names: Optional[List] = None):
    if pkg_names is None:
        pkg_names = [".check"]
    for base_pkg_name in pkg_names:
        logger.debug("Base package name: %s", base_pkg_name)
        base_pkg = importlib.import_module(base_pkg_name, package=__package__)

        logger.debug("Base package: %s", base_pkg)

        path = base_pkg.__path__[0]
        logger.debug("Base path: %s", path)

        for filename in os.listdir(path):
            if filename == "__init__.py":
                continue

            pkg_name = None
            if os.path.isdir(os.path.join(path, filename)) and \
                    os.path.exists(os.path.join(path, filename, "__init__.py")):
                pkg_name = filename

            if filename[-3:] == '.py':
                pkg_name = filename[:-3]

            if pkg_name is None:
                continue

            mod_name = "{}.{}".format(base_pkg_name, pkg_name)
            try:
                importlib.import_module(mod_name, package=__package__)
                logger.info("Loaded '%s' successfully", mod_name)
            except ImportError:
                logger.warning("Unable to load: '%s'", mod_name)
                logger.debug("An error occurred while importing '%s'", mod_name, exc_info=True)
