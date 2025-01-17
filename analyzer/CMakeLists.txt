# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

spicy_add_analyzer(
    NAME HTTP
    PACKAGE_NAME HTTP
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek)
