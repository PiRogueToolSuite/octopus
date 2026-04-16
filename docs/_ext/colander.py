# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from docutils import nodes
from docutils.nodes import Node, system_message
from sphinx.application import Sphinx
from sphinx.roles import GUILabel
from sphinx.util.typing import ExtensionMetadata


class TextMonoRole(GUILabel):
    def run(self) -> tuple[list[Node], list[system_message]]:
        node = nodes.inline(rawtext=self.rawtext, classes=[self.name])
        node += nodes.Text(self.text)
        return [node], []


class TextMonoBorderRole(TextMonoRole):
    def run(self) -> tuple[list[Node], list[system_message]]:
        return super().run()


class ColanderTypeRole(TextMonoRole):
    def run(self) -> tuple[list[Node], list[system_message]]:
        node = nodes.inline(rawtext=self.rawtext, classes=[self.name])
        spans = self.text.split(":")
        node += nodes.inline("", "", nodes.Text(spans[0]), classes=["prefix"])
        node += nodes.Text(spans[1])
        return [node], []


class OtherTypeRole(ColanderTypeRole):
    def run(self) -> tuple[list[Node], list[system_message]]:
        return super().run()


def setup(app: Sphinx) -> ExtensionMetadata:
    app.add_role("colandertype", ColanderTypeRole())
    app.add_role("othertype", OtherTypeRole())
    app.add_role("textmono", TextMonoRole())
    app.add_role("textmonoborder", TextMonoBorderRole())

    return {
        "version": "0.1",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
