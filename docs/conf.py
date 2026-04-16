# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
import sys
from pathlib import Path

sys.path.append(str(Path("_ext").resolve()))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "Octopus - Dynamic analysis framework"
copyright = "2026, Defensive Lab Agency - Esther Onfroy"
author = "Esther Onfroy"

autodoc_typehints = "description"
autodoc_typehints_description_target = "documented_params"
autoclass_content = "class"
autodoc_member_order = "groupwise"


extensions = [
    "colander",
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx_copybutton",
    "sphinx_rtd_theme",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.githubpages",
    "sphinxcontrib.datatemplates",
]

templates_path = ["_templates"]
html_static_path = ["_static"]
html_theme = "sphinx_rtd_theme"
html_logo = "_static/pts_logo.png"
html_theme_options = {
    "logo_only": False,
    "prev_next_buttons_location": "bottom",
    "style_external_links": False,
    "vcs_pageview_mode": "",
    "flyout_display": "hidden",
    "collapse_navigation": True,
    "sticky_navigation": True,
    "navigation_depth": 4,
    "titles_only": False,
}
html_css_files = [
    "css/table-fix.css",
    "css/theme-extra.css",
]

viewcode_line_numbers = True

napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = True
napoleon_preprocess_types = True
napoleon_use_param = True

exclude_patterns = []

autosummary_generate = True

intersphinx_mapping = {
    "pymisp": ("https://pymisp.readthedocs.io/en/latest", None),
    "adb-shell": ("https://adb-shell.readthedocs.io/en/stable", None),
    "jinja2": ("https://jinja.palletsprojects.com/en/stable", None),
    "python": ("https://docs.python.org/3", None),
}
