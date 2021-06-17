"""The module contains functions for the docs route."""
from flask import render_template, request
from easywall.web.login import login
from easywall.web.webutils import Webutils


def docs() -> str:
    """Return the docs page when the user is logged in."""
    utils = Webutils()
    if utils.check_login(request) is True:
        return render_template(utils.cfg.get_value("uwsgi", "docs-page"), vars=utils.get_default_payload("Docs"))
    return login()
