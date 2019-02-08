"""
UWSGI integration for the API module.
"""
from acme_chief import api
app = api.create_app()  # pylint: disable=invalid-name
