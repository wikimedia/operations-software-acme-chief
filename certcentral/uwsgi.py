"""
UWSGI integration for the API module.
"""
from certcentral import api
app = api.create_app()  # pylint: disable=invalid-name
