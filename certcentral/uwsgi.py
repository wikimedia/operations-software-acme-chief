"""
UWSGI integration for the API module.
"""
from certcentral import certcentral_api
app = certcentral_api.create_app()  # pylint: disable=invalid-name
