"""
Module containing OCSP helper classes

Valentin Gutierrez <vgutierrez@wikimedia.org> 2019
"""

from enum import Enum

import requests
from requests.exceptions import HTTPError, Timeout, TooManyRedirects

from cryptography.x509 import ocsp as crypto_ocsp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA1

CRYPTOGRAPHY_BACKEND = default_backend()

OCSP_ENDPOINT_TIMEOUT = 2.0


class OCSPResponseStatus(Enum):
    """OCSP Response Status"""
    SUCCESSFUL = crypto_ocsp.OCSPResponseStatus.SUCCESSFUL.value
    MALFORMED_REQUEST = crypto_ocsp.OCSPResponseStatus.MALFORMED_REQUEST.value
    INTERNAL_ERROR = crypto_ocsp.OCSPResponseStatus.INTERNAL_ERROR.value
    TRY_LATER = crypto_ocsp.OCSPResponseStatus.TRY_LATER.value
    SIG_REQUIRED = crypto_ocsp.OCSPResponseStatus.SIG_REQUIRED.value
    UNAUTHORIZED = crypto_ocsp.OCSPResponseStatus.UNAUTHORIZED.value


class OCSPCertStatus(Enum):
    """OCSP Certificate Status"""
    GOOD = crypto_ocsp.OCSPCertStatus.GOOD.value
    REVOKED = crypto_ocsp.OCSPCertStatus.REVOKED.value
    UNKNOWN = crypto_ocsp.OCSPCertStatus.UNKNOWN.value


class OCSPError(Exception):
    """Base OCSP Error class"""


class OCSPRequestError(OCSPError):
    """OCSP Request Error"""


class OCSPResponseError(OCSPError):
    """OCSP Response Error"""


class OCSPRequest:
    """OCSP request builder"""
    def __init__(self, certificate, issuer):
        if certificate.ocsp_uri is None:
            raise ValueError('certificate must provide an OCSP URI')

        self.certificate = certificate
        self._builder = crypto_ocsp.OCSPRequestBuilder()
        self._builder = self._builder.add_certificate(certificate.certificate, issuer.certificate, SHA1())

    @property
    def ocsp_request(self):
        """The returned value can be sent to the OCSP endpoint of the certificate"""
        return self._builder.build().public_bytes(serialization.Encoding.DER)

    def fetch_response(self, **kwargs):
        """Attempt to fetch an OCSPResponse for the current OCSPRequest"""
        timeout = kwargs.get('timeout', OCSP_ENDPOINT_TIMEOUT)
        try:
            http_request = requests.post(self.certificate.ocsp_uri, data=self.ocsp_request, timeout=timeout)
            http_request.raise_for_status()
        except (HTTPError, Timeout, TooManyRedirects) as request_error:
            raise OCSPRequestError from request_error

        return OCSPResponse(http_request.content)


class OCSPResponse:
    """OCSP Response"""
    def __init__(self, der_response):
        self.der_response = der_response
        try:
            self._response = crypto_ocsp.load_der_ocsp_response(der_response)
        except (TypeError, ValueError) as input_error:
            raise OCSPResponseError from input_error

    @property
    def response_status(self):
        """OCSP response status, instance of OCSPResponseStatus"""
        return OCSPResponseStatus(self._response.response_status.value)

    @property
    def cert_status(self):
        """Certificate status, instance of OCSPCertStatus"""
        return OCSPCertStatus(self._response.certificate_status.value)

    @property
    def this_update(self):
        """Returns the datetime of the current OCSP response"""
        return self._response.this_update

    @property
    def next_update(self):
        """Returns the datetime of the next OCSP response"""
        return self._response.next_update

    def save(self, path):
        """Persists the OCSP response on disk"""
        with open(path, 'wb') as response_file:
            response_file.write(self.der_response)
