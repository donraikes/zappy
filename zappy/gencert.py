"""
Write Zap's root certificate into zap.der.

The zap.der file can be converted into a PEM-encoded file using:
After writing the der format certificate openssl will be invoked to convert it
into a PEM-encoded certificate.
"""
import logging
import os
import sys
import subprocess

from zapv2 import ZAPv2

class   GenCert(object):
    """
    A class to automate the extraction of zap's root certificate.
    """

    def WriteCertificate(self, APIKEY, zap):
        """Write the der-encoded certificate to disk."""
        logging.info("Writing the der-encoded certificate into zap.der")
        with open("zap.der","w") as f:
    	    f.write(zap.core.rootcert())

    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.APIKEY="demo"
        self.local_proxy="http://localhost:8090"
        self.zap = ZAPv2(apikey=self.APIKEY,
            proxies={'http': self.local_proxy, 
            'https': self.local_proxy})
        self.WriteCertificate(self.APIKEY, self.zap)
