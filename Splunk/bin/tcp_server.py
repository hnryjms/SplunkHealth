import os
import sys
import ssl
import SocketServer

from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime

SPLUNK_HOME = os.environ["SPLUNK_HOME"]
CERTIFICATE_PATH = os.path.join(SPLUNK_HOME, "etc", "apps", "healthkit", "local", "server.pem")

def generate_certificate(output, base_cert = os.path.join(SPLUNK_HOME, "etc", "auth", "server.pem"),
                         ca_cert = os.path.join(SPLUNK_HOME, "etc", "auth", "ca.pem")):
    """Generate a new self-signed certificate.

    Generate a new certificate to be used on our TCP server, based on
    the existing `server.pem` certificate used by Splunk and signed by the CA
    certificate pair `ca.pem`.

    Args:
        output (str):    File path to write the generated certificate.
        base_cert (str): Certificate used for info to the generated certificate.
        ca_cert (str):   CA Certificate pair used to sign the generated certificate.
    """

    if base_cert:
        with open(base_cert, "r") as f:
            lines = f.read()
            base_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, lines)

        # Get an X509Name object for the certificate used by Splunk.
        base_subject = base_x509.get_subject()
    else:
        # Get an empty X509Name object, so our defaults below are used.
        base_subject = crypto.X509().get_subject()

    k = None
    ca_issuer = None
    if ca_cert:
        with open(ca_cert, "r") as f:
            lines = f.read()
            try:
                ca_issuer = crypto.load_certificate(crypto.FILETYPE_PEM, lines)
                k = crypto.load_privatekey(crypto.FILETYPE_PEM, lines)
            except crypto.Error:
                pass

    if not k:
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    if base_subject.C:
        cert.get_subject().C = base_subject.C
    if base_subject.ST:
        cert.get_subject().ST = base_subject.ST
    if base_subject.L:
        cert.get_subject().L = base_subject.L
    cert.get_subject().O = base_subject.O or "Splunk"
    cert.get_subject().OU = base_subject.OU or "SplunkHealth"
    cert.get_subject().CN = "SplunkHealthDefaultCert"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)

    if ca_issuer:
        cert.set_issuer(ca_issuer.get_subject())
    else:
        cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')

    with open(output, "w") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        if ca_issuer:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_issuer))

if not os.path.exists(CERTIFICATE_PATH):
    generate_certificate(CERTIFICATE_PATH)

class TCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    def server_bind(self):
        SocketServer.TCPServer.server_bind(self)
        self.socket = ssl.wrap_socket(
            self.socket, certfile=CERTIFICATE_PATH, server_side=True,
            do_handshake_on_connect=False)

    def get_request(self):
        (socket, addr) = SocketServer.TCPServer.get_request(self)
        socket.do_handshake()
        return (socket, addr)

class MyTCPHandler(SocketServer.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        # self.request is the TCP socket connected to the client
        while True:
            self.data = self.request.recv(1024).strip()
            if self.data == '':
                break
            print "{} wrote:".format(self.client_address[0])
            print self.data
            # just send back the same data, but upper-cased
            self.request.sendall(self.data.upper() + "\n")

if __name__ == "__main__":
    HOST, PORT = "", 8087

    # Create the server, binding on port 8087
    server = TCPServer((HOST, PORT), MyTCPHandler)

    # Activate the server; this will keep running until the
    # server crashes (in which case, Splunk will restart it).
    server.serve_forever()
