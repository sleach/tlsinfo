# -*- encoding: utf-8 -*-
# requires a recent enough python with idna support in socket
# pyopenssl, cryptography and idna

import sys
from collections import namedtuple
from socket import socket

import idna
from cryptography import x509
from cryptography.x509.oid import NameOID
from OpenSSL import SSL

HostInfo = namedtuple(field_names="cert hostname peername", typename="HostInfo")

ev_oids = [
    "2.16.840.1.113733.1.7.23.6",  # verisign
    "1.3.6.1.4.1.14370.1.6",  # geotrust
    "2.16.840.1.113733.1.7.48.1",  # thawte
    "2.16.840.1.114412.2.1",  # digicert
]


def verify_cert(cert, hostname):
    # verify notAfter/notBefore, CA trusted, servername/sni/hostname
    cert.has_expired()
    # service_identity.pyopenssl.verify_hostname(client_ssl, hostname)
    # issuer


def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD)  # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)


def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None


def get_policies(cert):
    return cert.extensions.get_extension_for_class(x509.CertificatePolicies)


def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def is_ev(cert):
    policies = get_policies(cert)
    for policy in policies.value:
        if policy.policy_identifier.dotted_string in ev_oids:
            return True
    return False


def print_basic_info(hostinfo):
    s = """{hostname} {peername}
    \tcommonName: {commonname}
    \tSAN: {SAN}
    \tissuer: {issuer}
    \tnotBefore: {notbefore}
    \tnotAfter:  {notafter}
    \tEV: {isev}
    """.format(
        hostname=hostinfo.hostname,
        peername=hostinfo.peername,
        commonname=get_common_name(hostinfo.cert),
        SAN=get_alt_names(hostinfo.cert),
        issuer=get_issuer(hostinfo.cert),
        notbefore=hostinfo.cert.not_valid_before,
        notafter=hostinfo.cert.not_valid_after,
        isev=is_ev(hostinfo.cert),
    )
    print(s)


def check_it_out(hostname, port):
    hostinfo = get_certificate(hostname, port)
    print_basic_info(hostinfo)


if __name__ == "__main__":
    info = get_certificate(sys.argv[1], 443)
    print_basic_info(info)
