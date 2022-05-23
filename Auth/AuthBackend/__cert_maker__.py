from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from datetime import datetime, timedelta
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

def generate_private_key(filename: str, passphrase: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    algorithm = serialization.NoEncryption()
    with open(filename, "wb") as keyfile:
        keyfile.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=algorithm))
    return private_key

def generate_public_key(private_key, filename, **kwargs):
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs["country"]), x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, kwargs["state"]), x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs["locality"]), x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs["org"]), x509.NameAttribute(NameOID.COMMON_NAME, kwargs["hostname"])])
    issuer = subject
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=30)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(valid_from).not_valid_after(valid_to).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True))
    public_key = builder.sign(private_key, hashes.SHA256(), default_backend())
    with open(filename, "wb") as certfile:
        certfile.write(public_key.public_bytes(serialization.Encoding.PEM))
    return public_key

def generate_csr(private_key, filename, **kwargs):
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs["country"]), x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, kwargs["state"]), x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs["locality"]), x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs["org"]), x509.NameAttribute(NameOID.COMMON_NAME, kwargs["hostname"])])
    alt_names = []
    for name in kwargs.get("alt_names", []):
        alt_names.append(x509.DNSName(name))
    san = x509.SubjectAlternativeName(alt_names)
    builder = (x509.CertificateSigningRequestBuilder().subject_name(subject).add_extension(san, critical=False))
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    with open(filename, "wb") as csrfile:
        csrfile.write(csr.public_bytes(serialization.Encoding.PEM))
    return csr

def sign_csr(csr, ca_public_key, ca_private_key, new_filename):
    valid_from = datetime.utcnow()
    valid_until = valid_from + timedelta(days=30)
    builder = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_public_key.subject).public_key(csr.public_key()).serial_number(x509.random_serial_number()).not_valid_before(valid_from).not_valid_after(valid_until))
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    public_key = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())
    with open(new_filename, "wb") as keyfile:
        keyfile.write(public_key.public_bytes(serialization.Encoding.PEM))
server_private_key = generate_private_key("server-private-key.pem", "")
private_key = generate_private_key("ca-private-key.pem", "")
generate_public_key(private_key, filename="ca-public-key.pem", country="US", state="Iowa", locality="Ankeny", org="32", hostname="192.168.6.3")
generate_csr( server_private_key, filename="server-csr.pem", country="US", state="Iowa", locality="Ankeny", org="32", hostname="192.168.6.3", alt_names=["localhost", "ldums.com", "192.168.6.3"]) #edit this list with alt names for your domain.
csr_file = open("server-csr.pem", "rb")
csr = x509.load_pem_x509_csr(csr_file.read(), default_backend())
ca_public_key_file = open("ca-public-key.pem", "rb")
ca_public_key = x509.load_pem_x509_certificate(ca_public_key_file.read(), default_backend())
ca_private_key_file = open("ca-private-key.pem", "rb")
ca_private_key = serialization.load_pem_private_key(ca_private_key_file.read(), None, default_backend())
sign_csr(csr, ca_public_key, ca_private_key, "server-public-key.pem")