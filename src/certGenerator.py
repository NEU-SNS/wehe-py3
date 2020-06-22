import argparse
import os
import sys
from urllib.request import urlopen

# https://gist.github.com/fntlnz/cf14feb5a46b2eda428e000157447309

default_root_cert_location = './ssl/ca.crt'
default_root_key_location = './ssl/ca.key'

parser = argparse.ArgumentParser(
    description='Generate a new certificate and sign it with root CA')
parser.add_argument('--root_cert', metavar='ca.crt', type=str,
                    help='path to root certificate', default=default_root_cert_location)
parser.add_argument('--root_key', metavar='ca.key', type=str,
                    help='path to root CA key', default=default_root_key_location)
parser.add_argument('--root_pass', metavar='<password>', type=str,
                    help='root certificate password', default='')
parser.add_argument('--destination', metavar='./ssl', type=str,
                    help='certificate output directory', default='./ssl/')
parser.add_argument('--file_names', metavar='server', type=str,
                    help='what to name the certificate and key files', default='server')
parser.add_argument('--domain_name', metavar='127.0.0.1', type=str,
                    help='the domain for which to generate the cert, by default we use the ip of the current server',
                    default='')
parser.add_argument('--days', metavar='500', type=str,
                    help='Number of days until the signed certificate expires', default='500')

args = parser.parse_args()

# Check if root ca cert is there
exists = os.path.isfile(args.root_cert)
if not exists:
    print(("-- Root certificate not found at path %s --" % args.root_cert))
    if args.root_cert == default_root_cert_location:
        print("-- Default location was used, you may want to specify the location using the '--root_cert' flag --")
    sys.exit(1)

# Check if root ca key is there
exists = os.path.isfile(args.root_key)
if not exists:
    print(("-- Root certificate key not found at path %s --" % args.root_key))
    if args.root_key == default_root_key_location:
        print("-- Default location was used, you may want to specify the location using the '--root_key' flag --")
    sys.exit(1)

exists = os.path.isdir(args.destination)
if not exists:
    print(("-- Destination folder %s not found, attempting to create it --" %
           args.destination))
    os.makedirs(args.destination)

# Generate a new key
print("-- Generating private key for our new server certificate")
key_name = "%s.key" % args.file_names
key_path = os.path.join(args.destination, key_name)
retvalue = os.system("openssl genrsa -out %s 2048" % key_path)

if retvalue == 0:
    print(("-- Created private key %s --" % key_path))
else:
    print(("-- Error creaing private key, openssl returned non-zero exit code %d --" % retvalue))
    sys.exit(1)

# Generate signing request for root CA to sign
print("-- Generating a certificate signing request for our root CA to sign")

if args.domain_name == '':
    print("-- No domain name was provided, attemtping to figure out server ip via ip.42.pl --")
    my_ip = urlopen('http://ip.42.pl/raw').read()
    print(("-- ip.42.pl reported the servers ip as %s --" % my_ip))
    args.domain_name = my_ip

csr_name = "%s.csr" % args.file_names
csr_path = os.path.join(args.destination, csr_name)
retvalue = os.system("openssl req -new -sha256 -key %s -subj '/C=US/ST=MA/O=Northeastern/CN=%s' -out %s" %
                     (key_path, args.domain_name, csr_path))
if retvalue == 0:
    print(("-- Created certificate signing request %s --" % csr_path))
else:
    print(("-- Error creaing certificate signing request, openssl returned non-zero exit code %d --" % retvalue))
    sys.exit(1)

# openssl x509 -req -in mydomain.com.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out mydomain.com.crt -days 500 -sha256

# Sign the certificate request
print("-- Signing the certificate signing request --")
crt_name = "%s.crt" % args.file_names
crt_path = os.path.join(args.destination, crt_name)
retvalue = os.system(
    "openssl x509 -req -in %s -CA %s -CAkey %s -passin pass:%s -CAcreateserial -out %s -days %s -sha256" %
    (csr_path, args.root_cert, args.root_key, args.root_pass, crt_path, args.days))

if retvalue == 0:
    print(("-- Signed certificate %s --" % crt_path))
else:
    print(("-- Error signing certificate, openssl returned non-zero exit code %d --" % retvalue))
    if retvalue == 256:
        print("-- It looks like the root password was incorrect --")
        print(
            "-- If you did not specify a root password but one is required, please use the '--root_pass' flag to specify one")
    sys.exit(1)

print("-- Cleaning up --")
os.remove(csr_path)
print("-- Success --")
