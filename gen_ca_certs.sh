#!/bin/bash

this_path=$(realpath $0)         ## Path of this file including filename
dir_name=`dirname ${this_path}`  ## Dir where this file is
myname=`basename ${this_path}`   ## file name of this script.

days=3650
cadir='.'

function usage {
  echo "
  usage: $myname [options]

  -n <dn>   required  Domain name (i.e. yahoo.com, google.com)

  -c <dir>     optional  Create top CA directory here. Default: ./
  -e <days>    optional  Days until expiration. Default: 3650
  -r <pass>    optional  Root CA password
  -s <pass>    optional  Signing CA password
  -t <pass>    optional  Java truststore password
  -q           optional  Suppress log messages on screen, just log them.
  -h           optional  Print this help message
               "
  exit 1
}

while getopts :n:c:e:r:s:t:h args
do
  case $args in
  n) dn="$OPTARG" ;;
  c) cadir="$OPTARG" ;;
  e) days="$OPTARG" ;;
  r) rpw="$OPTARG" ;;
  s) spw="$OPTARG" ;;
  t) tpw="$OPTARG" ;;
  h) usage ;;
  :) echo "The argument -$OPTARG requires a parameter" ;;
  *) usage ;;
  esac
done

# Gather input
if [[ ! $dn ]]  ; then read -p "Enter domain name: " dn ; echo ; fi
if [[ ! $rpw ]] ; then read -p "Enter Root CA pass: "    -s rpw ; echo ; fi
if [[ ! $spw ]] ; then read -p "Enter Signing CA pass: " -s spw ; echo ; fi
if [[ ! $tpw ]] ; then read -p "Enter Truststore pass: " -s tpw ; echo ; fi

### Main ###
function main {

  # Create Root CA directory structure and DB files
  mkdir -p $cadir/ca/root.ca/private $cadir/ca/root.ca/db $cadir/crl $cadir/certs $cadir/etc || exit 1
  chmod 700 $cadir/ca/root.ca/private || exit 1

  sed -e "s#_REPLACE_DOMAIN_#$dn #g" \
      -e "s#_REPLACE_DIR_#$cadir #g" \
      $dir_name/etc/root-ca.conf.template > $cadir/etc/root-ca.conf || exit 1

  sed -e "s#_REPLACE_DOMAIN_#$dn #g" \
      -e "s#_REPLACE_DIR_#$cadir #g" \
      $dir_name/etc/signing-ca.conf.template > $cadir/etc/signing-ca.conf || exit 1

  cp /dev/null $cadir/ca/root.ca/db/root.ca.$dn.db || exit 1
  cp /dev/null $cadir/ca/root.ca/db/root.ca.$dn.db.attr || exit 1
  echo 01 > $cadir/ca/root.ca/db/root.ca.$dn.crt.srl || exit 1
  echo 01 > $cadir/ca/root.ca/db/root.ca.$dn.crl.srl || exit 1

  # Generate Root Key and CSR

  openssl req -new \
          -config $cadir/etc/root-ca.conf \
          -out $cadir/ca/root.ca.$dn.csr \
          -keyout $cadir/ca/root.ca/private/root.ca.$dn.key \
        	-batch \
        	-passout pass:$rpw || exit 1

  # Self-sign Root CA

  openssl ca -selfsign \
          -config $cadir/etc/root-ca.conf \
          -in $cadir/ca/root.ca.$dn.csr \
          -out $cadir/ca/root.ca.$dn.crt \
          -extensions root_ca_ext \
          -days $days \
        	-batch \
        	-passin pass:$rpw || exit 1
  	
  echo Root CA generated

  # Create Signing CA directory structure and DB files
  	
  mkdir -p $cadir/ca/signing.ca/private $cadir/ca/signing.ca/db $cadir/crl $cadir/certs || exit 1
  chmod 700 $cadir/ca/signing.ca/private || exit 1

  cp /dev/null $cadir/ca/signing.ca/db/signing.ca.$dn.db || exit 1
  cp /dev/null $cadir/ca/signing.ca/db/signing.ca.$dn.db.attr || exit 1
  echo 01 > $cadir/ca/signing.ca/db/signing.ca.$dn.crt.srl || exit 1
  echo 01 > $cadir/ca/signing.ca/db/signing.ca.$dn.crl.srl || exit 1

  # Generate Signing CSR

  openssl req -new \
          -config $cadir/etc/signing-ca.conf \
          -out $cadir/ca/signing.ca.$dn.csr \
          -keyout $cadir/ca/signing.ca/private/signing.ca.$dn.key \
        	-batch \
        	-passout pass:$spw || exit 1

  # Sign with Root CA

  openssl ca \
          -config $cadir/etc/root-ca.conf \
          -in $cadir/ca/signing.ca.$dn.csr \
          -out $cadir/ca/signing.ca.$dn.crt \
          -extensions signing_ca_ext \
          -days $days \
        	-batch \
        	-passin pass:$rpw || exit 1
  	
  echo Signing CA generated

  # Create PEM chains

  openssl x509 \
          -in $cadir/ca/root.ca.$dn.crt \
          -out $cadir/ca/root.ca.$dn.pem \
          -outform PEM || exit 1
  openssl x509 \
          -in $cadir/ca/signing.ca.$dn.crt \
          -out $cadir/ca/signing.ca.$dn.pem \
          -outform PEM || exit 1

  cat $cadir/ca/signing.ca.$dn.pem $cadir/ca/root.ca.$dn.pem > $cadir/ca/chain.ca.$dn.pem || exit 1

  # Generate truststore with Root CA

  cat $cadir/ca/root.ca.$dn.pem | keytool \
      -import \
      -v \
      -keystore $cadir/ca/truststore.$dn.jks   \
      -storepass $tpw  \
      -noprompt -alias root.ca || exit 1

}

## Boot strap the script.
main "$@"