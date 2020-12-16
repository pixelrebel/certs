#!/bin/bash

this_path=$(realpath $0)         ## Path of this file including filename
dir_name=`dirname ${this_path}`  ## Dir where this file is
myname=`basename ${this_path}`   ## file name of this script.

ct="server"
days=730
dns=()
ip=()
oid=()

function usage {
  echo "
  usage: $myname [options]

  -b <name>    required  Common Name or Host Name (db1)
  -n <name>    required  Domain Name (mycompany.net)
  -c <dir>     required  Path to CA directory with valid signing certs/keys
  -s <pass>    required  SigningCA Key Password
  -k <pass>    required  KeyStore Password
  -N <name>    optional  CA Domain Name. Default: Same as -n
  -t <type>    optional  NS Cert Type. (server/client) Default: server
  -e <days>    optional  Days until expiration. Default: 730
  -d <name>    optional  SubjectAltName:DNS (can include many)
  -i <ipaddr>  optional  SubjectAltName:IP (can include many)
  -o <oid>     optional  SubjectAltName:OID (can include many)
  -D <name>    optional  Distinguished Name String (excluding CN)
                         example: \"OU=Network Security, O=My Company, L=Los Angeles, S=California, C=US\"
  -K <path>    optional  Generate certs from existing PEM key file.
  -h           optional  Print this help message

  example ./gen_leaf_cert.sh -n mycompany.net -b db1 -c /etc/ssl/ca -d db1.mycompany.com
  "
  exit 1
}
function myreadlink {
    # OS agnostic readlink -f
    # Credit: https://stackoverflow.com/questions/1055671/how-can-i-get-the-behavior-of-gnus-readlink-f-on-a-mac

    TARGET_FILE=$1

    cd $(dirname $TARGET_FILE)
    TARGET_FILE=$(basename $TARGET_FILE)

    # Iterate down a (possible) chain of symlinks
    while [ -L "$TARGET_FILE" ]
    do
        TARGET_FILE=$(readlink $TARGET_FILE)
        cd $(dirname $TARGET_FILE)
        TARGET_FILE=$(basename $TARGET_FILE)
    done

    # Compute the canonicalized name by finding the physical path
    # for the directory we're in and appending the target file.
    PHYS_DIR=$(pwd -P)
    RESULT=$PHYS_DIR/$TARGET_FILE
    echo $RESULT

}

## Start coding from here. Some basic flags are already provide. Feel free to override, add, delete
while getopts :b:n:c:s:k:N:t:e:d:i:o:K:D:h: args
do
  case $args in
  b) hn="$OPTARG" ;;
  n) dn="$OPTARG" ;;
  c) cadir="$OPTARG" ;;
  s) spw="$OPTARG" ;;
  k) kpw="$OPTARG" ;;
  N) cadn="$OPTARG" ;;
  t) ct="$OPTARG" ;;
  e) days="$OPTARG" ;;
  d) dns+=("$OPTARG") ;;
  i) ip+=("$OPTARG") ;;
  o) oid+=("$OPTARG") ;;
  K) keyf="$OPTARG" ;;
  D) disn="$OPTARG" ;;
  h) usage ;;
  *) usage ;;
  esac
done

# Gather input
if [[ ! $dn ]]    ; then read -p "Enter domain name: " dn ; echo ; fi
if [[ ! $hn ]]    ; then read -p "Enter host name: " hn ; echo ; fi
if [[ ! $cadir ]] ; then read -p "Enter path to your CA top directory: " cadir ; echo ; fi
if [[ ! $spw ]]   ; then read -p "Enter signing CA pass: " -s spw ; echo ; fi
if [[ ! $kpw ]]   ; then read -p "Enter keystore pass: " -s kpw ; echo ; fi

# Prepare input data
if [[ $ct == "server" ]]
then
  fqdn=$hn.$dn
  cn=$fqdn
else
  ct="client"
  cn=$hn
  fqdn=$hn.client.$dn
  dns+=("$hn.client")
fi
if [[ ! $cadn ]] ; then cadn="$dn" ; fi
if [[ $disn ]] ; then disn="$disn" ; fi
san=","
san+=`for i in ${dns[@]}; do echo -n "dns:$i,"; done;`
san+=`for i in ${ip[@]}; do echo -n "ip:$i,"; done;`
san+=`for i in ${oid[@]}; do echo -n "oid:$i,"; done;`
san=`echo $san | sed -e 's/,$//g'`

### Main ###
function main {

  if [[ $keyf && ! -f $keyf ]]
  then
      echo "Key file not found: $keyf"
      exit 1
  fi

  if [[ -f $keyf && $(dirname $(myreadlink $keyf)) == $(myreadlink $cadir/certs/$ct/$fqdn) ]]
  then
    # Archive existing certs when keyfile is specified
    archive=$cadir/certs/$ct/$fqdn/$(date +"%Y-%m-%d")
    mkdir -p $archive || exit 1
    find $(dirname $(myreadlink $keyf)) ! -name "$(basename $keyf)" -type f | xargs -I{} mv "{}" $archive
  else
    rm -rf $cadir/certs/$ct/$fqdn || exit 1
    mkdir -p $cadir/certs/$ct/$fqdn || exit 1
  fi

  echo Generating keystore for leaf $hn
  keytool -genkey \
          -alias     $fqdn \
          -keystore  $cadir/certs/$ct/$fqdn/$fqdn.jks \
          -keyalg    RSA \
          -keysize   2048 \
          -validity  $days \
          -sigalg SHA256withRSA \
          -keypass $kpw \
          -storepass $kpw \
          -dname "$disn, CN=$cn" \
          -ext san=ip:127.0.0.1,dns:localhost,dns:$hn,dns:$fqdn$san || exit 1

  echo Generating certificate signing request for leaf $hn
  if [[ $keyf ]]
  then
    san2="IP:127.0.0.1,DNS:localhost,DNS:$hn,DNS:$fqdn"
    san2+="$(echo $san | sed -e 's/dns:/DNS:/g' -e 's/ip:/IP:/g' -e 's/oid:/OID:/g')"
    disn2="/$(echo $disn | sed -e 's#\\,#_-_-_#g' -e 's#, *#/#g' -e 's#_-_-_#,#g')"
    keytool -delete \
            -alias $fqdn \
            -storepass $kpw \
            -keystore $cadir/certs/$ct/$fqdn/$fqdn.jks || exit 1
    openssl req -new \
            -subj "$disn2/CN=$cn" \
            -key $keyf \
            -out $cadir/certs/$ct/$fqdn/$fqdn.csr \
            -reqexts FLYSAN \
            -config <(cat $cadir/etc/signing-ca.conf \
                    <(printf "\n[FLYSAN]\nsubjectAltName=$san2\n\n[ca_dn]\ncommonName=$cn")) || exit 1
  else
    keytool -certreq \
            -alias      $fqdn \
            -keystore   $cadir/certs/$ct/$fqdn/$fqdn.jks \
            -file       $cadir/certs/$ct/$fqdn/$fqdn.csr \
            -keyalg     rsa \
            -keypass $kpw \
            -storepass $kpw \
            -dname "$disn, CN=$cn" \
            -ext san=ip:127.0.0.1,dns:localhost,dns:$hn,dns:$fqdn$san || exit 1
  fi

  echo Sign certificate request with CA
  openssl ca \
          -in $cadir/certs/$ct/$fqdn/$fqdn.csr \
          -notext \
          -out $cadir/certs/$ct/$fqdn/$fqdn.pem \
          -config $cadir/etc/signing-ca.conf \
          -days $days \
          -batch \
        	-passin pass:$spw \
        	-extensions $ct\_ext || exit 1

  if [[ $keyf ]]
  then
    echo "Create PKCS12 key/cert bundle (including CA chain)"
    openssl pkcs12 -export \
            -out $cadir/certs/$ct/$fqdn/$fqdn.p12 \
            -inkey $keyf \
            -password pass:$kpw \
            -in $cadir/certs/$ct/$fqdn/$fqdn.pem || exit 1
    echo "Import back to keystore (including CA chain)"
    keytool -v -importkeystore \
            -srckeystore $cadir/certs/$ct/$fqdn/$fqdn.p12 \
            -srcstorepass $kpw \
            -srcstoretype PKCS12 \
            -destkeystore $cadir/certs/$ct/$fqdn/$fqdn.jks \
            -deststorepass $kpw \
            -deststoretype JKS || exit 1
  else
    echo "Import back to keystore (including CA chain)"
    cat $cadir/ca/chain.ca.$cadn.pem $cadir/certs/$ct/$fqdn/$fqdn.pem | keytool \
        -importcert \
        -keystore $cadir/certs/$ct/$fqdn/$fqdn.jks \
        -storepass $kpw \
        -noprompt \
        -alias $fqdn || exit 1

    echo "Create PKCS12 key/cert bundle (including CA chain)"
    keytool -importkeystore \
            -srckeystore $cadir/certs/$ct/$fqdn/$fqdn.jks \
            -srcstorepass $kpw \
            -srcstoretype JKS \
            -deststoretype PKCS12 \
            -deststorepass $kpw \
            -destkeystore $cadir/certs/$ct/$fqdn/$fqdn.p12 || exit 1
  fi

  echo "Create PEM key from PKCS12 file"
  openssl pkcs12 \
          -in "$cadir/certs/$ct/$fqdn/$fqdn.p12" \
          -out "$cadir/certs/$ct/$fqdn/$fqdn.key" \
          -nocerts -nodes \
          -passin pass:$kpw || exit 1
  echo "Create PKCS8 key from PEM key file"
  openssl pkcs8 \
          -topk8 \
          -in "$cadir/certs/$ct/$fqdn/$fqdn.key" \
          -out "$cadir/certs/$ct/$fqdn/$fqdn.p8" \
          -nocrypt || exit 1

  cat $cadir/ca/chain.ca.$cadn.pem >> $cadir/certs/$ct/$fqdn/$fqdn.pem || exit 1

  echo All done for $hn

}

## Boot strap the script.
main "$@"
