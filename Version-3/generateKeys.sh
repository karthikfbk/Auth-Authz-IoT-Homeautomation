#!/bin/bash

KEY_STORE_CAS=keyStoreCAS.jks
KEY_STORE_CAS_PWD=endPasscas
TRUST_STORE_CAS=trustStoreCAS.jks
TRUST_STORE_CAS_PWD=rootPasscas

KEY_STORE_C=keyStoreC.jks
KEY_STORE_C_PWD=endPassc
TRUST_STORE_C=trustStoreC.jks
TRUST_STORE_C_PWD=rootPassc

KEY_STORE_AS=keyStoreAS.jks
KEY_STORE_AS_PWD=endPassas
TRUST_STORE_AS=trustStoreAS.jks
TRUST_STORE_AS_PWD=rootPassas

KEY_STORE_RS=keyStoreRS.jks
KEY_STORE_RS_PWD=endPassrs
TRUST_STORE_RS=trustStoreRS.jks
TRUST_STORE_RS_PWD=rootPassrs

VALIDITY=365

echo "creating baseroot1 key and certificate..."
keytool -genkeypair -alias baseroot1 -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse,OU=Californium,CN=baseroot1' \
        -validity $VALIDITY -keypass $TRUST_STORE_CAS_PWD -keystore $TRUST_STORE_CAS -storepass $TRUST_STORE_CAS_PWD

keytool -exportcert -alias baseroot1 -keypass $TRUST_STORE_CAS_PWD -keystore $TRUST_STORE_CAS -storepass $TRUST_STORE_CAS_PWD -rfc -file baseroot1.pem

echo "creating cas key and certificate..."
keytool -genkeypair -alias cas -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse,OU=Californium,CN=cas' \
        -validity $VALIDITY -keypass $KEY_STORE_CAS_PWD -keystore $KEY_STORE_CAS -storepass $KEY_STORE_CAS_PWD
keytool -keystore $KEY_STORE_CAS -storepass $KEY_STORE_CAS_PWD -certreq -alias cas | \
  keytool -keystore $TRUST_STORE_CAS -storepass $TRUST_STORE_CAS_PWD -alias baseroot1 -gencert -ext BC=0 -validity $VALIDITY -rfc > cas.pem
keytool -alias baseroot1 -importcert -keystore $KEY_STORE_CAS -storepass $KEY_STORE_CAS_PWD -trustcacerts -file baseroot1.pem  
keytool -alias cas -importcert -keystore $KEY_STORE_CAS -storepass $KEY_STORE_CAS_PWD -trustcacerts -file cas.pem  

echo "creating client key and certificate..."
keytool -genkeypair -alias client -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse,OU=Californium,CN=client' \
        -validity $VALIDITY -keypass $KEY_STORE_C_PWD -keystore $KEY_STORE_C -storepass $KEY_STORE_C_PWD
keytool -keystore $KEY_STORE_C -storepass $KEY_STORE_C_PWD -certreq -alias client | \
  keytool -keystore $KEY_STORE_CAS -storepass $KEY_STORE_CAS_PWD -alias cas -gencert -ext KU=dig -validity $VALIDITY -rfc > client.pem
keytool -alias baseroot1 -importcert -keystore $KEY_STORE_C -storepass $KEY_STORE_C_PWD -trustcacerts -file baseroot1.pem  
keytool -alias client -importcert -keystore $KEY_STORE_C -storepass $KEY_STORE_C_PWD -trustcacerts -file client.pem 
keytool -alias baseroot1 -importcert -keystore $TRUST_STORE_C -storepass $TRUST_STORE_C_PWD -trustcacerts -file baseroot1.pem 

echo "creating baseroot2 key and certificate..."
keytool -genkeypair -alias baseroot2 -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse,OU=Californium,CN=baseroot2' \
        -validity $VALIDITY -keypass $TRUST_STORE_AS_PWD -keystore $TRUST_STORE_AS -storepass $TRUST_STORE_AS_PWD

keytool -exportcert -alias baseroot2 -keypass $TRUST_STORE_AS_PWD -keystore $TRUST_STORE_AS -storepass $TRUST_STORE_AS_PWD -rfc -file baseroot2.pem

echo "creating as key and certificate..."
keytool -genkeypair -alias as -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse,OU=Californium,CN=as' \
        -validity $VALIDITY -keypass $KEY_STORE_AS_PWD -keystore $KEY_STORE_AS -storepass $KEY_STORE_AS_PWD
keytool -keystore $KEY_STORE_AS -storepass $KEY_STORE_AS_PWD -certreq -alias as | \
  keytool -keystore $TRUST_STORE_AS -storepass $TRUST_STORE_AS_PWD -alias baseroot2 -gencert -ext BC=1 -validity $VALIDITY -rfc > as.pem
keytool -alias baseroot2 -importcert -keystore $KEY_STORE_AS -storepass $KEY_STORE_AS_PWD -trustcacerts -file baseroot2.pem  
keytool -alias as -importcert -keystore $KEY_STORE_AS -storepass $KEY_STORE_AS_PWD -trustcacerts -file as.pem

echo "creating server key and certificate..."
keytool -genkeypair -alias server -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse,OU=Californium,CN=server' \
        -validity $VALIDITY -keypass $KEY_STORE_RS_PWD -keystore $KEY_STORE_RS -storepass $KEY_STORE_RS_PWD
keytool -keystore $KEY_STORE_RS -storepass $KEY_STORE_RS_PWD -certreq -alias server | \
  keytool -keystore $KEY_STORE_AS -storepass $KEY_STORE_AS_PWD -alias as -gencert -ext KU=dig -validity $VALIDITY -rfc > server.pem
keytool -alias baseroot2 -importcert -keystore $KEY_STORE_RS -storepass $KEY_STORE_RS_PWD -trustcacerts -file baseroot2.pem  
keytool -alias server -importcert -keystore $KEY_STORE_RS -storepass $KEY_STORE_RS_PWD -trustcacerts -file server.pem 
keytool -alias baseroot2 -importcert -keystore $TRUST_STORE_RS -storepass $TRUST_STORE_RS_PWD -trustcacerts -file baseroot2.pem 
keytool -alias as -importcert -keystore $TRUST_STORE_RS -storepass $TRUST_STORE_RS_PWD -trustcacerts -file as.pem 

echo "importing baseroot1 cert to as"
keytool -alias baseroot1 -importcert -keystore $TRUST_STORE_AS -storepass $TRUST_STORE_AS_PWD -trustcacerts -file baseroot1.pem 
echo "importing cas cert to as"
keytool -alias cas -importcert -keystore $TRUST_STORE_AS -storepass $TRUST_STORE_AS_PWD -trustcacerts -file cas.pem 

echo "importing baseroot2 cert to cas"
keytool -alias baseroot2 -importcert -keystore $TRUST_STORE_CAS -storepass $TRUST_STORE_CAS_PWD -trustcacerts -file baseroot2.pem 
echo "importing as cert to cas"
keytool -alias as -importcert -keystore $TRUST_STORE_CAS -storepass $TRUST_STORE_CAS_PWD -trustcacerts -file as.pem 
