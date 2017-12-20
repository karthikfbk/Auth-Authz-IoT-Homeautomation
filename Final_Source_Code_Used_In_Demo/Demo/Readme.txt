REQUIRED : Mysql version 5.7 installed and running in localhost.

>> Refer to the Topology.jpg file to the prototype setup and ip address assigned with CAS,AS,Client and RS.

CAS and AS can support both Asymmetric and Hybrid model by default.

>> To run CAS, run the following in the terminal.
java -jar federated-iot-as-0.0.1-SNAPSHOT-jar-with-dependencies.jar ./Config_cas.json 5684

>> To run AS, run the following in the terminal
java -jar federated-iot-as-0.0.1-SNAPSHOT-jar-with-dependencies.jar ./Config_as.json 5684

############## To run RS and Client in Asymmetric Model #############

>> To run RS, run the following in the terminal
java -cp federated-iot-rs-0.0.1-SNAPSHOT-jar-with-dependencies.jar thesis.authz.federated_iot_rs.App ./Config_rs.json 5684

>> To run Client, run the following in the terminal
sudo java -cp federated-iot-client-0.0.1-SNAPSHOT-jar-with-dependencies.jar thesis.authz.federated_iot_client.App ./Config_c.json

############## To run RS and Client in Hybrid Model #############

>> To run RS, run the following in the terminal
java -cp federated-iot-rs-0.0.1-SNAPSHOT-jar-with-dependencies.jar thesis.authz.federated_iot_rs_hybrid.App ./Config_rs.json 5684

>> To run Client, run the following in the terminal
sudo java -cp federated-iot-client-0.0.1-SNAPSHOT-jar-with-dependencies.jar thesis.authz.federated_iot_client.hybrid.App ./Config_c.json

NOTE:

The RS stores the all the access tokens in a file called as tokens.json.
If you encounter and error like 'SEVERE: Message processing aborted: Duplicate cti' on the RS, it means there is already a token in tokens.json
file with the same 'cti - token identifier'. Solution would be to remove the file tokens.json and try again.

