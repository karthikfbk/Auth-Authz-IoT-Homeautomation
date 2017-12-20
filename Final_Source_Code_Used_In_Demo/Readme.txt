############# CLONING THE REPOSITORY ##############

>> Repository Link - https://www.code.dtf.lighting.com/users/600011213/repos/ma_internship_poc/browse
>> Add your ssh public key to clone the repository. More info - https://confluence.atlassian.com/bitbucketserver052/creating-ssh-keys-935362650.html
>> After adding your ssh public key. Open git client or terminal
	>> git clone ssh://git@origin.www.code.dtf.lighting.com:7999/~600011213/ma_internship_poc.git

############# IMPORTING AND BUILDING PROJECTS #############

>> Make sure you have java version 1.8 installed
>> Open Eclipse ( I used Eclipse Oxygen )
>> File -> Import -> Maven -> Existing Maven Project -> Next.
>> Browse to the location where you cloned the repository.
>> Select 'Final_Source_Code_Used_In_Demo -> federated-iot-core'.
>> Click OK and Finish.

>> Similarly import 'Final_Source_Code_Used_In_Demo -> federated-iot-as',
'Final_Source_Code_Used_In_Demo -> federated-iot-client',
'Final_Source_Code_Used_In_Demo -> federated-iot-rs'
to the eclipse workspace.

>> To Build the projects.
>> First build, federated-iot-core project by rightclick -> run as -> Maven Build
>> Give maven goal as 'clean install' and Click 'RUN'

>> Then build the rest of the projects 'federated-iot-as','federated-iot-client','federated-iot-rs'
in the similar way, but enter the maven goal 'clean compile install assembly:single -X' for these projects.

>> After successful build you will find three execuitable jar files generated under the 'target' folder for each 
federated-iot-as,federated-iot-client and federated-iot-rs projects namely, 'federated-iot-client-0.0.1-SNAPSHOT-jar-with-dependencies',
'federated-iot-as-0.0.1-SNAPSHOT-jar-with-dependencies', ' federated-iot-rs-0.0.1-SNAPSHOT-jar-with-dependencies'.


NOTE: My project source code had dependencies with 'ace-java' library which is the java implementation of 'https://tools.ietf.org/html/draft-ietf-ace-oauth-authz'.
So, it advisable to clone and import that repository also into the the eclipse workspace along with the above projects and do a maven build on it first before building 'federated-iot-core'.

>> clone the ace-java repository from : "https://bitbucket.org/lseitz/ace-java.git".
>> More information: "https://bitbucket.org/lseitz/ace-java/overview"

################## How to run #########################
>> Instructions on how to run these jars is present in Readme.txt present in 'Demo' Folder of this repository.

>> generateKeys.sh script file is used to generate the X509 Certificates for CAS,AS,Client and RS respectively.
>> After executing generateKeys.sh you will get 8 files namely,
--	keyStoreAS
--	trustStoreAS
--	keyStoreCAS
--	trustStoreCAS
--	keyStoreC
--	trustStoreC
--	keyStoreRS
--	trustStoreRS

>> keyStore is used to store the entity certificates and private keys while the trust store is used to store the trusted certicates for that entity.
>> For example, keyStore of Client(keyStoreC) will contain the client certificate signed by CAS and the trustStore of Client (trustStoreC) will contain the CAS certificate and
Root CA certificate of CAS.
 



	