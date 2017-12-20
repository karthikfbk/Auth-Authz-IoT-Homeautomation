package thesis.authz.federated_iot.as;

import java.net.InetSocketAddress;
import java.net.URL;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.as.DBConnector;
import se.sics.ace.as.Introspect;
import se.sics.ace.as.Token;
import se.sics.ace.coap.as.CoapAceEndpoint;
import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.coap.as.CoapsAS;
import se.sics.ace.examples.MySQLDBAdapter;
import se.sics.ace.examples.SQLConnector;
import thesis.authz.federated_iot.AS_Params;
import thesis.authz.federated_iot.Utils.AS_MODE;
import thesis.authz.federated_iot.db.FedIoT_CoapDBConnector;
import thesis.authz.federated_iot.db.FedIoT_DBConnector;
import thesis.authz.federated_iot.db.FedIoT_MySQLDBAdapter;
import thesis.authz.federated_iot.db.FedIoT_SQLConnector;
import thesis.authz.federated_iot.endpoint.FederatedIoTEndpoint;

/**
 * Authorization Server implementing functionalities
 * of both AS and CAS.
 * 
 * https://tools.ietf.org/html/draft-ietf-ace-actors-05
 *
 */
public class AS extends CoapServer implements AutoCloseable{
	/**
	 * The logger
	 */
	private static final Logger LOGGER 
	= Logger.getLogger(CoapsAS.class.getName());

	/*
	 * Parameters for this AS
	 */
	AS_Params parameters;

	/*
	 * Authorization mode for this AS
	 */
	AS_MODE authorization_mode;

	/*
	 * cose_key for this AS. Sysmmetric or Asymmetric based upon the security profile
	 */
	OneKey cose_key;
	/*
	 * Server to host resources to .well-known/core
	 */
	Discovery_Server discovery_server;

	/*
	 * db for this AS
	 */
	FedIoT_CoapDBConnector db;

	/*
	 * 
	 */
	FedIoT_MySQLDBAdapter dbAdapter;
	/**
	 * The token endpoint
	 */
	Token t = null;

	/**
	 * The introspect endpoint
	 */
	Introspect i = null;

	/*
	 * TODO
	 * Implement query endpoint
	 */

	// Query q = null;
	// private FederatedIoTEndpoint query;

	/*
	 * TODO
	 * Implement Config endpoint
	 */

	Config c = null;
	private FederatedIoTEndpoint config;

	Registration r = null;
	private FederatedIoTEndpoint registration;

	/*
	 * TODO
	 * Implement ASExchange endpoint
	 */

	// ASExchange c = null;
	// private FederatedIoTEndpoint asexchange;

	private CoapAceEndpoint token;

	private CoapAceEndpoint introspect;

	private void init_db() throws Exception {
		dbAdapter = new FedIoT_MySQLDBAdapter();
		
		dbAdapter.setParams(this.parameters.dbuser, this.parameters.dbpwd, 
				FedIoT_DBConnector.dbName, this.parameters.dburl);		
		//Just to be sure that not old test pollutes the DB
		FedIoT_SQLConnector.wipeDatabase(dbAdapter, this.parameters.dbrootpwd);		

		FedIoT_SQLConnector.createDB(dbAdapter, this.parameters.dbrootpwd, 
				this.parameters.dbuser, this.parameters.dbpwd, 
				FedIoT_DBConnector.dbName, this.parameters.dburl);	
		
		FedIoT_SQLConnector.createUser(dbAdapter, this.parameters.dbrootpwd, 
				this.parameters.dbuser, this.parameters.dbpwd,this.parameters.dburl);		
		
		

		//db = (CoapDBConnector) SQLConnector.getInstance(dbAdapter,null, this.parameters.dbuser, this.parameters.dbpwd);
		db = new FedIoT_CoapDBConnector(this.parameters.dburl, this.parameters.dbuser, this.parameters.dbpwd);
	}

	public AS() throws Exception {		
		this(new AS_Params());       		
	}

	public AS(AS_Params parameters) throws Exception{
		this.parameters = parameters;
		LOGGER.log(Level.INFO, " Initializing DataBase");
		init_db();
		this.authorization_mode = AS_MODE.valueOf(this.parameters.authorization_mode);
		this.cose_key = new OneKey(
				CBORObject.DecodeFromBytes(Base64.getDecoder().decode(this.parameters.cose_key)));

		URL url = new URL(this.parameters.config_endpoint_resource.replaceAll(".*//","http://"));			
		String path = url.getPath();
		if(path.startsWith("/"))
			path = path.replaceFirst("/", "");
		this.c = new Config(parameters);
		this.config = new FederatedIoTEndpoint(path, c);

		add(this.config);

		url = new URL(this.parameters.registration_endpoint_resource.replaceAll(".*//","http://"));			
		path = url.getPath();
		if(path.startsWith("/"))
			path = path.replaceFirst("/", "");
		this.r = new Registration(this.db,this.parameters);
		this.registration = new FederatedIoTEndpoint(path, r);
		add(this.registration);

		//Start the discovery server for clients to discover the unprotected resources.
		discovery_server = new Discovery_Server(this.parameters.config_endpoint_resource,
				this.parameters.multicast_discovery, 
				this.parameters.as_security_profile);
		discovery_server.start();

		LOGGER.info("Starting AS with authorization mode set to " + this.authorization_mode);
		DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder(
				new InetSocketAddress(CoAP.DEFAULT_COAP_SECURE_PORT));
		if (this.cose_key != null && 
				this.cose_key.get(KeyKeys.KeyType) == KeyKeys.KeyType_EC2 ) {
			LOGGER.info("Starting AS with RPK");
			config.setSupportedCipherSuites(new CipherSuite[]{					
					CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
		} else {
			LOGGER.info("Starting AS with PSK only");
			config.setSupportedCipherSuites(new CipherSuite[]{
					CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
		}
		config.setPskStore(this.db);
		if (this.cose_key != null) {
			config.setIdentity(this.cose_key.AsPrivateKey(), 
					this.cose_key.AsPublicKey());
		}
		config.setClientAuthenticationRequired(true);
		//See -  https://github.com/eclipse/californium/issues/235
		config.setRetransmissionTimeout(20000);
		DTLSConnector connector = new DTLSConnector(config.build());
		addEndpoint(new CoapEndpoint(connector, NetworkConfig.getStandard()));
	}   



	public void close() throws Exception {
		// TODO Auto-generated method stub
		discovery_server.stop();
		this.c.close();
	}    
}
