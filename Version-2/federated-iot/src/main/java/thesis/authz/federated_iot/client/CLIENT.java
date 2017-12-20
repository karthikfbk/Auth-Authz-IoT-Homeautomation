package thesis.authz.federated_iot.client;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.URL;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.CoapClient.Builder;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

import org.json.JSONObject;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.OneKey;
import se.sics.ace.Constants;
import thesis.authz.federated_iot.Client_Params;
import thesis.authz.federated_iot.Utils.*;

public class CLIENT implements AutoCloseable{
	/**
	 * The logger
	 */
	private static final Logger LOGGER 
	= Logger.getLogger(CLIENT.class.getName() ); 

	private static final String marker = "******************************************************************";

	private DTLSConnector dtlsConnector;

	private StringBuilder Client_Job_result;
	private StringBuilder discovery_result;
	private StringBuilder fetch_as_config_result;
	private StringBuilder client_registration_result;

	private Client_Params parameters;

	/*
	 * Create a basic client
	 */
	public CoapClient client;

	public SECURITY_PROFILE client_security_profile;



	/*
	 * Constructor
	 */
	public CLIENT(Client_Params parameters) {
		this.Client_Job_result = new StringBuilder();
		this.discovery_result = new StringBuilder();
		this.fetch_as_config_result = new StringBuilder();
		this.client_registration_result = new StringBuilder();
		this.parameters = parameters;
	}

	private void create_Client(SECURITY_PROFILE sprofile, String host,
			String path, String query) throws CoseException, IOException {

		CoapClient.Builder client_builder = null;
		DtlsConnectorConfig.Builder dtls_builder = null;

		switch(sprofile) {
		case CoAP_Dtls_PSK:
			//YET to Implement
			break;
		case CoAP_Dtls_CERT:
			//YET to Implement
			break;
		case No_Security:
			if(host != null && !host.isEmpty()) 
				client_builder = new Builder(host, CoAP.DEFAULT_COAP_PORT).scheme("coap");			
			else {
				LOGGER.info("Invalid target host string");
				break;
			}
			if(path != null)
				client_builder.path(path);
			if(query !=null)
				client_builder.query(query);
			this.client = client_builder.create();
			this.client_security_profile = SECURITY_PROFILE.No_Security;
			break;

		case CoAP_Dtls_RPK:
			//TODO:
			//USE DTLSProfileRequests.getRpkClient in the future.
			OneKey asymmetricKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
			dtls_builder = new DtlsConnectorConfig.Builder(
					new InetSocketAddress(0));	        
			dtls_builder.setIdentity(asymmetricKey.AsPrivateKey(), 
					asymmetricKey.AsPublicKey());
			dtls_builder.setClientOnly();
			dtls_builder.setSupportedCipherSuites(new CipherSuite[]{
					CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
			//See -  https://github.com/eclipse/californium/issues/235
			dtls_builder.setRetransmissionTimeout(20000);
			this.dtlsConnector = new DTLSConnector(dtls_builder.build());
			this.dtlsConnector.start();
			CoapEndpoint e = new CoapEndpoint(dtlsConnector, NetworkConfig.getStandard());

			if(host != null && !host.isEmpty()) 
				client_builder = new Builder(host, CoAP.DEFAULT_COAP_SECURE_PORT).scheme("coaps");			
			else {
				LOGGER.info("Invalid target host string");
				break;
			}
			if(path != null)
				client_builder.path(path);
			if(query !=null)
				client_builder.query(query);
			this.client = client_builder.create();
			this.client.setEndpoint(e);
			//see - https://github.com/eclipse/californium/issues/235
			this.client.setTimeout(30000);
			this.client_security_profile = SECURITY_PROFILE.CoAP_Dtls_RPK;
			break;
		default:
			break;
		}
	}

	public void execute() throws CoseException, Exception {

		//If Discovery Bit is Set
		if((this.parameters.Client_JOBS & CLIENT_JOB.Discover_AS.getIdValue()) == 
				CLIENT_JOB.Discover_AS.getIdValue()) {
			this.discovery_result.append(marker).append("\n");
			this.discovery_result.append("<<<<<Discover_AS>>>>>").append("\n");
			execute_discovey_job();
			this.Client_Job_result.append(this.discovery_result);
		}
		//If Fetch_AS_Config Bit is Set
		if((this.parameters.Client_JOBS & CLIENT_JOB.Fetch_AS_Config.getIdValue()) == 
				CLIENT_JOB.Fetch_AS_Config.getIdValue()){	
			this.fetch_as_config_result.append(marker).append("\n");
			this.fetch_as_config_result.append("<<<<<Fetch_AS_Config>>>>>").append("\n");
			execute_fetch_asconfig_job();
			this.Client_Job_result.append(this.fetch_as_config_result);
		}

		//If Client_Registration Bit is Set
		if((this.parameters.Client_JOBS & CLIENT_JOB.Client_Registration.getIdValue()) == 
				CLIENT_JOB.Client_Registration.getIdValue()){	
			this.client_registration_result.append(marker).append("\n");
			this.client_registration_result.append("<<<<<Client_Registration>>>>>").append("\n");
			execute_client_registration_job();
			this.Client_Job_result.append(this.client_registration_result);
		}
		//If Dump Result Bit is Set
		if((this.parameters.Client_JOBS & CLIENT_JOB.Dump_Results.getIdValue()) == 
				CLIENT_JOB.Dump_Results.getIdValue()){	
			execute_dump_results_job();
		}

	}

		private void execute_client_registration_job() throws CoseException, IOException{
			if(this.parameters.server_metadata.registration_endpoint != null &&
					!this.parameters.server_metadata.registration_endpoint.isEmpty()) {
	
				// Just a small tweek by replacing the protocol from coap to http so that we can use the
				// existing URL library to extract the hostname and path
				// TODO: Maybe later write your own code to extract the hostname and path from coap url
				URL url = new URL(this.parameters.server_metadata.registration_endpoint.replaceAll(".*//","http://"));			
				String host = url.getHost();
				String path = url.getPath();
	
				//Remove the starting '/' from path if present
				if(path.startsWith("/"))
					path = path.replaceFirst("/", "");
				switch(SECURITY_PROFILE.valueOf(this.parameters.as_security_profile)) {
				case coap_dtls_psk:
					//YET TO IMPLEMENT
					break;
				case coap_dtls_rpk:
					create_Client(SECURITY_PROFILE.CoAP_Dtls_RPK,host,path,"");
	
					CBORObject params = CBORObject.NewMap();
					//<short,int>
					int value = GRANTS.getIntValues(this.parameters.client_metadata.grant_type);
					params.Add(CLIENT_METADATA.Grant_Type.getIdValue(), CBORObject.FromObject(value));
					//<short,cborstring>
					params.Add(CLIENT_METADATA.Client_Name.getIdValue(), CBORObject.FromObject(this.parameters.client_metadata.client_name));
					//<short,int>
					value = CLIENT_AUTH_METHOD.getIdEnum(this.parameters.client_metadata.token_endpoint_auth_method).getIdValue();
					params.Add(CLIENT_METADATA.Token_Endpoint_Auth_Method.getIdValue(), CBORObject.FromObject(value));
					//<short,int>
					value = CLIENT_ROLES.getIntValues(this.parameters.client_metadata.client_role);
					params.Add(CLIENT_METADATA.Client_Role.getIdValue(), CBORObject.FromObject(value));
					//<short,cborarray of cborstring>
					params.Add(CLIENT_METADATA.Scope.getIdValue(), CBORObject.FromObject(this.parameters.client_metadata.scope));
					//<short,int>
					value = SECURITY_PROFILE.getIdEnum(this.parameters.client_metadata.client_security_profile).getIdValue();
					params.Add(CLIENT_METADATA.Client_Security_Profile.getIdValue(), CBORObject.FromObject(value));
					//<short,cborstring>
					params.Add(CLIENT_METADATA.Client_Notification_Endpoint.getIdValue(), CBORObject.FromObject(this.parameters.client_metadata.client_notification_endpoint));
					
					CBORObject cose_keys = CBORObject.NewArray();
					for(JSONObject obj : this.parameters.client_metadata.cose_key) {
						CBORObject cose_key = CBORObject.NewMap();
						cose_key.Add(CLIENT_METADATA.Key_Usage.getIdValue(), CBORObject.FromObject(obj.getString("key_usage")));
						cose_key.Add(CLIENT_METADATA.Key_Type.getIdValue(), CBORObject.FromObject(obj.getString("key_type")));
						cose_key.Add(CLIENT_METADATA.Key.getIdValue(), CBORObject.FromObject(obj.getString("key")));
						cose_keys.Add(cose_key);
					}
					params.Add(CLIENT_METADATA.Cose_Key.getIdValue(), cose_keys);
					
					CoapResponse response = this.client.post(params.EncodeToBytes(), 
							MediaTypeRegistry.APPLICATION_CBOR);
	
					try {
						this.close();
					} catch (Exception e) {
						LOGGER.log(Level.WARNING, " Error closing Client Resource after client registration job");
						e.printStackTrace();
					}
					if(response == null) {
						LOGGER.info(" Received Null Client Registration response from Server ");
						System.exit(0);
					}
					else if(!response.getCode().equals(ResponseCode.CREATED)) {
						LOGGER.info(" Received Response code of  " + response.getCode().name() + " from server");
						System.exit(0);
					}
					else {
						CBORObject result = CBORObject.DecodeFromBytes(response.getPayload());
						if(result.getType().equals(CBORType.Map)) {
							for (CBORObject key : result.getKeys()) {
								if(key.getType().equals(CBORType.Number)) {
									if(key.AsInt16() == Constants.ERROR) {
										LOGGER.info(" Received error response from server " + result.get(key));
										System.exit(0);
									}
								CLIENT_METADATA registration_parameter = CLIENT_METADATA.getIdEnum(key.AsInt32());
								CBORObject rvalue;
								switch(registration_parameter) {
								case Grant_Type:
									rvalue = result.get(key);
									if(rvalue.getType().equals(CBORType.Number)) {
										
											this.parameters.client_metadata.grant_type = GRANTS.getStringValues(rvalue.AsInt32());
											this.client_registration_result.append("grant_type:").append(this.parameters.client_metadata.grant_type).append("\n");
										
									}else {
										this.parameters.client_metadata.grant_type = null;
										this.client_registration_result.append("grant_type_supported:").append(this.parameters.client_metadata.grant_type).append("\n");
									}
									break;
								case Client_Name:
									rvalue = result.get(key);
									if(rvalue.getType().equals(CBORType.TextString)) {
										this.parameters.client_metadata.client_name = rvalue.AsString();
										this.client_registration_result.append("client_name:").append(this.parameters.client_metadata.client_name).append("\n");
									}else {
										this.parameters.client_metadata.client_name = null;
										this.client_registration_result.append("client_name:").append(this.parameters.client_metadata.client_name).append("\n");
									}
									break;
								case Token_Endpoint_Auth_Method:
									rvalue = result.get(key);
									if(rvalue.getType().equals(CBORType.Number)) {
										
											this.parameters.client_metadata.token_endpoint_auth_method = CLIENT_AUTH_METHOD.getStringEnum(rvalue.AsInt32()).getNameValue();
											this.client_registration_result.append("token_endpoint_auth_method:").append(this.parameters.client_metadata.token_endpoint_auth_method).append("\n");
										
									}else {
										this.parameters.client_metadata.token_endpoint_auth_method = null;
										this.client_registration_result.append("token_endpoint_auth_method:").append(this.parameters.client_metadata.token_endpoint_auth_method).append("\n");
									}
									break;
								case Client_Role:
									rvalue = result.get(key);
									if(rvalue.getType().equals(CBORType.Number)) {
										
											this.parameters.client_metadata.client_role = CLIENT_ROLES.getStringValues(rvalue.AsInt32());
											this.client_registration_result.append("client_role:").append(this.parameters.client_metadata.client_role).append("\n");
										
									}else {
										this.parameters.client_metadata.client_role = null;
										this.client_registration_result.append("client_role:").append(this.parameters.client_metadata.client_role).append("\n");
									}
									break;
								case Scope:
									rvalue = result.get(key);
									if(rvalue.getType().equals(CBORType.Array)) {
										this.parameters.client_metadata.scope.clear();
										for(CBORObject obj:rvalue.getValues()) {
											this.parameters.client_metadata.scope.add(obj.AsString());
										}
											
											this.client_registration_result.append("scope:").append(this.parameters.client_metadata.scope).append("\n");
										
									}else {
										this.parameters.client_metadata.scope = null;
										this.client_registration_result.append("scope:").append(this.parameters.client_metadata.scope).append("\n");
									}
									
									break;
								case Client_Security_Profile:
									rvalue = result.get(key);
									if(rvalue.getType().equals(CBORType.Number)) {
										
											this.parameters.client_metadata.client_security_profile = SECURITY_PROFILE.getStringEnum(rvalue.AsInt32()).getNameValue();
											this.client_registration_result.append("client_security_profile:").append(this.parameters.client_metadata.client_security_profile).append("\n");
										
									}else {
										this.parameters.client_metadata.client_security_profile = null;
										this.client_registration_result.append("client_security_profile:").append(this.parameters.client_metadata.client_security_profile).append("\n");
									}
									break;
								case Privilege_Client_Secret:
									rvalue = result.get(key);
									if(rvalue.getType().equals(CBORType.TextString)) {
										this.parameters.client_metadata.privilege_client_secret = rvalue.AsString();
										this.client_registration_result.append("privilege_client_secret:").append(this.parameters.client_metadata.privilege_client_secret).append("\n");
									}else {
										this.parameters.client_metadata.privilege_client_secret = null;
										this.client_registration_result.append("privilege_client_secret:").append(this.parameters.client_metadata.privilege_client_secret).append("\n");
									}							
									break;
								case Client_Notification_Endpoint:
									rvalue = result.get(key);
									if(rvalue.getType().equals(CBORType.TextString)) {
										this.parameters.client_metadata.client_notification_endpoint = rvalue.AsString();
										this.client_registration_result.append("client_notification_endpoint:").append(this.parameters.client_metadata.client_notification_endpoint).append("\n");
									}else {
										this.parameters.client_metadata.client_notification_endpoint = null;
										this.client_registration_result.append("client_notification_endpoint:").append(this.parameters.client_metadata.client_notification_endpoint).append("\n");
									}
									break;

								case Client_Id:
									rvalue = result.get(key);
									if(rvalue.getType().equals(CBORType.TextString)) {
										this.parameters.client_metadata.client_id = rvalue.AsString();
										this.client_registration_result.append("client_id:").append(this.parameters.client_metadata.client_id).append("\n");
									}else {
										this.parameters.client_metadata.client_id = null;
										this.client_registration_result.append("client_id:").append(this.parameters.client_metadata.client_id).append("\n");
									}									
									break;
								case Client_Secret:
									rvalue = result.get(key);
									if(rvalue.getType().equals(CBORType.TextString)) {
										this.parameters.client_metadata.client_secret = rvalue.AsString();
										this.client_registration_result.append("client_secret:").append(this.parameters.client_metadata.client_secret).append("\n");
									}else {
										this.parameters.client_metadata.client_secret = null;
										this.client_registration_result.append("client_secret:").append(this.parameters.client_metadata.client_secret).append("\n");
									}								
									break;
								default:
									break;
								}
								}
								else {
									LOGGER.info(" Invalid Payload key format Received from server");
									System.exit(0);
								}
							}
						}
						else {
							LOGGER.info(" Invalid Response Payload Format Received from server");
							System.exit(0);
						}
					}
					break;
				case coap_dtls_cert:
					//YET TO IMPLEMENT
					break;
				case oscoap:
					//YET TO IMPLEMENT
					break;
				case no_security:
					//YET TO IMPLEMENT
					break;
				default:
					break;		
				}
			}
	
		}

	private void execute_dump_results_job() throws Exception {
		// TODO Auto-generated method stub
		if(this.parameters.to_console)
			System.out.println(this.Client_Job_result);
		if(this.parameters.to_file) {
			PrintWriter out = new PrintWriter(new FileWriter(this.parameters.output_filepath));
			//output to the file
			out.println(this.Client_Job_result);
			out.close();
		}
	}

	private void execute_discovey_job() throws CoseException, IOException {
		create_Client(SECURITY_PROFILE.No_Security,this.parameters.host,"","");
		if(this.parameters.query != null && !this.parameters.query.isEmpty()) {
			try {
				//Discover the AS using the query String
				Set<WebLink> discovered_links = this.client.discover(this.parameters.query);
				if(discovered_links != null && discovered_links.size() > 0) {
					WebLink first_link = discovered_links.iterator().next();

					//Set the config endpoint of AS based on returned result
					this.parameters.server_metadata.config_endpoint = first_link.getURI().replaceFirst("/", "");
					this.discovery_result.append("config_endpoint:").append(this.parameters.server_metadata.config_endpoint).append("\n");
					//Set the security profile of the config endpoint
					String link_profile_attribute = first_link.getAttributes().getAttributeValues("profile").get(0);
					SECURITY_PROFILE as_secprofile = SECURITY_PROFILE.valueOf(link_profile_attribute);
					switch(as_secprofile) {
					case coap_dtls_psk:
						this.parameters.as_security_profile = SECURITY_PROFILE.coap_dtls_psk.getNameValue();
						this.discovery_result.append("as_security_profile:").append(this.parameters.as_security_profile).append("\n");
						break;
					case coap_dtls_rpk:
						this.parameters.as_security_profile = SECURITY_PROFILE.coap_dtls_rpk.getNameValue();
						this.discovery_result.append("as_security_profile:").append(this.parameters.as_security_profile).append("\n");
						break;
					case coap_dtls_cert:
						this.parameters.as_security_profile = SECURITY_PROFILE.coap_dtls_cert.getNameValue();
						this.discovery_result.append("as_security_profile:").append(this.parameters.as_security_profile).append("\n");
						break;
					case oscoap:
						this.parameters.as_security_profile = SECURITY_PROFILE.oscoap.getNameValue();
						this.discovery_result.append("as_security_profile:").append(this.parameters.as_security_profile).append("\n");
						break;
					case no_security:
						this.parameters.as_security_profile = SECURITY_PROFILE.no_security.getNameValue();
						this.discovery_result.append("as_security_profile:").append(this.parameters.as_security_profile).append("\n");
						break;
					default:
						break;
					}
				}
				else {
					LOGGER.info("Received null response for discovery");
					System.exit(0);
				}
			}
			catch(Exception e) {
				LOGGER.log(Level.SEVERE, "Caught exception during discovery operation");
				e.printStackTrace();
				System.exit(0);
			}
		}
		else {
			LOGGER.info("Invalid Query Search String.");
			LOGGER.info("Search for AS as anchor=/as/asconfig");
			LOGGER.info("Search for CAS as anchor=/cas/casconfig");
			LOGGER.info("Search for AS and CAS as anchor=/ascas/ascasconfig");
			System.exit(0);
		}
	}

	private void execute_fetch_asconfig_job() throws CoseException, IOException {
		if(this.parameters.server_metadata.config_endpoint != null &&
				!this.parameters.server_metadata.config_endpoint.isEmpty()) {

			// Just a small tweek by replacing the protocol from coap to http so that we can use the
			// existing URL library to extract the hostname and path
			// TODO: Maybe later write your own code to extract the hostname and path from coap url
			URL url = new URL(this.parameters.server_metadata.config_endpoint.replaceAll(".*//","http://"));			
			String host = url.getHost();
			String path = url.getPath();

			//Remove the starting '/' from path if present
			if(path.startsWith("/"))
				path = path.replaceFirst("/", "");
			switch(SECURITY_PROFILE.valueOf(this.parameters.as_security_profile)) {
			case coap_dtls_psk:
				//YET TO IMPLEMENT
				break;
			case coap_dtls_rpk:
				create_Client(SECURITY_PROFILE.CoAP_Dtls_RPK,host,path,"");
				CoapResponse response = this.client.get();
				try {
					this.close();
				} catch (Exception e) {
					LOGGER.log(Level.WARNING, " Error closing Client Resource after fetch asconfig job");
					e.printStackTrace();
				}
				if(response == null) {
					LOGGER.info(" Received Null Client fetch asconfig response from Server ");
					System.exit(0);
				}
				else if(!response.getCode().equals(ResponseCode.CREATED)) {
					LOGGER.info(" Received Response code of  " + response.getCode().name() + " from server");
					System.exit(0);
				}
				else {
					CBORObject result = CBORObject.DecodeFromBytes(response.getPayload());

					if(result.getType().equals(CBORType.Map)) {
						for (CBORObject key : result.getKeys()) {
							//System.out.println(key.toString() + " : " + result.get(key).toString());
							if(key.getType().equals(CBORType.Number)) {
								CBORObject value;
								SERVER_METADATA server_metadata = SERVER_METADATA.getIdEnum(key.AsInt32());
								switch(server_metadata) {
								case Issuer:
									value = result.get(key);
									if(value.getType().equals(CBORType.TextString)) {
										this.parameters.server_metadata.issuer = value.AsString();
										this.fetch_as_config_result.append("issuer:").append(this.parameters.server_metadata.issuer).append("\n");
									}else {
										this.parameters.server_metadata.issuer = null;
										this.fetch_as_config_result.append("issuer:").append(this.parameters.server_metadata.issuer).append("\n");
									}
									break;
								case Auth_Mode:
									value = result.get(key);
									if(value.getType().equals(CBORType.TextString)) {
										this.parameters.server_metadata.auth_mode = value.AsString();
										this.fetch_as_config_result.append("authorization_mode:").append(this.parameters.server_metadata.auth_mode).append("\n");
									}else {
										this.parameters.server_metadata.issuer = null;
										this.fetch_as_config_result.append("authorization_mode:").append(this.parameters.server_metadata.auth_mode).append("\n");
									}
									break;
								case Config_Endpoint:
									value = result.get(key);
									if(value.getType().equals(CBORType.TextString)) {
										this.parameters.server_metadata.config_endpoint = value.AsString();
										this.fetch_as_config_result.append("config_endpoint:").append(this.parameters.server_metadata.config_endpoint).append("\n");
									}else {
										this.parameters.server_metadata.config_endpoint = null;
										this.fetch_as_config_result.append("config_endpoint:").append(this.parameters.server_metadata.config_endpoint).append("\n");
									}
									break;
								case Token_Endpoint:
									value = result.get(key);
									if(value.getType().equals(CBORType.TextString)) {
										this.parameters.server_metadata.token_endpoint = value.AsString();
										this.fetch_as_config_result.append("token_endpoint:").append(this.parameters.server_metadata.token_endpoint).append("\n");
									}else {
										this.parameters.server_metadata.token_endpoint = null;
										this.fetch_as_config_result.append("token_endpoint:").append(this.parameters.server_metadata.token_endpoint).append("\n");
									}
									break;
								case Query_Endpoint:
									value = result.get(key);
									if(value.getType().equals(CBORType.TextString)) {
										this.parameters.server_metadata.query_endpoint = value.AsString();
										this.fetch_as_config_result.append("query_endpoint:").append(this.parameters.server_metadata.query_endpoint).append("\n");
									}else {
										this.parameters.server_metadata.query_endpoint = null;
										this.fetch_as_config_result.append("query_endpoint:").append(this.parameters.server_metadata.query_endpoint).append("\n");
									}
									break;
								case Registration_Endpoint:
									value = result.get(key);
									if(value.getType().equals(CBORType.TextString)) {
										this.parameters.server_metadata.registration_endpoint = value.AsString();
										this.fetch_as_config_result.append("registration_endpoint:").append(this.parameters.server_metadata.registration_endpoint).append("\n");
									}else {
										this.parameters.server_metadata.registration_endpoint = null;
										this.fetch_as_config_result.append("registration_endpoint:").append(this.parameters.server_metadata.registration_endpoint).append("\n");
									}
									break;
								case Grant_Type_Supported:
									value = result.get(key);
									if(value.getType().equals(CBORType.Number)) {
										
											this.parameters.server_metadata.grant_type_supported = GRANTS.getStringValues(value.AsInt32());
											this.fetch_as_config_result.append("grant_type_supported:").append(this.parameters.server_metadata.grant_type_supported).append("\n");
										
									}else {
										this.parameters.server_metadata.grant_type_supported = null;
										this.fetch_as_config_result.append("grant_type_supported:").append(this.parameters.server_metadata.grant_type_supported).append("\n");
									}
									break;
								case Token_Endpoint_Auth_Method:
									value = result.get(key);
									if(value.getType().equals(CBORType.Number)) {
										this.parameters.server_metadata.token_endpoint_auth_method = CLIENT_AUTH_METHOD.getStringValues(value.AsInt32());
										this.fetch_as_config_result.append("token_endpoint_auth_method:").append(this.parameters.server_metadata.token_endpoint_auth_method).append("\n");
									}else {
										this.parameters.server_metadata.token_endpoint_auth_method = null;
										this.fetch_as_config_result.append("token_endpoint_auth_method:").append(this.parameters.server_metadata.token_endpoint_auth_method).append("\n");
									}
									break;
								case Introspection_Endpoint:
									value = result.get(key);
									if(value.getType().equals(CBORType.TextString)) {
										this.parameters.server_metadata.introspection_endpoint = value.AsString();
										this.fetch_as_config_result.append("introspection_endpoint:").append(this.parameters.server_metadata.introspection_endpoint).append("\n");
									}else {
										this.parameters.server_metadata.introspection_endpoint = null;
										this.fetch_as_config_result.append("introspection_endpoint:").append(this.parameters.server_metadata.introspection_endpoint).append("\n");
									}
									break;
								case Introspection_Endpoint_Auth_Method:
									value = result.get(key);
									if(value.getType().equals(CBORType.Number)) {
										this.parameters.server_metadata.introspection_endpoint_auth_method = CLIENT_AUTH_METHOD.getStringValues(value.AsInt32());
										this.fetch_as_config_result.append("introspection_endpoint_auth_method:").append(this.parameters.server_metadata.introspection_endpoint_auth_method).append("\n");
									}else {
										this.parameters.server_metadata.introspection_endpoint_auth_method = null;
										this.fetch_as_config_result.append("introspection_endpoint_auth_method:").append(this.parameters.server_metadata.introspection_endpoint_auth_method).append("\n");
									}
									break;
								case Cose_Key:
									value = result.get(key);
									if(value.getType().equals(CBORType.TextString)) {
										this.parameters.server_metadata.cose_key = value.AsString();
										this.fetch_as_config_result.append("cose_key:").append(this.parameters.server_metadata.cose_key).append("\n");
									}else {
										this.parameters.server_metadata.cose_key = null;
										this.fetch_as_config_result.append("cose_key:").append(this.parameters.server_metadata.cose_key).append("\n");
									}
									break;
								case Client_Count:
									value = result.get(key);
									if(value.getType().equals(CBORType.Number)) {
										this.parameters.server_metadata.client_count = value.AsInt16();
										this.fetch_as_config_result.append("client_count:").append(this.parameters.server_metadata.client_count).append("\n");
									}else {
										this.parameters.server_metadata.client_count = -1;
										this.fetch_as_config_result.append("client_count:").append(this.parameters.server_metadata.client_count).append("\n");
									}
									break;
								default:
									break;
								}
							}
							else {
								LOGGER.info(" Invalid Payload key format Received from server");
								System.exit(0);
							}
						}
						
					}
					else {
						LOGGER.info(" Invalid Response Payload Format Received from server");
						System.exit(0);
					}
				}
				break;
			case coap_dtls_cert:
				//YET TO IMPLEMENT
				break;
			case no_security:
				//YET TO IMPLEMENT
				break;
			default:
				break;		
			}
		}else {
			LOGGER.info("Invalid Server Config Endpoint Value");
			System.exit(0);
		}
	}

	//	private void collect_results(CLIENT_JOB Client_job) {
	//		// TODO Auto-generated method stub
	//		switch(Client_job) {
	//		case Discover_AS:
	//			this.Client_Job_result.append(marker).append("\n");
	//			this.Client_Job_result.append("<<<<<Discover_AS>>>>>").append("\n");
	//			
	//			this.Client_Job_result.append("config_endpoint:").append(this.parameters.server_metadata.config_endpoint).append("\n").
	//			append("secprofile:").append(this.parameters.as_secprofile).append("\n");
	//
	//			this.Client_Job_result.append(marker).append("\n");
	//			break;
	//		case Fetch_AS_Config:
	//			this.Client_Job_result.append(marker).append("\n");
	//			this.Client_Job_result.append("<<<<<Fetch_AS_Config>>>>>").append("\n");
	//
	//			this.Client_Job_result.append("issuer:").append(this.parameters.server_metadata.issuer).append("\n");
	//			this.Client_Job_result.append("token_endpoint:").append(this.parameters.server_metadata.token_endpoint).append("\n");
	//			this.Client_Job_result.append("token_endpoint_auth_method:").append(this.parameters.server_metadata.token_endpoint_auth_method).append("\n");
	//			this.Client_Job_result.append("introspection_endpoint:").append(this.parameters.server_metadata.introspection_endpoint).append("\n");
	//			this.Client_Job_result.append("introspection_endpoint_auth_method:").append(this.parameters.server_metadata.introspection_endpoint_auth_method).append("\n");
	//			this.Client_Job_result.append("registration_endpoint:").append(this.parameters.server_metadata.registration_endpoint).append("\n");
	//			this.Client_Job_result.append("query_endpoint:").append(this.parameters.server_metadata.query_endpoint).append("\n");
	//			this.Client_Job_result.append("grant_type_supported:").append(this.parameters.server_metadata.grant_type_supported).append("\n");
	//			this.Client_Job_result.append("cose_key:").append(this.parameters.server_metadata.cose_key.AsCBOR()).append("\n");
	//			this.Client_Job_result.append("client_count:").append(this.parameters.server_metadata.client_count).append("\n");
	//
	//			this.Client_Job_result.append(marker).append("\n");
	//			break;			
	//		case Client_Registration:
	//			this.Client_Job_result.append(marker).append("\n");
	//			this.Client_Job_result.append("<<<<<Client_Registration>>>>>").append("\n");
	//
	//			this.Client_Job_result.append("grant_type:").append(this.parameters.client_metadata.grant_type.toString()).append("\n");
	//			this.Client_Job_result.append("client_name:").append(this.parameters.client_metadata.client_name.toString()).append("\n");
	//			this.Client_Job_result.append("token_endpoint_auth_method:").append(this.parameters.client_metadata.token_endpoint_auth_method.toString()).append("\n");
	//			this.Client_Job_result.append("client_role:").append(this.parameters.client_metadata.client_role.toString()).append("\n");
	//			this.Client_Job_result.append("scope:").append(this.parameters.client_metadata.scope.toString()).append("\n");
	//			this.Client_Job_result.append("client_security_profile:").append(this.parameters.client_metadata.client_security_profile.toString()).append("\n");
	//			this.Client_Job_result.append("privilege_client_secret:").append(this.parameters.client_metadata.privilege_client_secret.toString()).append("\n");
	//			this.Client_Job_result.append("client_notification_endpoint:").append(this.parameters.client_metadata.client_notification_endpoint.toString()).append("\n");
	//			this.Client_Job_result.append("cose_key:").append(this.parameters.client_metadata.cose_key.toString()).append("\n");
	//			this.Client_Job_result.append("contact:").append(this.parameters.client_metadata.contact.toString()).append("\n");	
	//			this.Client_Job_result.append("client_id:").append(this.parameters.client_metadata.client_id.toString()).append("\n");
	//			this.Client_Job_result.append("client_secret:").append(this.parameters.client_metadata.client_secret.toString()).append("\n");
	//
	//			this.Client_Job_result.append(marker).append("\n");
	//			break;
	//		default:
	//			break;
	//		}
	//
	//	}

	@Override
	public void close() throws Exception {
		// TODO Auto-generated method stub
		if(this.dtlsConnector !=null)
		{
			this.dtlsConnector.destroy();
		}
	}	
}
