package thesis.authz.federated_iot;

import java.util.ArrayList;

import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONArray;
import org.json.JSONObject;

import thesis.authz.federated_iot.Utils.*;

public class Client_Params {
	private static final Logger LOGGER 
	= Logger.getLogger(Client_Params.class.getName() ); 

	public String host; //Authorization Server hostname of ip
	public String query; //Query string used to discover the AS
	public String as_security_profile; //Security profile of the AS
	public Server_Metadata server_metadata;
	public Client_Metadata client_metadata;
	public Boolean to_console;
	public Boolean to_file;
	public String output_filepath;
	public int Client_JOBS;

	public Client_Params() {
		this.server_metadata = new Server_Metadata();
		this.client_metadata = new Client_Metadata();
	}
	public class Server_Metadata{
		public String issuer;
		public String config_endpoint;
		public String token_endpoint;
		public String query_endpoint;
		public String registration_endpoint;
		public List<String> grant_type_supported;
		public List<String> token_endpoint_auth_method;
		public String introspection_endpoint;
		public List<String> introspection_endpoint_auth_method;
		public String cose_key;
		public int client_count;

		public Server_Metadata() {
			this.grant_type_supported = new ArrayList<String>();
			this.token_endpoint_auth_method = new ArrayList<String>();
			this.introspection_endpoint_auth_method = new ArrayList<String>();
		}
	}

	public class Client_Metadata{
		public List<String> grant_type; //type array of textstring
		public String client_name; //type textstring
		public String token_endpoint_auth_method; //type textstring
		public List<String> client_role; //type array of textstring
		public List<String> scope; //type array of textstring
		public String client_security_profile; //type textstring
		public String privilege_client_secret; //type textstring
		public String client_notification_endpoint; //type textstring
		public String cose_key; //type OneKey
		public String contact; //type textstring
		public String client_id; //type textstring
		public String client_secret; //type textstring

		public Client_Metadata() {
			this.grant_type = new ArrayList<String>();
			this.client_role = new ArrayList<String>();
			this.scope = new ArrayList<String>();
		}
	}

	public void Fill(JSONObject params) {
		try {
			//Get the ClientJobs
			JSONObject job = (JSONObject) params.get("job");
			Iterator<String> jobkeys = job.keys();

			//Get the ClientResults
			JSONObject results = (JSONObject) params.get("results");


			while(jobkeys.hasNext()) {
				String key = (String)jobkeys.next();
				CLIENT_JOB key_method = CLIENT_JOB.valueOf(key);
				Object key_value = null;
				switch(key_method) {
				case discover_as:
					key_value = job.get(key);
					if(key_value instanceof Boolean) {
						if((Boolean)key_value) { //If discovery is set to true
							this.Client_JOBS = this.Client_JOBS | CLIENT_JOB.Discover_AS.getIdValue();
							JSONObject discover_as = (JSONObject)params.get(key);
							Object value;
							value = discover_as.get("host");
							if(value instanceof String) 
								this.host = value.toString();
							else {
								LOGGER.log(Level.SEVERE, "Invalid host parameter value");
								return;
							}
							value = discover_as.get("query");
							if(value instanceof String) 
								this.query = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid query parameter value");
								return;
							}

						}
						else {
							JSONObject discover_as_result = (JSONObject) results.get(key);
							Object value;
							value = discover_as_result.get("config_endpoint");
							if(value instanceof String) 
								this.server_metadata.config_endpoint = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid config_endpoint parameter value");
								return;
							}

							value = discover_as_result.get("as_security_profile");
							if(value instanceof String) 
								this.as_security_profile = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid as_security_profile parameter value");
								return;
							}

						}
						System.out.println("***********Discovery Job");
						System.out.println(this.host);
						System.out.println(this.query);
						System.out.println(this.server_metadata.config_endpoint);
						System.out.println(this.as_security_profile);
					}
					break;
				case fetch_as_config:
					key_value = job.get(key);
					if(key_value instanceof Boolean) {
						if((Boolean)key_value) { //If discovery is set to true
							this.Client_JOBS = this.Client_JOBS | CLIENT_JOB.Fetch_AS_Config.getIdValue();
						}
						else {
							JSONObject fetch_as_config_result = (JSONObject) results.get(key);
							Object value;
							value = fetch_as_config_result.get("issuer");
							if(value instanceof String) 
								this.server_metadata.issuer = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid issuer parameter value");
								return;
							}

							value = fetch_as_config_result.get("token_endpoint");
							if(value instanceof String) 
								this.server_metadata.token_endpoint = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid token_endpoint parameter value");
								return;
							}

							value = fetch_as_config_result.get("token_endpoint_auth_method");
							if(value instanceof JSONArray) {
								JSONArray j = (JSONArray)value;
								for(int i=0; i<j.length(); i++) {
									this.server_metadata.token_endpoint_auth_method.add(j.getString(i));
								}
							}
							else{
								LOGGER.log(Level.SEVERE, "Invalid token_endpoint_auth_method parameter value");
								return;
							}

							value = fetch_as_config_result.get("introspection_endpoint");
							if(value instanceof String) 
								this.server_metadata.introspection_endpoint = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid introspection_endpoint parameter value");
								return;
							}

							value = fetch_as_config_result.get("introspection_endpoint_auth_method");
							if(value instanceof JSONArray) {
								JSONArray j = (JSONArray)value;
								for(int i=0; i<j.length(); i++) {
									this.server_metadata.introspection_endpoint_auth_method.add(j.getString(i));
								}
							}
							else{
								LOGGER.log(Level.SEVERE, "Invalid introspection_endpoint_auth_method parameter value");
								return;
							}

							value = fetch_as_config_result.get("query_endpoint");
							if(value instanceof String) 
								this.server_metadata.query_endpoint = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid query_endpoint parameter value");
								return;
							}

							value = fetch_as_config_result.get("registration_endpoint");
							if(value instanceof String) 
								this.server_metadata.registration_endpoint = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid registration_endpoint parameter value");
								return;
							}

							value = fetch_as_config_result.get("grant_type_supported");
							if(value instanceof JSONArray) {
								JSONArray j = (JSONArray)value;
								for(int i=0; i<j.length(); i++) {
									this.server_metadata.grant_type_supported.add(j.getString(i));
								}
							}
							else{
								LOGGER.log(Level.SEVERE, "Invalid grant_type_supported parameter value");
								return;
							}

							value = fetch_as_config_result.get("cose_key");
							if(value instanceof String) 
								this.server_metadata.cose_key = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid cose_key parameter value");
								return;
							}

							value = fetch_as_config_result.get("client_count");
							if(value instanceof Integer) 
								this.server_metadata.client_count = ((Integer) value).intValue();
							else{
								LOGGER.log(Level.SEVERE, "Invalid client_count parameter value");
								return;
							}

							/*
							this.server_metadata.issuer = fetch_as_config_result.getString("issuer").trim().replace("\"", "");
							this.server_metadata.token_endpoint = fetch_as_config_result.getString("token_endpoint").trim().replace("\"", "");
							this.server_metadata.token_endpoint_auth_method = fetch_as_config_result.getString("token_endpoint_auth_method").trim().replace("\"", "");
							this.server_metadata.introspection_endpoint = fetch_as_config_result.getString("introspection_endpoint").trim().replace("\"", "");
							this.server_metadata.introspection_endpoint_auth_method = fetch_as_config_result.getString("introspection_endpoint_auth_method").trim().replace("\"", "");
							this.server_metadata.query_endpoint = fetch_as_config_result.getString("query_endpoint").trim().replace("\"", "");
							this.server_metadata.registration_endpoint = fetch_as_config_result.getString("registration_endpoint").trim().replace("\"", "");
							this.server_metadata.grant_type_supported = fetch_as_config_result.getString("grant_type_supported").trim().replace("\"", "");
							this.server_metadata.token_endpoint_auth_method = fetch_as_config_result.getString("token_endpoint_auth_method").trim().replace("\"", "");
							this.server_metadata.cose_key =  new OneKey(
									CBORObject.DecodeFromBytes(Base64.getDecoder().decode(fetch_as_config_result.getString("cose_key"))));
							this.server_metadata.client_count = fetch_as_config_result.getString("client_count");		*/
						}
						System.out.println("***********Fetch AS Config Job");
						System.out.println(this.server_metadata.issuer);
						System.out.println(this.server_metadata.token_endpoint);
						System.out.println(this.server_metadata.token_endpoint_auth_method);
						System.out.println(this.server_metadata.query_endpoint);
						System.out.println(this.server_metadata.registration_endpoint);
						System.out.println(this.server_metadata.introspection_endpoint);
						System.out.println(this.server_metadata.introspection_endpoint_auth_method);
						System.out.println(this.server_metadata.grant_type_supported);
						System.out.println(this.server_metadata.cose_key);
						System.out.println(this.server_metadata.client_count);
					}
					break;
				case client_registration:
					key_value = job.get(key);
					if(key_value instanceof Boolean) {
						if((Boolean)key_value) { //If client registration is set to true
							this.Client_JOBS = this.Client_JOBS | CLIENT_JOB.Client_Registration.getIdValue();

							JSONObject client_registration = (JSONObject)params.get(key);
							Object value;
							value = client_registration.get("grant_type");
							//grant_type parameter
							if(value instanceof JSONArray) {
								JSONArray j = (JSONArray)value;
								for(int i=0; i<j.length(); i++) {
									this.client_metadata.grant_type.add(j.getString(i));
								}
							}
							else{
								LOGGER.log(Level.SEVERE, "Invalid grant_type parameter value");
								return;
							}

							//client_name parameter
							value = client_registration.get("client_name");
							if(value instanceof String) 
								this.client_metadata.client_name = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid client_name parameter value");
								return;
							}


							//token_endpoint_auth_method paramter
							value = client_registration.get("token_endpoint_auth_method");
							if(value instanceof String) 
								this.client_metadata.token_endpoint_auth_method = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid token_endpoint_auth_method parameter value");
								return;
							}


							//client_role parameter
							value = client_registration.get("client_role");
							if(value instanceof JSONArray) {
								JSONArray j = (JSONArray)value;
								for(int i=0; i<j.length(); i++) {
									this.client_metadata.client_role.add(j.getString(i));
								}
							}
							else{
								LOGGER.log(Level.SEVERE, "Invalid client_role parameter value");
								return;
							}


							//scope parameter
							value = client_registration.get("scope");
							if(value instanceof JSONArray) {
								JSONArray j = (JSONArray)value;
								for(int i=0; i<j.length(); i++) {
									this.client_metadata.scope.add(j.getString(i));
								}
							}
							else{
								LOGGER.log(Level.SEVERE, "Invalid scope parameter value");
								return;
							}


							//client_security_profile
							value = client_registration.get("client_security_profile");
							if(value instanceof String) 
								this.client_metadata.client_security_profile = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid client_security_profile parameter value");
								return;
							}



							//privilege_client_secret
							value = client_registration.get("privilege_client_secret");
							if(value instanceof String) 
								this.client_metadata.privilege_client_secret = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid privilege_client_secret parameter value");
								return;
							}


							//client_notification_endpoint
							value = client_registration.get("client_notification_endpoint");
							if(value instanceof String) 
								this.client_metadata.client_notification_endpoint = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid client_notification_endpoint parameter value");
								return;
							}



							//cose_keys
							value = client_registration.get("cose_key");
							if(value instanceof String) 
								this.client_metadata.cose_key = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid cose_key parameter value");
								return;
							}


							//contact
							value = client_registration.get("contact");
							if(value instanceof String) 
								this.client_metadata.contact = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid contact parameter value");
								return;
							}


						}
						else {			
							JSONObject client_registration_result = (JSONObject)results.get(key);
							Object value;
							value = client_registration_result.get("grant_type");
							//grant_type parameter
							if(value instanceof JSONArray) {
								JSONArray j = (JSONArray)value;
								for(int i=0; i<j.length(); i++) {
									this.client_metadata.grant_type.add(j.getString(i));
								}
							}
							else{
								LOGGER.log(Level.SEVERE, "Invalid grant_type parameter value");
								return;
							}

							//client_name parameter
							value = client_registration_result.get("client_name");
							if(value instanceof String) 
								this.client_metadata.client_name = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid client_name parameter value");
								return;
							}


							//token_endpoint_auth_method paramter
							value = client_registration_result.get("token_endpoint_auth_method");
							if(value instanceof String) 
								this.client_metadata.token_endpoint_auth_method = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid token_endpoint_auth_method parameter value");
								return;
							}


							//client_role parameter
							value = client_registration_result.get("client_role");
							if(value instanceof JSONArray) {
								JSONArray j = (JSONArray)value;
								for(int i=0; i<j.length(); i++) {
									this.client_metadata.client_role.add(j.getString(i));
								}
							}
							else{
								LOGGER.log(Level.SEVERE, "Invalid client_role parameter value");
								return;
							}


							//scope parameter
							value = client_registration_result.get("scope");
							if(value instanceof JSONArray) {
								JSONArray j = (JSONArray)value;
								for(int i=0; i<j.length(); i++) {
									this.client_metadata.scope.add(j.getString(i));
								}
							}
							else{
								LOGGER.log(Level.SEVERE, "Invalid scope parameter value");
								return;
							}


							//client_security_profile
							value = client_registration_result.get("client_security_profile");
							if(value instanceof String) 
								this.client_metadata.client_security_profile = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid client_security_profile parameter value");
								return;
							}



							//privilege_client_secret
							value = client_registration_result.get("privilege_client_secret");
							if(value instanceof String) 
								this.client_metadata.privilege_client_secret = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid privilege_client_secret parameter value");
								return;
							}


							//client_notification_endpoint
							value = client_registration_result.get("client_notification_endpoint");
							if(value instanceof String) 
								this.client_metadata.client_notification_endpoint = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid client_notification_endpoint parameter value");
								return;
							}



							//cose_keys
							value = client_registration_result.get("cose_key");
							if(value instanceof String) 
								this.client_metadata.cose_key = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid cose_key parameter value");
								return;
							}


							//contact
							value = client_registration_result.get("contact");
							if(value instanceof String) 
								this.client_metadata.contact = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid contact parameter value");
								return;
							}


							//client_id
							value = client_registration_result.get("client_id");
							if(value instanceof String) 
								this.client_metadata.client_id = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid client_id parameter value");
								return;
							}



							//client_secret
							value = client_registration_result.get("client_secret");
							if(value instanceof String) 
								this.client_metadata.client_secret = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid client_secret parameter value");	
								return;
							}

						}
						System.out.println("***********Client Registration Job");
						System.out.println(this.client_metadata.grant_type);
						System.out.println(this.client_metadata.client_name);
						System.out.println(this.client_metadata.token_endpoint_auth_method);
						System.out.println(this.client_metadata.client_role);
						System.out.println(this.client_metadata.scope);
						System.out.println(this.client_metadata.client_security_profile);
						System.out.println(this.client_metadata.client_notification_endpoint);
						System.out.println(this.client_metadata.privilege_client_secret);
						System.out.println(this.client_metadata.cose_key);
						System.out.println(this.client_metadata.contact);
						System.out.println(this.client_metadata.client_id);
						System.out.println(this.client_metadata.client_secret);
					}
					break;
				case dump_results:
					key_value = job.get(key);
					if(key_value instanceof Boolean) {
						if((Boolean)key_value) { //If dump_results is set to true	
							this.Client_JOBS = this.Client_JOBS | CLIENT_JOB.Dump_Results.getIdValue();
							JSONObject dump_results = (JSONObject)params.get(key);
							Object value;
							value = dump_results.get("tofile");
							if(value instanceof Boolean) 
								this.to_file = ((Boolean) value).booleanValue();
							else{
								LOGGER.log(Level.SEVERE, "Invalid tofile parameter value");
								return;
							}


							value = dump_results.get("toconsole");
							if(value instanceof Boolean) 
								this.to_console = ((Boolean) value).booleanValue();
							else{
								LOGGER.log(Level.SEVERE, "Invalid toconsole parameter value");
								return;
							}


							value = dump_results.get("filepath");
							if(value instanceof String) 
								this.output_filepath = value.toString();
							else{
								LOGGER.log(Level.SEVERE, "Invalid filepath parameter value");
								return;
							}

						}
						System.out.println("***********Dump Result Job");
						System.out.println(this.to_file);
						System.out.println(this.to_console);
						System.out.println(this.output_filepath);
					}
					break;
				default:
					break;
				}
			}
		}

		catch(Exception e) {
			System.out.println("Error Parsing Client Config");
			System.out.println(e.getMessage());
			System.exit(0);
		}
	}
}
