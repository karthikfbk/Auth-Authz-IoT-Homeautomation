package thesis.authz.federated_iot;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONArray;
import org.json.JSONObject;

public class AS_Params {
	private static final Logger LOGGER 
	= Logger.getLogger(AS_Params.class.getName() ); 
	/*
	 * Startup Configuration
	 */

	public Boolean multicast_discovery;
	public String as_security_profile;
	/*
	 * AS Metadata
	 */
	public String issuer;
	public String token_endpoint_resource;
	public String config_endpoint_resource;
	public String query_endpoint_resource;
	public String registration_endpoint_resource;
	// its a bit field value representing summation of all grant types.
	public List<String> grant_type_supported; 		
	// its a bit field value representing summation of all auth methods.
	public List<String> token_endpoint_auth_method;		
	public String introspection_endpoint_resource;
	//its a bit field value representing summation of all auth methods.
	public List<String> introspection_endpoint_auth_method;
	public String cose_key;
	public int client_count;
	public String authorization_mode;
	/*
	 * DB Configurations
	 */
	public String dburl;
	public String dbuser;
	public String dbpwd;
	public String dbrootpwd;

	public AS_Params(){
		this.grant_type_supported = new ArrayList<String>();
		this.token_endpoint_auth_method = new ArrayList<String>();
		this.introspection_endpoint_auth_method = new ArrayList<String>();
	}

	//		/***
	//		 * GETTERS
	//		 * @return
	//		 */
	//		public AS_MODE get_AS_MODE() {
	//			return this.authorization_mode;
	//		}
	//		public SECURITY_PROFILE get_SECURITY_PROFILE() {
	//			return this.security_profile;
	//		}
	//		public String get_issuer() {
	//			return this.issuer;
	//		}
	//		public Boolean get_multicast_discovery() {
	//			return this.multicast_discovery;
	//		}
	//		public String get_token_endpoint_resource() {
	//			return this.token_endpoint_resource;
	//		}
	//		public String get_config_endpoint_resource() {
	//			return this.config_endpoint_resource;
	//		}
	//		public String get_query_endpoint_resource() {
	//			return this.query_endpoint_resource;
	//		}
	//		public String get_introspection_endpoint_resource() {
	//			return this.introspection_endpoint_resource;
	//		}
	//		public String get_registration_endpoint_resource() {
	//			return this.registration_endpoint_resource;
	//		}
	//		public int get_grant_type_supported() {
	//			return this.grant_type_supported;
	//		}
	//		public int get_token_endpoint_auth_method() {
	//			return this.token_endpoint_auth_method;
	//		}
	//		public int get_introspection_endpoint_auth_method() {
	//			return this.introspection_endpoint_auth_method;
	//		}
	//		public OneKey get_cose_key() {
	//			return this.cose_key;
	//		}
	//		public int get_client_count() {
	//			return this.client_count;
	//		}
	//		public String get_dburl() {
	//			return this.dburl;
	//		}
	//		public String get_dbuser() {
	//			return this.dbuser;
	//		}
	//		public String get_dbpwd() {
	//			return this.dbpwd;
	//		}
	//		
	//		/***
	//		 * SETTERS
	//		 * @return
	//		 */
	//		public void set_AS_MODE(AS_MODE authorization_mode) {
	//			this.authorization_mode = authorization_mode;
	//		}
	//		public void set_SECURITY_PROFILE(SECURITY_PROFILE securityprofile) {
	//			this.security_profile = securityprofile;
	//		}
	//		public void set_issuer(String issuer) {
	//			this.issuer = issuer;
	//		}
	//		public void set_multicast_discovery(Boolean multicast_discovery) {
	//			 this.multicast_discovery = multicast_discovery;
	//		}
	//		public void set_token_endpoint_resource(String token_endpoint_resource) {
	//			 this.token_endpoint_resource = token_endpoint_resource;
	//		}
	//		public void set_config_endpoint_resource(String config_endpoint_resource) {
	//			 this.config_endpoint_resource = config_endpoint_resource;
	//		}
	//		public void set_query_endpoint_resource(String query_endpoint_resource) {
	//			 this.query_endpoint_resource = query_endpoint_resource;
	//		}
	//		public void set_introspection_endpoint_resource(String introspection_endpoint_resource) {
	//			 this.introspection_endpoint_resource = introspection_endpoint_resource;
	//		}
	//		public void set_registration_endpoint_resource(String registration_endpoint_resource) {
	//			 this.registration_endpoint_resource = registration_endpoint_resource;
	//		}
	//		public void set_grant_type_supported(int grant_type_supported) {
	//			 this.grant_type_supported = grant_type_supported;
	//		}
	//		public void set_token_endpoint_auth_method(int token_endpoint_auth_method) {
	//			 this.token_endpoint_auth_method = token_endpoint_auth_method;
	//		}
	//		public void set_introspection_endpoint_auth_method(int introspection_endpoint_auth_method) {
	//			 this.introspection_endpoint_auth_method = introspection_endpoint_auth_method;
	//		}
	//		public void set_cose_key(OneKey cose_key) {
	//			 this.cose_key=cose_key;
	//		}
	//		public void set_client_count(int client_count) {
	//			 this.client_count=client_count;
	//		}
	//		public void set_dburl(String dburl) {
	//			this.dburl = dburl;
	//		}
	//		public void set_dbuser(String dbuser) {
	//			this.dbuser = dbuser;
	//		}
	//		public void set_dbpwd(String dbpwd) {
	//			this.dbpwd = dbpwd;
	//		}
	//		



	public void Fill(JSONObject params) {
		//Get startup configuration
		JSONObject startup = (JSONObject) params.get("startup");

		Object value;

		value = startup.get("multicast_discovery");
		if(value instanceof Boolean) 
			this.multicast_discovery = ((Boolean) value).booleanValue();
		else {
			LOGGER.log(Level.SEVERE, "Invalid multicast_discovery parameter value");
			return;
		}
		value = startup.get("as_security_profile");
		if(value instanceof String) 
			this.as_security_profile = value.toString();
		else {
			LOGGER.log(Level.SEVERE, "Invalid as_security_profile parameter value");
			return;
		}

		//Get AS Metadata
		JSONObject metadata = (JSONObject) params.get("metadata");

		value = metadata.get("authorization_mode");
		if(value instanceof String) 
			this.authorization_mode = value.toString();
		else {
			LOGGER.log(Level.SEVERE, "Invalid authorization_mode parameter value");
			return;
		}

		value = metadata.get("issuer");
		if(value instanceof String) 
			this.issuer = value.toString();
		else {
			LOGGER.log(Level.SEVERE, "Invalid issuer parameter value");
			return;
		}

		value = metadata.get("token_endpoint");
		if(value instanceof JSONObject) 
			this.token_endpoint_resource = Construct_Endpoint_URI((JSONObject) value);
		else {
			LOGGER.log(Level.SEVERE, "Invalid token_endpoint parameter value");
			return;
		}

		value = metadata.get("query_endpoint");
		if(value instanceof JSONObject) 
			this.query_endpoint_resource = Construct_Endpoint_URI((JSONObject) value);
		else {
			LOGGER.log(Level.SEVERE, "Invalid query_endpoint parameter value");
			return;
		}

		value = metadata.get("registration_endpoint");
		if(value instanceof JSONObject) 
			this.registration_endpoint_resource = Construct_Endpoint_URI((JSONObject) value);
		else {
			LOGGER.log(Level.SEVERE, "Invalid registration_endpoint parameter value");
			return;
		}


		value = metadata.get("grant_type_supported");
		if(value instanceof JSONArray) {
			JSONArray j = (JSONArray)value;
			for(int i=0; i<j.length(); i++) {
				this.grant_type_supported.add(j.getString(i));
			}
		}
		else{
			LOGGER.log(Level.SEVERE, "Invalid grant_type_supported parameter value");
			return;
		}

		value = metadata.get("token_endpoint_auth_method");
		if(value instanceof JSONArray) {
			JSONArray j = (JSONArray)value;
			for(int i=0; i<j.length(); i++) {
				this.token_endpoint_auth_method.add(j.getString(i));
			}
		}
		else{
			LOGGER.log(Level.SEVERE, "Invalid token_endpoint_auth_method parameter value");
			return;
		}

		value = metadata.get("introspection_endpoint");
		if(value instanceof JSONObject) 
			this.introspection_endpoint_resource = Construct_Endpoint_URI((JSONObject) value);
		else {
			LOGGER.log(Level.SEVERE, "Invalid introspection_endpoint parameter value");
			return;
		}

		value = metadata.get("config_endpoint");
		if(value instanceof JSONObject) 
			this.config_endpoint_resource = Construct_Endpoint_URI((JSONObject) value);
		else {
			LOGGER.log(Level.SEVERE, "Invalid config_endpoint parameter value");
			return;
		}

		value = metadata.get("introspection_endpoint_auth_method");
		if(value instanceof JSONArray) {
			JSONArray j = (JSONArray)value;
			for(int i=0; i<j.length(); i++) {
				this.introspection_endpoint_auth_method.add(j.getString(i));
			}
		}
		else{
			LOGGER.log(Level.SEVERE, "Invalid introspection_endpoint_auth_method parameter value");
			return;
		}

		value = metadata.get("cose_key");
		if(value instanceof String) 
			this.cose_key = value.toString();
		else {
			LOGGER.log(Level.SEVERE, "Invalid cose_key parameter value");
			return;
		}
		//			String cose = metadata.getString("cose_key");
		//
		//			try {
		//				this.set_cose_key(new OneKey(
		//						CBORObject.DecodeFromBytes(Base64.getDecoder().decode(cose))));
		//			} catch (CoseException e) {
		//				// TODO Auto-generated catch block
		//				e.printStackTrace();
		//			}
		value = metadata.get("client_count");
		if(value instanceof Integer) 
			this.client_count = ((Integer) value).intValue();
		else {
			LOGGER.log(Level.SEVERE, "Invalid client_count parameter value");
			return;
		}


		//Get AS Metadata
		JSONObject database = (JSONObject) params.get("database");

		value = database.get("db_endpoint");
		if(value instanceof JSONObject) 
			this.dburl = Construct_Endpoint_URI((JSONObject) value);
		else {
			LOGGER.log(Level.SEVERE, "Invalid db_endpoint parameter value");
			return;
		}

		value = database.get("root_pwd");
		if(value instanceof String) 
			this.dbrootpwd = value.toString();
		else {
			LOGGER.log(Level.SEVERE, "Invalid root_pwd parameter value");
			return;
		}

		value = database.get("user_name");
		if(value instanceof String) 
			this.dbuser = value.toString();
		else {
			LOGGER.log(Level.SEVERE, "Invalid user_name parameter value");
			return;
		}

		value = database.get("user_pwd");
		if(value instanceof String) 
			this.dbpwd = value.toString();
		else {
			LOGGER.log(Level.SEVERE, "Invalid user_pwd parameter value");
			return;
		}
		

		System.out.println("***********AS Config************");
		System.out.println(this.authorization_mode);
		System.out.println(this.multicast_discovery);
		System.out.println(this.as_security_profile);
		System.out.println(this.issuer);
		System.out.println(this.token_endpoint_resource);
		System.out.println(this.query_endpoint_resource);
		System.out.println(this.registration_endpoint_resource);
		System.out.println(this.grant_type_supported.toString());
		System.out.println(this.token_endpoint_auth_method);
		System.out.println(this.introspection_endpoint_resource);
		System.out.println(this.introspection_endpoint_auth_method);
		System.out.println(this.cose_key);
		System.out.println(this.client_count);
		System.out.println("***********DATABASE************");
		System.out.println(this.dburl);
		System.out.println(this.dbrootpwd);
		System.out.println(this.dbuser);
		System.out.println(this.dbpwd);
	}

	private String Construct_Endpoint_URI(JSONObject map) {
		String proto = null;
		String port = null;
		String ip = null;
		String uri_path = null;
		if(map == null) {
			LOGGER.log(Level.SEVERE, "Null JSONObject for Endpoint URI Construction");
			return null;
		}
		Object value = map.get("protocol");			

		if(value instanceof String) 
			proto = value.toString();
		else {
			LOGGER.log(Level.SEVERE, "Invalid protocol parameter value");
			return null;
		}

		value = map.get("port");
		if(value instanceof Integer) 
			port = value.toString();
		else {
			LOGGER.log(Level.SEVERE, "Invalid port parameter value");
			return null;
		}		

		if(!map.isNull("interface")) {
			value = map.get("interface");
			if(value instanceof String) 
				ip = get_ip(value.toString());
			else{
				LOGGER.log(Level.SEVERE, "Invalid interface parameter value");
				return null;
			}
		}
		
		if(!map.isNull("host")) {
			value = map.get("host");
			if(value instanceof String) 
				ip = value.toString();
			else{
				LOGGER.log(Level.SEVERE, "Invalid host parameter value");
				return null;
			}
		}

		if(!map.isNull("path")) {
			value = map.get("path");
			if(value instanceof String) 
				uri_path = value.toString();
			else {
				LOGGER.log(Level.SEVERE, "Invalid uri_path parameter value");
				return null;
			}
		}

		StringBuilder endpoint_uri = new StringBuilder();
		endpoint_uri.append(proto).append("://").append(ip).append(":").append(port);
		
		if(uri_path != null) {
			endpoint_uri.append(uri_path);
		}

		return endpoint_uri.toString();
	}


	private String get_ip(String interfaceName) {
		String ip = null;
		NetworkInterface networkInterface = null;
		try {
			networkInterface = NetworkInterface.getByName(interfaceName);
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		Enumeration<InetAddress> inetAddress = networkInterface.getInetAddresses();
		InetAddress currentAddress;
		while(inetAddress.hasMoreElements())
		{
			currentAddress = inetAddress.nextElement();
			if(currentAddress instanceof Inet4Address && !currentAddress.isLoopbackAddress())
			{
				ip = currentAddress.getHostAddress();
				break;
			}
		}

		return ip;
	}

}
