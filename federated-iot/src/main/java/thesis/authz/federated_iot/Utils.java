package thesis.authz.federated_iot;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import se.sics.ace.Constants;

public class Utils extends Constants{	

	public static final String client_params_job = "job";
	public static final String client_params_results = "results";


	public enum AS_MODE{
		as("as"),
		cas("cas"),
		ascas("ascas");

		private final String auth_mode;

		AS_MODE(String auth_mode){
			this.auth_mode = auth_mode;
		}
		public String getValue() { return auth_mode; }
	}

	public enum CLIENT_ROLES{
		Resource_Access(0x01),
		Resource_Share(0x02),
		resource_access("resource_access"),
		resource_share("resource_share");

		private final int role_id;
		private final String role_name;

		CLIENT_ROLES(int id){
			this.role_id = id;
			this.role_name = null;
		}
		CLIENT_ROLES(String name){
			this.role_name = name;
			this.role_id = -1;
		}
		public int getIdValue() { return this.role_id; }
		public String getNameValue() { return this.role_name; }

		public static int getIntValues(List<String> roles) {
			int val = 0;
			for(String role : roles) {
				switch(CLIENT_ROLES.valueOf(role)){
				case resource_access:
					val = val | CLIENT_ROLES.Resource_Access.getIdValue();
					break;
				case resource_share:
					val = val | CLIENT_ROLES.Resource_Share.getIdValue();
					break;
				default:
					return -1; 
				}
			}
			return val;
		}
		
		public static List<String> getStringValues(int roles) {

			List<String> values = new ArrayList<String>();
			//If Authorization_Code bit is set
			if((roles & CLIENT_ROLES.Resource_Access.getIdValue()) ==
					CLIENT_ROLES.Resource_Access.getIdValue()) {
				values.add(CLIENT_ROLES.resource_access.getNameValue());
			}
			//If Client_Credentials bit is set
			if((roles & CLIENT_ROLES.Resource_Share.getIdValue()) ==
					CLIENT_ROLES.Resource_Share.getIdValue()) {
				values.add(CLIENT_ROLES.resource_share.getNameValue());			
			}			
			if(values.isEmpty())
				return null;
			return values;
		}
	}

	public enum GRANTS{
		Authorization_Code(0x01),
		Client_Credentials(0x02),
		Refresh_Token(0x04),
		Password(0x08),
		authorization_code("authorization_code"),
		client_credentials("client_credentials"),
		refresh_token("refresh_token"),
		password("password");

		private final int grantype_id;
		private final String grantype_name;
		GRANTS(int id) { this.grantype_id = id; 
		this.grantype_name = null;}
		GRANTS(String method_val){
			this.grantype_name = method_val;
			this.grantype_id = -1;
		}
		public int getIdValue() { return grantype_id; }
		public String getNameValue() { return grantype_name; }

		public static int getIntValues(List<String> grant_types) {
			int val = 0;
			for(String grant : grant_types) {
				switch(GRANTS.valueOf(grant)){
				case authorization_code:
					val = val | GRANTS.Authorization_Code.getIdValue();
					break;
				case client_credentials:
					val = val | GRANTS.Client_Credentials.getIdValue();
					break;
				case refresh_token:
					val = val | GRANTS.Refresh_Token.getIdValue();
					break;
				case password:
					val = val | GRANTS.Password.getIdValue();
					break;
				default:
					return -1; // This means there is an unsupported grant type present. So just return -1
				}
			}
			return val;
		}

		public static List<String> getStringValues(int grant_types) {

			List<String> values = new ArrayList<String>();
			//If Authorization_Code bit is set
			if((grant_types & GRANTS.Authorization_Code.getIdValue()) ==
					GRANTS.Authorization_Code.getIdValue()) {
				values.add(GRANTS.authorization_code.getNameValue());
			}
			//If Client_Credentials bit is set
			if((grant_types & GRANTS.Client_Credentials.getIdValue()) ==
					GRANTS.Client_Credentials.getIdValue()) {
				values.add(GRANTS.client_credentials.getNameValue());			
			}
			//If Password bit is set
			if((grant_types & GRANTS.Password.getIdValue()) ==
					GRANTS.Password.getIdValue()) {
				values.add(GRANTS.password.getNameValue());			
			}
			//If Refresh_Token bit is set
			if((grant_types & GRANTS.Refresh_Token.getIdValue()) ==
					GRANTS.Refresh_Token.getIdValue()) {
				values.add(GRANTS.refresh_token.getNameValue());		
			}
			if(values.isEmpty())
				return null;
			return values;
		}
	}

	public enum CLIENT_AUTH_METHOD{
		Client_Secret_Post(0x01),
		Client_CERT(0x02), // just using dtls for client authentication
		client_secret_post("client_secret_post"),
		client_cert("client_cert");

		private final int authmethod_id;
		private final String authmethod_name;

		CLIENT_AUTH_METHOD(int id){
			this.authmethod_id = id;
			this.authmethod_name = null;
		}
		CLIENT_AUTH_METHOD(String name){
			this.authmethod_id = -1;
			this.authmethod_name = name;
		}

		public int getIdValue() { return this.authmethod_id; }
		public String getNameValue() { return this.authmethod_name; }


		public static int getIntValues(List<String> auth_methods) {

			int val = 0;
			for(String auth : auth_methods) {
				switch(CLIENT_AUTH_METHOD.valueOf(auth)){
				case client_secret_post:
					val = val | CLIENT_AUTH_METHOD.Client_Secret_Post.getIdValue();
					break;
				case client_cert:
					val = val | CLIENT_AUTH_METHOD.Client_CERT.getIdValue();
					break;
				default:
					return -1; // This means there is an unsupported authorization method. So just return -1
				}
			}
			return val;
		}

		public static List<String> getStringValues(int auth_methods) {

			List<String> values = new ArrayList<String>();
			//If Authorization_Code bit is set
			if((auth_methods & CLIENT_AUTH_METHOD.Client_Secret_Post.getIdValue()) ==
					CLIENT_AUTH_METHOD.Client_Secret_Post.getIdValue()) {
				values.add(CLIENT_AUTH_METHOD.client_secret_post.getNameValue());
			}
			//If Client_Credentials bit is set
			if((auth_methods & CLIENT_AUTH_METHOD.Client_CERT.getIdValue()) ==
					CLIENT_AUTH_METHOD.Client_CERT.getIdValue()) {
				values.add(CLIENT_AUTH_METHOD.client_cert.getNameValue());			
			}
			if(values.isEmpty())
				return null;
			return values;
		}

		public static CLIENT_AUTH_METHOD getIdEnum(int id) {
			if(id != -1) {
				for(CLIENT_AUTH_METHOD v : values()){
					if( v.getIdValue() == id){
						return v;
					}
				}
			}
			return null;

		}
		public static CLIENT_AUTH_METHOD getIdEnum(String name) {
			if(name != null) {
				for(CLIENT_AUTH_METHOD v : values()){
					if( v.getIdValue() != -1){
						//First Get the Id enum
						if(v.toString().toLowerCase().equals(name.toLowerCase())) {
							return v;
						}
					}
				}
			}
			return null;
		}
		
		public static CLIENT_AUTH_METHOD getStringEnum(int id) {
			if(id != -1) {
				for(CLIENT_AUTH_METHOD v : values()){
					if(v.getNameValue() != null) {
						if(v.toString().toLowerCase().equals(CLIENT_AUTH_METHOD.getIdEnum(id).toString().toLowerCase())) {
							return v;
						}
					}
				}
			}
			return null;

		}
		public static CLIENT_AUTH_METHOD getStringEnum(String name) {
			if(name != null) {
				for(CLIENT_AUTH_METHOD v : values()){
					if( v.getNameValue().equals(name)){
							return v;
						}
					}
				}
			
			return null;
		}
	}

	public enum SECURITY_PROFILE{
		CoAP_Dtls_PSK(0x01),
		CoAP_Dtls_RPK(0x02),
		CoAP_Dtls_CERT(0x04),
		OSCOAP(0x08),
		No_Security(0x10),
		coap_dtls_psk("coap_dtls_psk"),
		coap_dtls_rpk("coap_dtls_rpk"),
		coap_dtls_cert("coap_dtls_cert"),
		oscoap("oscoap"),
		no_security("no_security");

		private final int securityprofile_id;
		private final String securityprofile_name;

		SECURITY_PROFILE(int id){
			this.securityprofile_id = id;
			this.securityprofile_name = null;
		}
		SECURITY_PROFILE(String name){
			this.securityprofile_id = -1;
			this.securityprofile_name = name;
		}

		public static SECURITY_PROFILE getIdEnum(int id) {
			if(id != -1) {
				for(SECURITY_PROFILE v : values()){
					if( v.getIdValue() == id){
						return v;
					}
				}
			}
			return null;

		}
		public static SECURITY_PROFILE getIdEnum(String name) {
			if(name != null) {
				for(SECURITY_PROFILE v : values()){
					if( v.getIdValue() != -1){
						//First Get the Id enum
						if(v.toString().toLowerCase().equals(name.toLowerCase())) {
							return v;
						}
					}
				}
			}
			return null;
		}


		public static SECURITY_PROFILE getEnumById(int id){
			for(SECURITY_PROFILE v : values()){
				if( v.getIdValue() == id){
					return v;
				}
			}
			return null;
		}

		public static SECURITY_PROFILE getStringEnum(int id) {
			if(id != -1) {
				for(SECURITY_PROFILE v : values()){
					if(v.getNameValue() != null) {
						if(v.toString().toLowerCase().equals(SECURITY_PROFILE.getIdEnum(id).toString().toLowerCase())) {
							return v;
						}
					}
				}
			}
			return null;

		}
		public static SECURITY_PROFILE getStringEnum(String name) {
			if(name != null) {
				for(SECURITY_PROFILE v : values()){
					if( v.getNameValue().equals(name)){
							return v;
						}
					}
				}
			
			return null;
		}
		public short getIdValue() { return (short) this.securityprofile_id; }
		public String getNameValue() { return this.securityprofile_name; }

		public static int getIntValues(List<String> security_profiles) {
			int val = 0;
			for(String profile : security_profiles) {
				switch(SECURITY_PROFILE.valueOf(profile)){
				case coap_dtls_psk:
					val = val | SECURITY_PROFILE.CoAP_Dtls_PSK.getIdValue();
					break;
				case coap_dtls_rpk:
					val = val | SECURITY_PROFILE.CoAP_Dtls_RPK.getIdValue();
					break;
				case coap_dtls_cert:
					val = val | SECURITY_PROFILE.CoAP_Dtls_CERT.getIdValue();
					break;
				case oscoap:
					val = val | SECURITY_PROFILE.OSCOAP.getIdValue();
					break;
				default:
					return -1; // This means there is an unsupported security profile present. So just return -1
				}
			}
			return val;
		}

		public static String getStringValues(int security_profiles, String delimiter) {

			List<String> values = new LinkedList<>();
			//If Authorization_Code bit is set
			if((security_profiles & SECURITY_PROFILE.CoAP_Dtls_PSK.getIdValue()) ==
					SECURITY_PROFILE.CoAP_Dtls_PSK.getIdValue()) {
				values.add(SECURITY_PROFILE.coap_dtls_psk.getNameValue());
			}
			//If Client_Credentials bit is set
			if((security_profiles & SECURITY_PROFILE.CoAP_Dtls_RPK.getIdValue()) ==
					SECURITY_PROFILE.CoAP_Dtls_RPK.getIdValue()) {
				values.add(SECURITY_PROFILE.coap_dtls_rpk.getNameValue());			
			}
			//If Password bit is set
			if((security_profiles & SECURITY_PROFILE.CoAP_Dtls_CERT.getIdValue()) ==
					SECURITY_PROFILE.CoAP_Dtls_CERT.getIdValue()) {
				values.add(SECURITY_PROFILE.coap_dtls_cert.getNameValue());			
			}
			//If Refresh_Token bit is set
			if((security_profiles & SECURITY_PROFILE.OSCOAP.getIdValue()) ==
					SECURITY_PROFILE.OSCOAP.getIdValue()) {
				values.add(SECURITY_PROFILE.oscoap.getNameValue());		
			}
			if(values.isEmpty())
				return null;
			return String.join(delimiter, values);
		}
	}
	public enum CLIENT_JOB{
		Discover_AS(0x01),
		Fetch_AS_Config(0x02),
		Client_Registration(0x04),
		Dump_Results(0x08),
		discover_as("discover_as"),
		fetch_as_config("fetch_as_config"),
		client_registration("client_registration"),
		dump_results("dump_results");

		private final int method_id;
		private final String method_name;
		CLIENT_JOB(int id) { this.method_id = id; 
		this.method_name = null;}
		CLIENT_JOB(String method_val){
			this.method_name = method_val;
			this.method_id = -1;
		}
		public int getIdValue() { return method_id; }
		public String getNameValue() { return method_name; }
	}

	public enum SERVER_METADATA{
		Issuer(0x01),
		Config_Endpoint(0x02),
		Token_Endpoint(0x04),
		Query_Endpoint(0x08),
		Registration_Endpoint(0x11),
		Grant_Type_Supported(0x12),
		Token_Endpoint_Auth_Method(0x14),
		Introspection_Endpoint(0x18),
		Introspection_Endpoint_Auth_Method(0x21),
		Cose_Key(0x22),
		Client_Count(0x24),
		issuer("issuer"),
		config_endpoint("config_endpoint"),
		token_endpoint("token_endpoint"),
		query_endpoint("query_endpoint"),
		registration_endpoint("registration_endpoint"),
		grant_type_supported("grant_type_supported"),
		token_endpoint_auth_method("token_endpoint_auth_method"),
		introspection_endpoint("introspection_endpoint"),
		introspection_endpoint_auth_method("introspection_endpoint_auth_method"),
		cose_key("cose_key"),
		client_count("client_count");

		private final String config_parameter;
		private final int config_id;
		SERVER_METADATA(String config_param){
			this.config_parameter = config_param;
			this.config_id = -1;
		}
		SERVER_METADATA(int config_param){
			this.config_parameter = null;
			this.config_id = config_param;
		}
		public String getNameValue() { return config_parameter; }
		public short getIdValue() { return (short) config_id; }

		public static SERVER_METADATA getIdEnum(int id) {
			if(id != -1) {
				for(SERVER_METADATA v : values()){
					if( v.getIdValue() == id){
						return v;
					}
				}
			}
			return null;

		}
		public static SERVER_METADATA getIdEnum(String name) {
			if(name != null) {
				for(SERVER_METADATA v : values()){
					if( v.getIdValue() != -1){
						//First Get the Id enum
						if(v.toString().toLowerCase().equals(name.toLowerCase())) {
							return v;
						}
					}
				}
			}
			return null;
		}
		public static List<String> getStringValues(int metadata) {

			List<String> values = new ArrayList<String>();
			//If Issuer bit is set
			if((metadata & SERVER_METADATA.Issuer.getIdValue()) ==
					SERVER_METADATA.Issuer.getIdValue()) {
				values.add(SERVER_METADATA.issuer.getNameValue());
			}
			//If Config_Endpoint bit is set
			if((metadata & SERVER_METADATA.Config_Endpoint.getIdValue()) ==
					SERVER_METADATA.Config_Endpoint.getIdValue()) {
				values.add(SERVER_METADATA.config_endpoint.getNameValue());
			}
			//If Token_Endpoint bit is set
			if((metadata & SERVER_METADATA.Token_Endpoint.getIdValue()) ==
					SERVER_METADATA.Token_Endpoint.getIdValue()) {
				values.add(SERVER_METADATA.token_endpoint.getNameValue());
			}
			//If Query_Endpoint bit is set
			if((metadata & SERVER_METADATA.Query_Endpoint.getIdValue()) ==
					SERVER_METADATA.Query_Endpoint.getIdValue()) {
				values.add(SERVER_METADATA.query_endpoint.getNameValue());
			}
			//If Registration_Endpoint bit is set
			if((metadata & SERVER_METADATA.Registration_Endpoint.getIdValue()) ==
					SERVER_METADATA.Registration_Endpoint.getIdValue()) {
				values.add(SERVER_METADATA.registration_endpoint.getNameValue());
			}
			//If Grant_Type_Supported bit is set
			if((metadata & SERVER_METADATA.Grant_Type_Supported.getIdValue()) ==
					SERVER_METADATA.Grant_Type_Supported.getIdValue()) {
				values.add(SERVER_METADATA.grant_type_supported.getNameValue());
			}
			//If Token_Endpoint_Auth_Method bit is set
			if((metadata & SERVER_METADATA.Token_Endpoint_Auth_Method.getIdValue()) ==
					SERVER_METADATA.Token_Endpoint_Auth_Method.getIdValue()) {
				values.add(SERVER_METADATA.token_endpoint_auth_method.getNameValue());
			}
			//If Introspection_Endpoint bit is set
			if((metadata & SERVER_METADATA.Introspection_Endpoint.getIdValue()) ==
					SERVER_METADATA.Introspection_Endpoint.getIdValue()) {
				values.add(SERVER_METADATA.introspection_endpoint.getNameValue());
			}
			//If Introspection_Endpoint_Auth_Method bit is set
			if((metadata & SERVER_METADATA.Introspection_Endpoint_Auth_Method.getIdValue()) ==
					SERVER_METADATA.Introspection_Endpoint_Auth_Method.getIdValue()) {
				values.add(SERVER_METADATA.introspection_endpoint_auth_method.getNameValue());
			}
			//If Cose_Key bit is set
			if((metadata & SERVER_METADATA.Cose_Key.getIdValue()) ==
					SERVER_METADATA.Cose_Key.getIdValue()) {
				values.add(SERVER_METADATA.cose_key.getNameValue());
			}
			//If Client_Count bit is set
			if((metadata & SERVER_METADATA.Client_Count.getIdValue()) ==
					SERVER_METADATA.Client_Count.getIdValue()) {
				values.add(SERVER_METADATA.client_count.getNameValue());
			}
			if(values.isEmpty())
				return null;
			return values;
		}
	}

	public enum CLIENT_METADATA{
		Grant_Type(0x01),
		Client_Name(0x02),
		Token_Endpoint_Auth_Method(0x04),
		Client_Role(0x08),
		Scope(0x10),
		Client_Security_Profile(0x11),
		Privilege_Client_Secret(0x12),
		Client_Notification_Endpoint(0x14),
		Cose_Key(0x18),
		Contact(0x21),
		Client_Id(0x22),
		Client_Secret(0x24),
		grant_type("grant_type"),
		client_name("client_name"),
		token_endpoint_auth_method("token_endpoint_auth_method"),
		client_role("client_role"),
		scope("scope"),
		client_security_profile("client_security_profile"),
		privilege_client_secret("privilege_client_secret"),
		client_notification_endpoint("client_notification_endpoint"),
		cose_key("cose_key"),
		contact("contact"),
		client_id("client_id"),
		client_secret("client_secret");


		private final String parameter;
		private final int param_id;
		CLIENT_METADATA(String parameter){
			this.parameter = parameter;
			this.param_id = -1;
		}
		CLIENT_METADATA(int param_id){
			this.param_id = param_id;
			this.parameter = null;
		}
		public String getNameValue() { return parameter; }
		public short getIdValue() { return (short)param_id; }
		

		public static CLIENT_METADATA getIdEnum(int id) {
			if(id != -1) {
				for(CLIENT_METADATA v : values()){
					if( v.getIdValue() == id){
						return v;
					}
				}
			}
			return null;

		}
		public static CLIENT_METADATA getIdEnum(String name) {
			if(name != null) {
				for(CLIENT_METADATA v : values()){
					if( v.getIdValue() != -1){
						//First Get the Id enum
						if(v.toString().toLowerCase().equals(name.toLowerCase())) {
							return v;
						}
					}
				}
			}
			return null;
		}
	}

}
