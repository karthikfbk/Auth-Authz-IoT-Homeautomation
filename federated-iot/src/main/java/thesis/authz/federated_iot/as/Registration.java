package thesis.authz.federated_iot.as;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.Code;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.CoseException;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.as.DBConnector;
import se.sics.ace.as.Token;
import thesis.authz.federated_iot.AS_Params;
import thesis.authz.federated_iot.Utils.CLIENT_METADATA;
import thesis.authz.federated_iot.Utils.GRANTS;
import thesis.authz.federated_iot.Utils.*;
public class Registration implements Endpoint, AutoCloseable{

	/**
	 * The logger
	 */
	private static final Logger LOGGER 
	= Logger.getLogger(Token.class.getName());

	/**
	 * The database connector for storing and retrieving stuff.
	 */
	private DBConnector db;

	private AS_Params parameters;
	/**
	 * Constructor
	 */
	public Registration(DBConnector db,AS_Params parameters) {
		/*
		 * TODO add ASID as UUID
		 */
		this.db = db;
		this.parameters = parameters;
	}


	@Override
	public Message processMessage(Message msg) {
		String client_ID = null;
		String client_secret = null;
		Set<String> profiles = new HashSet<>();
		Set<String> ra_scopes= new HashSet<>();
		Set<String> rs_scopes= new HashSet<>();
		Set<String> auds= new HashSet<>();;
		Set<String> keyTypes= new HashSet<>();
		Set<Integer> tokenTypes= new HashSet<>();;
		Set<COSEparams> cose= new HashSet<>();;
		long expiration;
		OneKey sharedKey;
		OneKey client_cose_key=null;
		String contact = null;
		LOGGER.log(Level.INFO, "Registration Endpoint received message ");
		if(msg.getMessageCode() != Code.POST.value) {
			LOGGER.severe("Message processing aborted: ");
			return msg.failReply(Message.FAIL_METHOD_NOT_ALLOWED, null);
		}
		Boolean privilege_client = false;
		CBORObject registration_response = CBORObject.NewMap();
		//CBORObject registration_response = CBORObject.NewMap();
		//Check if this is a privilege client or normal client.
		if(msg.getParameter(CLIENT_METADATA.Privilege_Client_Secret.getIdValue()) != null) {
			if(validate_privilege_client(msg.getParameter(CLIENT_METADATA.Privilege_Client_Secret.getIdValue()))) {
				privilege_client = true;
			}
			else {				
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, "Privilege client validation fails");

				LOGGER.log(Level.SEVERE, "Message processing aborted: "
						+ " privilege client validation failed ");
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
		}
		//Check for client_notification_endpoint parameter. This is only for privileged clients
		if(msg.getParameter(CLIENT_METADATA.Client_Notification_Endpoint.getIdValue()) != null) {
			if(privilege_client) {
				CBORObject notification_endpoint = msg.getParameter(CLIENT_METADATA.Client_Notification_Endpoint.getIdValue());
				if (!notification_endpoint.getType().equals(CBORType.TextString)) {
					LOGGER.log(Level.SEVERE, "Message processing aborted: "
							+ " invalid notification_endpoint parameter type");
					return msg.failReply(Message.FAIL_UNSUPPORTED_CONTENT_FORMAT, null);
				}
				registration_response.Add(CLIENT_METADATA.Client_Notification_Endpoint.getIdValue(),notification_endpoint);
			}
		}
		if(msg.getParameter(CLIENT_METADATA.Grant_Type.getIdValue()) == null) {
			LOGGER.log(Level.SEVERE, "Message processing aborted: "
					+ " grant_type parameter not present");
			return msg.failReply(Message.FAIL_BAD_REQUEST, null);
		}

		//Check the grant types the client has requested
		if(msg.getParameter(CLIENT_METADATA.Grant_Type.getIdValue()) != null) {
			CBORObject grant_types = msg.getParameter(CLIENT_METADATA.Grant_Type.getIdValue());
			if (!grant_types.getType().equals(CBORType.Number)) {
				LOGGER.log(Level.SEVERE, "Message processing aborted: "
						+ " invalid grant type parameter type");
				return msg.failReply(Message.FAIL_UNSUPPORTED_CONTENT_FORMAT, null);
			}
			int value = grant_types.AsInt32();
			List<String> values = GRANTS.getStringValues(value);
			for(String v : values) {
				if(!this.parameters.grant_type_supported.contains(v)) {
					//if the requested value is not supported by the server.
					//remove the value
					values.remove(v);
				}
			}
			if(values.size() > 0) {
				registration_response.Add(CLIENT_METADATA.Grant_Type.getIdValue(),CBORObject.FromObject(GRANTS.getIntValues(values)));
			}
			else {
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.UNSUPPORTED_GRANT_TYPE);

				LOGGER.log(Level.SEVERE, "Message processing aborted: "
						+ " invalid grant type requested by client ");
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
		}

		//Check Client name
		if(msg.getParameter(CLIENT_METADATA.Client_Name.getIdValue()) == null) {
			LOGGER.log(Level.SEVERE, "Message processing aborted: "
					+ " client_name parameter not present");
			return msg.failReply(Message.FAIL_BAD_REQUEST, null);
		}

		if(msg.getParameter(CLIENT_METADATA.Client_Name.getIdValue()) != null) {
			CBORObject client_name = msg.getParameter(CLIENT_METADATA.Client_Name.getIdValue());
			if(!client_name.getType().equals(CBORType.TextString)) {
				LOGGER.log(Level.SEVERE, "Message processing aborted: "
						+ " invalid client name parameter type");
				return msg.failReply(Message.FAIL_UNSUPPORTED_CONTENT_FORMAT, null);
			}
			registration_response.Add(CLIENT_METADATA.Client_Name.getIdValue(),client_name);

			//Create a new Client Id for this Client
			String salt= Long.toHexString(Double.doubleToLongBits(Math.random()));
			client_ID = client_name.AsString().concat(salt);
			client_secret = Long.toHexString(Double.doubleToLongBits(Math.random()));
			registration_response.Add(CLIENT_METADATA.Client_Id.getIdValue(), CBORObject.FromObject(client_ID));
			registration_response.Add(CLIENT_METADATA.Client_Secret.getIdValue(), CBORObject.FromObject(client_secret));
		}

		//Check token endpoint auth methods that client requested
		if(msg.getParameter(CLIENT_METADATA.Token_Endpoint_Auth_Method.getIdValue()) == null) {
			LOGGER.log(Level.SEVERE, "Message processing aborted: "
					+ " token_endpoint_auth_method parameter not present");
			return msg.failReply(Message.FAIL_BAD_REQUEST, null);
		}

		if(msg.getParameter(CLIENT_METADATA.Token_Endpoint_Auth_Method.getIdValue()) != null) {
			CBORObject auth_method = msg.getParameter(CLIENT_METADATA.Token_Endpoint_Auth_Method.getIdValue());
			if (!auth_method.getType().equals(CBORType.Number)) {
				LOGGER.log(Level.SEVERE, "Message processing aborted: "
						+ " invalid token_endpoint_auth_method parameter type");
				return msg.failReply(Message.FAIL_UNSUPPORTED_CONTENT_FORMAT, null);
			}

			int value = auth_method.AsInt32();
			String auth = CLIENT_AUTH_METHOD.getStringEnum(value).getNameValue();
			if(this.parameters.token_endpoint_auth_method.contains(auth)) {



				registration_response.Add(CLIENT_METADATA.Token_Endpoint_Auth_Method.getIdValue(),CBORObject.FromObject(value));
			}
			else {
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, "Unsupported token endpoint auth method");

				LOGGER.log(Level.SEVERE, "Message processing aborted: "
						+ " invalid token endpoint auth method requested by client ");
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
		}


		/**
		 * Important note:
		 * A RS also needs to register at CAS for getting tokens.
		 * A C also needs to register at CAS for introspection.
		 * Similarly,
		 * A RS also needs to register at AS for introspection.
		 * A C also needs to register at AS for getting tokens.
		 * So the bottom line is irrespective of the authorization mode, check for the client role parameter.
		 * If its resource_access, then it means its a client device then do a db.addClient
		 * If its resource_share, then it means its a Resource server then do  a db.addRS
		 * If its both, the do both db.addClient and db.addRS
		 */
		//Check client role
		int client_roles = 0;
		if(msg.getParameter(CLIENT_METADATA.Client_Role.getIdValue()) != null) {
			CBORObject roles = msg.getParameter(CLIENT_METADATA.Client_Role.getIdValue());
			if(!roles.getType().equals(CBORType.Number)) {
				LOGGER.log(Level.SEVERE, "Message processing aborted: "
						+ " invalid client role parameter type");
				return msg.failReply(Message.FAIL_UNSUPPORTED_CONTENT_FORMAT, null);
			}
			// Check if the requested roles with the authorization mode of AS
			List<String> values = CLIENT_ROLES.getStringValues(roles.AsInt32());
			for(String role : values) {
				switch(CLIENT_ROLES.valueOf(role)) {
				case resource_access:
					client_roles = client_roles | CLIENT_ROLES.Resource_Access.getIdValue();
					break;
				case resource_share:
					client_roles = client_roles | CLIENT_ROLES.Resource_Share.getIdValue();
					break;
				default:
					//If client has requested any other role than this then remove it from list
					values.remove(role);
					break;
				}
			}
			if(client_roles != 0) {
				registration_response.Add(CLIENT_METADATA.Client_Role.getIdValue(),CBORObject.FromObject(CLIENT_ROLES.getIntValues(values)));
			}
			else {
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, "unsupported client role");

				LOGGER.log(Level.SEVERE, "Message processing aborted: "
						+ " invalid client role requested by client ");
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
		}

		/**
		 * Important Note
		 * if the client role is resource_access, then all the scope values MUST start with 'ra'
		 * if the client role is resource_share, then all the scope values MUST start with 'rs'
		 */
		//Check for scopes requested by clients
		if(msg.getParameter(CLIENT_METADATA.Scope.getIdValue()) != null) {
			CBORObject scopes = msg.getParameter(CLIENT_METADATA.Scope.getIdValue());
			if(!scopes.getType().equals(CBORType.Array)) {
				LOGGER.log(Level.SEVERE, "Message processing aborted: "
						+ " invalid scope parameter type");
				return msg.failReply(Message.FAIL_UNSUPPORTED_CONTENT_FORMAT, null);
			}
			CBORObject ra_scope = CBORObject.NewArray();
			CBORObject rs_scope = CBORObject.NewArray();
			CBORObject final_scopes = CBORObject.NewArray();
			for(CBORObject scope : scopes.getValues()) {
				if(scope.AsString().startsWith("ra")) {
					ra_scope.Add(scope.AsString());
					ra_scopes.add(scope.AsString());
				}
				if(scope.AsString().startsWith("rs")) {
					rs_scope.Add(scope.AsString());
					rs_scopes.add(scope.AsString());
				}
			}
			//If the client has Resource Access role
			if((client_roles & CLIENT_ROLES.Resource_Access.getIdValue()) == 
					CLIENT_ROLES.Resource_Access.getIdValue()) {
				for(CBORObject s : ra_scope.getValues()) {
					final_scopes.Add(s);
				}
			}
			//If the client has Resource Share role
			if((client_roles & CLIENT_ROLES.Resource_Share.getIdValue()) == 
					CLIENT_ROLES.Resource_Share.getIdValue()) {
				for(CBORObject s : rs_scope.getValues()) {
					final_scopes.Add(s);
				}
			}
			if(final_scopes.size() > 0 ) {
				registration_response.Add(CLIENT_METADATA.Scope.getIdValue(), final_scopes);
			}else {
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, "unsupported client scope");

				LOGGER.log(Level.SEVERE, "Message processing aborted: "
						+ " invalid client scopes requested by client ");
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}			
		}



		//Check client_security_profile
		if(msg.getParameter(CLIENT_METADATA.Client_Security_Profile.getIdValue()) != null) {
			CBORObject security_profile = msg.getParameter(CLIENT_METADATA.Client_Security_Profile.getIdValue());
			if(!security_profile.getType().equals(CBORType.Number)) {
				LOGGER.log(Level.SEVERE, "Message processing aborted: "
						+ " invalid client security profile parameter type");
				return msg.failReply(Message.FAIL_UNSUPPORTED_CONTENT_FORMAT, null);
			}
			//Check if the secruity profile requested by the client is supported in the framework
			if(SECURITY_PROFILE.getIdEnum(security_profile.AsInt32()) != null) {
				registration_response.Add(CLIENT_METADATA.Client_Security_Profile.getIdValue(), CBORObject.FromObject(security_profile.AsInt32()));
				profiles.add(SECURITY_PROFILE.getStringEnum(security_profile.AsInt32()).getNameValue());
			}
		}
		//Check cose_key
		if(msg.getParameter(CLIENT_METADATA.Cose_Key.getIdValue()) != null) {
			CBORObject cose_key = msg.getParameter(CLIENT_METADATA.Cose_Key.getIdValue());
			if(!cose_key.getType().equals(CBORType.TextString)) {
				LOGGER.log(Level.SEVERE, "Message processing aborted: "
						+ " invalid cose key parameter type");
				return msg.failReply(Message.FAIL_UNSUPPORTED_CONTENT_FORMAT, null);
			}


			//					//The cose_key is now the public key of the client.
			//					//Later it might contain the symmetric key and also the coseparams
			//					try {
			//						client_cose_key = new OneKey(cose_key);
			//					} catch (CoseException e) {
			//						// TODO Auto-generated catch block
			//						e.printStackTrace();
			//						LOGGER.log(Level.SEVERE, "Message processing aborted: "
			//								+ " cannot assign cose_key parameter requested by client");
			//						return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			//					}
			registration_response.Add(CLIENT_METADATA.Cose_Key.getIdValue(),cose_key);
		}

		//Check contact parameter
		if(msg.getParameter(CLIENT_METADATA.Contact.getIdValue()) != null) {
			CBORObject Contact_param = msg.getParameter(CLIENT_METADATA.Contact.getIdValue());
			if(!Contact_param.getType().equals(CBORType.TextString)) {
				LOGGER.log(Level.SEVERE, "Message processing aborted: "
						+ " invalid Contact parameter type");
				return msg.failReply(Message.FAIL_UNSUPPORTED_CONTENT_FORMAT, null);
			}

			registration_response.Add(CLIENT_METADATA.Contact.getIdValue(),Contact_param);
		}
		//First add to the database, send success if database addition is successfull.
		try {

			//db_registration(client_roles, client_ID, profiles, ra_scopes, rs_scopes, client_cose_key);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			LOGGER.severe("Message processing aborted: Failed to do databased operation "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		return msg.successReply(Message.CREATED, registration_response);
	}


	private void db_registration(int client_roles, String client_ID, Set<String> profiles, 
			Set<String> ra_scopes, Set<String> rs_scopes, OneKey client_cose_key) throws Exception {

		//If the client has Resource Access role
		if((client_roles & CLIENT_ROLES.Resource_Access.getIdValue()) == 
				CLIENT_ROLES.Resource_Access.getIdValue()) {
			//the default scope for the client is null. Get it from the configurations maybe later
			this.db.addClient(client_ID, profiles, null, null, null, null, client_cose_key,false);
		}
		//If the client has Resource Share role
		if((client_roles & CLIENT_ROLES.Resource_Share.getIdValue()) == 
				CLIENT_ROLES.Resource_Share.getIdValue()) {
			this.db.addRS(client_ID, profiles, rs_scopes, null, null, null, null, 1L , null, client_cose_key);
		}

	}
	private boolean validate_privilege_client(CBORObject parameter) {
		// TODO Auto-generated method stub
		return false;
	}


	@Override
	public void close() throws AceException {
		// TODO Auto-generated method stub

	}


}
