package thesis.authz.federated_iot.as;


import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.Code;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.AceException;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.as.Token;
import thesis.authz.federated_iot.AS_Params;
import thesis.authz.federated_iot.Utils.GRANTS;
import thesis.authz.federated_iot.Utils.SERVER_METADATA;
import thesis.authz.federated_iot.Utils.CLIENT_AUTH_METHOD;


public class Config implements Endpoint, AutoCloseable{

	/**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(Token.class.getName());
	
    private AS_Params parameters;
    /***
     * Constructor
     * 
     */
    public Config(AS_Params parameters) {
    	/*
    	 * TODO add ASID as UUID
    	 */
    	this.parameters = parameters;
    }
    
	public Message processMessage(Message msg) {
		 LOGGER.log(Level.INFO, "Config Endpoint received message ");
		 if(msg.getMessageCode() != Code.GET.value) {
			 LOGGER.severe("Message processing aborted: ");
             return msg.failReply(Message.FAIL_METHOD_NOT_ALLOWED, null);
		 }
		
		 CBORObject param = CBORObject.NewMap();
		 // <short,cborstring>
		 param.Add(SERVER_METADATA.Issuer.getIdValue(), CBORObject.FromObject(this.parameters.issuer));
		 // <short,cborstring>
		 param.Add(SERVER_METADATA.Auth_Mode.getIdValue(), CBORObject.FromObject(this.parameters.authorization_mode));
		 // <short,cborstring>
		 param.Add(SERVER_METADATA.Token_Endpoint.getIdValue(), CBORObject.FromObject(this.parameters.token_endpoint_resource));
		 // <short,cborstring>
		 param.Add(SERVER_METADATA.Query_Endpoint.getIdValue(), CBORObject.FromObject(this.parameters.query_endpoint_resource));
		 // <short,cborstring>
		 param.Add(SERVER_METADATA.Registration_Endpoint.getIdValue(), CBORObject.FromObject(this.parameters.registration_endpoint_resource));
		 // <short,int>
		 int value = GRANTS.getIntValues(this.parameters.grant_type_supported);
		 param.Add(SERVER_METADATA.Grant_Type_Supported.getIdValue(), CBORObject.FromObject(value));
		 // <short,int>
		 value = CLIENT_AUTH_METHOD.getIntValues(this.parameters.token_endpoint_auth_method);
		 param.Add(SERVER_METADATA.Token_Endpoint_Auth_Method.getIdValue(), CBORObject.FromObject(value));
		 // <short,cborstring>
		 param.Add(SERVER_METADATA.Introspection_Endpoint.getIdValue(), CBORObject.FromObject(this.parameters.introspection_endpoint_resource));
		 // <short,int>
		 value = CLIENT_AUTH_METHOD.getIntValues(this.parameters.introspection_endpoint_auth_method);
		 param.Add(SERVER_METADATA.Introspection_Endpoint_Auth_Method.getIdValue(), CBORObject.FromObject(value));
		 // <short,cborstring>
		 param.Add(SERVER_METADATA.Cose_Key.getIdValue(),this.parameters.cose_key);
		 // <short,int>
		 param.Add(SERVER_METADATA.Client_Count.getIdValue(), CBORObject.FromObject(this.parameters.client_count));
		 
	 return msg.successReply(Message.CREATED, param);
	}

	public void close() throws AceException {
		// TODO Auto-generated method stub
		
	}
}
