package thesis.authz.federated_iot_core;

import java.security.Principal;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.server.resources.CoapExchange;

import se.sics.ace.Constants;
import com.upokecenter.cbor.CBORObject;

public class CoapRSInfo extends CoapResource {

	/**
	 * The logger
	 */
	private static final Logger LOGGER 
	= Logger.getLogger(CoapRSInfo.class.getName());

	private String rs_id;
	private String as_id;
	private String scopes;
	
	public CoapRSInfo(String rs_id, String as_id, String scopes) {
		super("info");
		this.rs_id = rs_id;
		this.as_id = as_id;
		this.scopes = scopes;
		// TODO Auto-generated constructor stub
	}
	
	@Override
	public void handleGET(CoapExchange exchange) {
		Principal p = exchange.advanced().getRequest().getSenderIdentity();
		if(p != null) {
			LOGGER.log(Level.INFO, " Printing sender identity for rsinfo " + p.getName());
		}
		else
			LOGGER.log(Level.INFO, " sender identity is null ");
		CBORObject rsinfo = CBORObject.NewMap();
		
		rsinfo.Add(Constants_ma.AS_ID, CBORObject.FromObject(as_id));
		rsinfo.Add(Constants_ma.RS_ID, CBORObject.FromObject(rs_id));
		rsinfo.Add(Constants.SCOPE, CBORObject.FromObject(scopes));
		
        exchange.respond(ResponseCode.CONTENT, rsinfo.EncodeToBytes(),
                MediaTypeRegistry.APPLICATION_CBOR);
	}
}
