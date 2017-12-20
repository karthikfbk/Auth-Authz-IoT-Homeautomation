package thesis.authz.federated_iot.endpoint;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;

import se.sics.ace.AceException;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.coap.CoapRes;


public class FederatedIoTEndpoint extends CoapResource implements AutoCloseable {
	/**
     * The logger
     */
    private static final Logger LOGGER = Logger.getLogger(FederatedIoTEndpoint.class.getName() );
    
    /**
     * The token library
     */
    private Endpoint e;
    
    /**
     * Constructor.
     * 
     * @param name  the resource name
     * @param e  the endpoint library instance
     */
    public FederatedIoTEndpoint(String name, Endpoint e) {
        super(name);
        this.e = e;        
    }
    
    /**
     * Handles the POST request in the given CoAPExchange.
     *
     * @param exchange the CoapExchange for the simple API
     */
    @Override
    public void handlePOST(CoapExchange exchange) {
        CoapReq req = null;
        try {
            req = CoapReq.getInstance(exchange.advanced().getRequest());
        } catch (AceException e) {
            LOGGER.severe(e.getMessage());
            exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR);
        }
        LOGGER.log(Level.FINEST, "Received request: " 
                + ((req==null)?"null" : req.toString()));
        Message m = this.e.processMessage(req);
        
        if (m instanceof CoapRes) {
            CoapRes res = (CoapRes)m;
            LOGGER.log(Level.FINEST, "Produced response: " + res.toString());
            //XXX: Should the profile set the content format here?
            exchange.respond(res.getCode(), res.getRawPayload(), 
                    MediaTypeRegistry.APPLICATION_CBOR);
            return;
        }
        LOGGER.severe(this.e.getClass().getName() 
                + " library produced wrong response type");
        exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles the GET request in the given CoAPExchange.
     *
     * @param exchange the CoapExchange for the simple API
     */
    @Override
    public void handleGET(CoapExchange exchange) {
    	LOGGER.info("Received Get request");
        CoapReq req = null;
        Request original_req = null;
        try {
        	//For a GET, the payload could be of length 0.
        	//So explicitly set the payload to null to avoid CBOR exception
        	original_req = exchange.advanced().getRequest();        	
        	if(original_req.getPayload().length == 0) {
        		String val = null;
        		original_req.setPayload(val);
        		req = CoapReq.getInstance(original_req);
        	}
        	else
        		req = CoapReq.getInstance(original_req);           
        } catch (AceException e) {
            LOGGER.severe(e.getMessage());
            exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR);
        }
        LOGGER.log(Level.FINEST, "Received request: " 
                + ((req==null)?"null" : req.toString()));
        Message m = this.e.processMessage(req);
        
        if (m instanceof CoapRes) {
            CoapRes res = (CoapRes)m;
            LOGGER.log(Level.FINEST, "Produced response: " + res.toString());
            //XXX: Should the profile set the content format here?
            exchange.respond(res.getCode(), res.getRawPayload(), 
                    MediaTypeRegistry.APPLICATION_CBOR);
            return;
        }
        LOGGER.severe(this.e.getClass().getName() 
                + " library produced wrong response type");
        exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR);
    }

	public void close() throws Exception {
		// TODO Auto-generated method stub
		
	}
}
