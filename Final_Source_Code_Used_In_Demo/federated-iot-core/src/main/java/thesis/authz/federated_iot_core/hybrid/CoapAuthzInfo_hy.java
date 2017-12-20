package thesis.authz.federated_iot_core.hybrid;

import java.util.logging.Logger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.server.resources.CoapExchange;

import se.sics.ace.AceException;
import se.sics.ace.Message;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.coap.CoapRes;
import se.sics.ace.coap.rs.CoapAuthzInfo;
import se.sics.ace.rs.AuthzInfo;

public class CoapAuthzInfo_hy extends CoapResource {

    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CoapAuthzInfo_hy.class.getName());
    
    /**
     * The underlying authz-info library
     */
    private AuthzInfo ai;
    
   /**
    * Constructor.
    * 
    * @param ai  the internal authorization information handler 
    */ 
    public CoapAuthzInfo_hy(AuthzInfo ai) {
        super("authz-info");
        this.ai = ai;
    }
    
    @Override
    public void handlePOST(CoapExchange exchange) {
        exchange.accept();
        Request req = new Request(exchange.getRequestCode());
        req.setPayload(exchange.getRequestPayload());
        try {
            CoapReq msg = CoapReq.getInstance(req);
            Message reply = this.ai.processMessage(msg);
            //Safe to cast, since CoapReq only ever renders a CoapRes
            CoapRes response = (CoapRes)reply; 
            exchange.respond(response.getCode(), response.getRawPayload(),
                    MediaTypeRegistry.APPLICATION_CBOR);
        } catch (AceException e) {
            LOGGER.severe("Error while handling incoming POST: " 
                    + e.getMessage());
            return;
        }  
    }
    
    public void handleGET(CoapExchange exchange) {
    	
    }
}

