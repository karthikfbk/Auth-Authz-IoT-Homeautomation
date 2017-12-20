package thesis.authz.federated_iot_core.hybrid;

import java.security.Principal;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.scandium.auth.RawPublicKeyIdentity;
import org.eclipse.californium.scandium.auth.X509CertPath;

import se.sics.ace.AceException;
import se.sics.ace.Message;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.coap.CoapRes;
import thesis.authz.federated_iot_core.AuthzInfo_ma;
import thesis.authz.federated_iot_core.CoapAuthzInfo_ma;

public class CoapFetchInfo_hy extends CoapResource {

    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CoapFetchInfo_hy.class.getName());
    
    /**
     * The underlying authz-info library
     */
    private FetchInfo_hy fi;
    
   /**
    * Constructor.
    * 
    * @param ai  the internal authorization information handler 
    */ 
    public CoapFetchInfo_hy(FetchInfo_hy fi) {
        super("fetch-info");
        this.fi = fi;
    }
    
    @Override
    public void handlePOST(CoapExchange exchange) {
        exchange.accept();
        Request req = new Request(exchange.getRequestCode());
        req.setPayload(exchange.getRequestPayload());
        
        //Now if its an DTLS connection with CERTFICATES, you can also set the sender identity,
        //Because the sender is already authenticated based on CERTS
        //But for RPK an out of band establishment is needed.
        Principal p = exchange.advanced().getRequest().getSenderIdentity();
        if(p instanceof RawPublicKeyIdentity) {
        	 req.setSenderIdentity(exchange.advanced().getRequest().getSenderIdentity());
        }       
        try {
            CoapReq msg = CoapReq.getInstance(req);
            Message reply = this.fi.processMessage(msg);
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
}


