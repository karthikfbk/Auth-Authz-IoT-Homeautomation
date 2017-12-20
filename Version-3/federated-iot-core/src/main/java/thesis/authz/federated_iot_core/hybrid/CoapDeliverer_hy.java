package thesis.authz.federated_iot_core.hybrid;

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.Resource;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.KeyKeys;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.examples.KissTime;
import se.sics.ace.rs.AsInfo;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.IntrospectionHandler;
import se.sics.ace.rs.TokenRepository;

public class CoapDeliverer_hy implements MessageDeliverer, Closeable {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CoapDeliverer_hy.class.getName());
    
    /**
     * The token repository
     */
    private TokenRepository tr;
    
    /**
     * The introspection handler
     */
    private IntrospectionHandler i;
    
    /**
     * The AS information message sent back to unauthorized requesters
     */
    private AsInfo asInfo;
  
    /**
     * The ServerMessageDeliverer that processes the request
     * after access control has been done
     */
    private ServerMessageDeliverer d;
    

    /**
     * Constructor. 
     * @param root  the root of the resources that this deliverer controls
     * @param tr  the token repository.
     * @param i  the introspection handler or null if there isn't any.
     * @param asInfo  the AS information to send for client authz errors.
     */
    public CoapDeliverer_hy(Resource root, TokenRepository tr, 
            IntrospectionHandler i, AsInfo asInfo) {
        this.d = new ServerMessageDeliverer(root);
        this.tr = tr;
        this.asInfo = asInfo;
    }
    
    @Override
    public void deliverRequest(final Exchange ex) {
        Request request = ex.getCurrentRequest();
        
        Response r = null;
        //authz-info is not under access control
        try {
            URI uri = new URI(request.getURI());
            //Need to check with and without trailing / in case there are query options
            if (uri.getPath().endsWith("/authz-info") || uri.getPath().endsWith("/authz-info/") ) { 
                this.d.deliverRequest(ex);
                return;
            }
        } catch (URISyntaxException e) {
            LOGGER.warning("Request-uri " + request.getURI()
                    + " is invalid: " + e.getMessage());
            r = new Response(ResponseCode.BAD_REQUEST);
            ex.sendResponse(r);
            return;
        }      
       
        if (request.getSenderIdentity() == null) {
            LOGGER.warning("Unauthenticated client tried to get access");
            r = new Response(ResponseCode.UNAUTHORIZED);
            r.setPayload(this.asInfo.getCBOR().EncodeToBytes());
            ex.sendResponse(r);
            return;
        }
        String subject = request.getSenderIdentity().getName();

        String kid = this.tr.getKid(subject);
     
        if (kid == null) {//Check if this was the Base64 encoded kid map
            try {
                CBORObject cbor = CBORObject.DecodeFromBytes(
                        Base64.getDecoder().decode(subject));
                if (cbor.getType().equals(CBORType.Map)) {
                   CBORObject ckid = cbor.get(KeyKeys.KeyId.AsCBOR());
                   if (ckid != null && ckid.getType().equals(
                           CBORType.ByteString)) {
                      kid = Base64.getEncoder().encodeToString(
                              ckid.GetByteString());
                   } else { //No kid in that CBOR map or it isn't a bstr
                       failUnauthz(ex);
                       return;
                   }
                } else {//Some weird CBOR that is not a map here
                   failUnauthz(ex);
                   return;
                }                
            } catch (CBORException e) {//Really no kid found for that subject
                LOGGER.finest("Error while trying to parse some "
                        + "subject identity to CBOR: " + e.getMessage());
               failUnauthz(ex);
               return;
            } catch (IllegalArgumentException e) {//Text was not Base64 encoded
                LOGGER.finest("Error: " + e.getMessage() 
                + " while trying to Base64 decode this: " + subject);
                failUnauthz(ex);
                return;
            }
           
        }
               
        String resource = request.getOptions().getUriPathString();
        String action = request.getCode().toString();  
      
        try {
            int res = this.tr.canAccess(kid, subject, resource, action, 
                    new KissTime(), this.i);
            switch (res) {
            case TokenRepository.OK :
                this.d.deliverRequest(ex);
                return;
            case TokenRepository.UNAUTHZ :
               failUnauthz(ex);
               return;
            case TokenRepository.FORBID :
                r = new Response(ResponseCode.FORBIDDEN);
                r.setPayload(this.asInfo.getCBOR().EncodeToBytes());
                ex.sendResponse(r);
                return;
            case TokenRepository.METHODNA :
                r = new Response(ResponseCode.METHOD_NOT_ALLOWED);
                r.setPayload(this.asInfo.getCBOR().EncodeToBytes());
                ex.sendResponse(r);
                return;
            default :
                LOGGER.severe("Error during scope evaluation,"
                        + " unknown result: " + res);
               ex.sendResponse(new Response(
                       ResponseCode.INTERNAL_SERVER_ERROR));
               return;
            }
        } catch (AceException e) {
            LOGGER.severe("Error in DTLSProfileInterceptor.receiveRequest(): "
                    + e.getMessage());    
        } catch (IntrospectionException e) {
            LOGGER.info("Introspection error, "
                    + "message processing aborted: " + e.getMessage());
           if (e.getMessage().isEmpty()) {
               ex.sendResponse(new Response(
                       ResponseCode.INTERNAL_SERVER_ERROR));
           }
           CBORObject map = CBORObject.NewMap();
           map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
           map.Add(Constants.ERROR_DESCRIPTION, e.getMessage());
           r = new Response(ResponseCode.BAD_REQUEST);
           r.setPayload(map.EncodeToBytes());
           ex.sendResponse(r);
        }
    }
    
    /**
     * Fail a request with 4.01 Unauthorized.
     * 
     * @param ex  the exchange
     */
    private void failUnauthz(final Exchange ex) {
        Response r = new Response(ResponseCode.UNAUTHORIZED);
        r.setPayload(this.asInfo.getCBOR().EncodeToBytes());
        ex.sendResponse(r);
    }

    @Override
    public void deliverResponse(Exchange exchange, Response response) {
        this.d.deliverResponse(exchange, response);        
    }

    @Override
    public void close() throws IOException {
        try {
            this.tr.close();
        } catch (AceException e) {
            LOGGER.severe("Error while trying to close token repository: " 
                    + e.getMessage());
        }        
    }
}
