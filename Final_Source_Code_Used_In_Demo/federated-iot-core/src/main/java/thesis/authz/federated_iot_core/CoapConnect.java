//package thesis.authz.federated_iot_core;
//
//import java.security.Principal;
//import java.security.cert.CertPath;
//import java.util.logging.Level;
//import java.util.logging.Logger;
//
//import org.eclipse.californium.core.CoapResource;
//import org.eclipse.californium.core.coap.CoAP.ResponseCode;
//import org.eclipse.californium.core.coap.MediaTypeRegistry;
//import org.eclipse.californium.core.coap.Request;
//import org.eclipse.californium.core.server.resources.CoapExchange;
//import org.eclipse.californium.core.server.resources.Resource;
//import org.eclipse.californium.scandium.auth.X509CertPath;
//
//import com.upokecenter.cbor.CBORObject;
//
//import se.sics.ace.AceException;
//import se.sics.ace.Constants;
//import se.sics.ace.Message;
//import se.sics.ace.coap.CoapReq;
//import se.sics.ace.coap.CoapRes;
//
//public class CoapConnect extends CoapResource {
//
//
//	/**
//	 * The logger
//	 */
//	private static final Logger LOGGER 
//	= Logger.getLogger(CoapConnect.class.getName());
//
//	/**
//	 * The underlying authz-info library
//	 */
//	private Connect c;
//
//
//	public CoapConnect(String name, Connect c) {
//		super(name);		
//		this.c = c;
//	}
//
//	@Override
//	public void handlePOST(CoapExchange exchange) {
//		exchange.accept();
//		Request req = new Request(exchange.getRequestCode());
//		req.setPayload(exchange.getRequestPayload());
//		try {
//			CoapReq msg = CoapReq.getInstance(req);
//			//Process the request only if the handshake is done via X509Certificates.
//			//Reject if its based on RPK.
//			Principal p = exchange.advanced().getRequest().getSenderIdentity();
//			if(p instanceof X509CertPath) {
//				req.setSenderIdentity(exchange.advanced().getRequest().getSenderIdentity());
//				
//				//pp.getCertificates().get(0);
//			    //exchange.advanced().getRequest().
//				Message reply = this.c.processMessage(msg);
//				//Safe to cast, since CoapReq only ever renders a CoapRes
//				CoapRes response = (CoapRes)reply; 
//				exchange.respond(response.getCode(), response.getRawPayload(),
//						MediaTypeRegistry.APPLICATION_CBOR);
//			}    
//			else {
//				CBORObject map = CBORObject.NewMap();				
//				map.Add(Constants.ERROR, Constants.INVALID_REQUEST);			
//				LOGGER.log(Level.INFO, "Message processing aborted: "
//						+ " Exhange not done via X509CERT ");
//				CoapRes r = (CoapRes) msg.failReply(Message.FAIL_UNAUTHORIZED, map);
//				exchange.respond(r.getCode(),r.getRawPayload(),MediaTypeRegistry.APPLICATION_CBOR);
//			}
//		} catch (AceException e) {
//			LOGGER.severe("Error while handling incoming POST: " 
//					+ e.getMessage());
//			return;
//		}  
//	}
//
//}
