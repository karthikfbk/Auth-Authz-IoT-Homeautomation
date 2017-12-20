package thesis.authz.federated_iot_core;



import se.sics.ace.AceException;
import se.sics.ace.Message;

/**
 * An interface for OAuth 2.0 endpoints.
 * 
 * @author Ludwig Seitz
 *
 */
public interface ProvisionEndpoint {

	/**
	 * @param msg  the incoming message to process
     *
	 * @return  the Reply message
	 */
	public Message processMessage(Message msg, CoapProvisionInfo server);
	
	/**
	 * Close any resources held by this endpoint before
	 * shutting down.
	 * 
	 * @throws AceException 
	 */
	public void close() throws AceException;

}
