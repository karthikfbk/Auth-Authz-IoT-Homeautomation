package thesis.authz.federated_iot.as;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;

import thesis.authz.federated_iot.Utils.AS_MODE;

public class Discovery_Server extends CoapServer{
private static final int COAP_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);
	
	private String auth_mode;
	private String anchor;
	 /***
	  * Discovery Class which host the resource to be discovered by public client.
	  * @param multicast TRUE to enable multicast Discovery
	  * @throws Exception
	  */
    public Discovery_Server(AS_MODE auth_mode, String config_resource, 
    		Boolean multicast, String secprofile){
        
    	this.auth_mode = auth_mode.getValue();
    	this.anchor = "/"+this.auth_mode+"/"+this.auth_mode+"config";
    	add(new AS_RootResource());
    	add(new AS_ExternalResource(config_resource,secprofile));
    	//add unicast endpoints so unicast discovery can be done by default
    	addEndpoints();
    	
    	//If multicast is endabled
    	if(multicast)
    		addMulticastEndpoint();
    		
    }
    
    /***
     * 
     * @throws Exception
     */
    private void addMulticastEndpoint() {
    	InetAddress addr = null;
		try {
			addr = InetAddress.getByName("239.255.0.10");
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	InetSocketAddress bindToAddress = new InetSocketAddress(addr, COAP_PORT);
    	CoapEndpoint multicast = new CoapEndpoint(bindToAddress);
    	addEndpoint(multicast);
    }
	
    /***
     * 
     * Add individual endpoints listening on default CoAP port on all IPv4 addresses of all network interfaces.
     */
    private void addEndpoints() {
    	for (InetAddress addr : EndpointManager.getEndpointManager().getNetworkInterfaces()) {
    		// only binds to IPv4 addresses and localhost
			if (addr instanceof Inet4Address || addr.isLoopbackAddress()) {
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, COAP_PORT);
				addEndpoint(new CoapEndpoint(bindToAddress));
			}
		}
    }
    /*
     * Definition of the ASCAS Root Resource
     */
    /***
     * 
     * @author 600011213
     *
     */
    class AS_RootResource extends CoapResource {
        
        public AS_RootResource() {
            
            // set resource identifier
            super(auth_mode);
            
            // set display name
            getAttributes().setTitle("Authorization Server Resource");
            getAttributes().addContentType(40);
            getAttributes().addResourceType("core." + auth_mode);
            getAttributes().addInterfaceDescription("authz-server");
            add(new ASCAS_ConfigResource());
            
        }        
    }
    
    /*
     * Definition of the ASCAS Config Resource
     */
    /***
     * 
     * @author 600011213
     *
     */
    class ASCAS_ConfigResource extends CoapResource {
        
        public ASCAS_ConfigResource() {
            
            // set resource identifier
            super(auth_mode + "config");
            
            // set display name
            getAttributes().setTitle("Authorization Server Metadata");
            getAttributes().addContentType(40);
            getAttributes().addResourceType("core." + auth_mode + "config");
            getAttributes().addInterfaceDescription("authz-server");
        }
        
        @Override
        public void handleGET(CoapExchange exchange) {
            
        	String payload = "Authorization Server Metadata Resource hosted as an external resource.\n"
        			+ "Do a GET on ./well-known/core?anchor="+anchor;
            // respond to the request
            exchange.respond(ResponseCode.VALID, payload);
        }
    }
    
    /*
     * 
     */
    /***
     * 
     * @author 600011213
     *
     */
    class AS_ExternalResource extends CoapResource {
        
        public AS_ExternalResource(String resource, String secprofile) {
            
            // set resource identifier
            super(resource);
            
            // set display name
            getAttributes().addAttribute("anchor", anchor);
            getAttributes().addAttribute("rel","describedBy");
            getAttributes().addAttribute("profile",secprofile);
        }
        
        @Override
        public void handleGET(CoapExchange exchange) {
            
        	String payload = "Authorization Server Metadata Resource hosted as an external resource.\n"
        			+ "Do a GET on ./well-known/core?anchor="+anchor;
            // respond to the request
            exchange.respond(ResponseCode.VALID, payload);
        }
        
    }
}
