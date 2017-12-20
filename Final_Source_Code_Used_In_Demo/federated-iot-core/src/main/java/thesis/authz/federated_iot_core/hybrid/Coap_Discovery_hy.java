package thesis.authz.federated_iot_core.hybrid;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;


public class Coap_Discovery_hy extends CoapServer{
	private static final int COAP_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);
	private String rsid;
	
	private String tokenendpoint;
	private String asid;
	private String rsscopes;
	
	public Coap_Discovery_hy(String rsid, String asid, String rsscopes,  String tokenendpoint) {
		this.rsid = rsid;
		this.asid = asid;
		this.rsscopes = rsscopes;
		
		this.tokenendpoint = tokenendpoint;
		add(new Info());
		addEndpoints();
	}
	
	
	class Info extends CoapResource {

		public Info() {

			// set resource identifier
			super("Info");

			// set display name
			getAttributes().setTitle("Resource Server Public Info");
			getAttributes().addContentType(40);
			getAttributes().addAttribute("rsid", rsid);
			getAttributes().addAttribute("rsscopes", rsscopes);
			getAttributes().addAttribute("asid", asid);
			//getAttributes().addAttribute("asconnectendpoint", connectendpoint);
			getAttributes().addAttribute("astokenendpoint", tokenendpoint);
		}        
	}
	/***
	 * 
	 * Add individual endpoints listening on default CoAP port on all IPv4 addresses of all network interfaces.
	 */
	private void addEndpoints() {
//		InetAddress addr = null;
//		try {
//			addr = InetAddress.getByName("127.0.0.1");
//		} catch (UnknownHostException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		InetSocketAddress bindToAddress = new InetSocketAddress(addr, COAP_PORT);
//		addEndpoint(new CoapEndpoint(bindToAddress));
		for (InetAddress addr : EndpointManager.getEndpointManager().getNetworkInterfaces()) {
			// only binds to IPv4 addresses and localhost
			if (addr instanceof Inet4Address) {
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, COAP_PORT);
				addEndpoint(new CoapEndpoint(bindToAddress));
			}
		}
	}

}
