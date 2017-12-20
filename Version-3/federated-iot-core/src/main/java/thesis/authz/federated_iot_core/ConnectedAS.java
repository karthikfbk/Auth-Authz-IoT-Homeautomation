package thesis.authz.federated_iot_core;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import COSE.OneKey;

import java.security.cert.Certificate;



public class ConnectedAS implements AutoCloseable{

	
	 /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(ConnectedAS.class.getName());
    
    
    private Map<String, Map<Short,Object>> Partners;
    
    
    public ConnectedAS() {
    	Partners = new HashMap();
    }
    
    public void addPartner(String name, Map<Short,Object> map) {
    	//Put replaces the old value if already present
    	this.Partners.put(name, map);
    }
    
    
    public Map<String, Map<Short, Object>> getPartners() {
    	return this.Partners;
    }
    
    public OneKey getPublicKey(String name) {
    	if(this.Partners.containsKey(name)) {
    		Map<Short, Object> map = this.Partners.get(name);
    		if(map.containsKey(Constants_ma.PUBLIC_KEY)) {
    		OneKey pubkey = (OneKey) map.get(Constants_ma.PUBLIC_KEY);
    		return pubkey;
    		}
    	}
    	return null;
    }
    
    
    
    public Certificate getRootCertificate(String name) {
    	if(this.Partners.containsKey(name)) {
    		Map<Short, Object> map = this.Partners.get(name);
    		if(map.containsKey(Constants_ma.ROOT_CERT)) {
    		Certificate cert = (Certificate) map.get(Constants_ma.ROOT_CERT);
    		return cert;
    		}
    	}
    	return null;
    }
    
    
	@Override
	public void close() throws Exception {
		// TODO Auto-generated method stub
		
	}

}
