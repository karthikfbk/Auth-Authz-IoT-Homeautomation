package thesis.authz.federated_iot_core;

public class Constants_ma {
	
	//To avoid conflicts with Constants.java , start all values from 100
	
	
	public static final short ID_TOKEN = 100; //5
	
	//Target paramater for requesting ID_Token
	public static final short TAR = 101;
	
	/**
	 * grant type id token
	 */
	public static final short GT_ASYMMETRIC = 102 ;
	
	
	public static final short PUBLIC_KEY = 103;
	
	public static final short ROOT_CERT = 104;
	
	public static final short REQUEST_TYPE = 105;
	
	public static final short CONNECT = 106;
	
	public static final short QUERY = 107;
	
	
	public static final short INVALID_TARGET = 108;
	
	public static final short PROVISION_TYPE = 109;
	
	public static final short ASYMMETRIC = 110; //this means by means of operational certificates
	
	public static final short HYBRID = 111; // this means via RPK
	
	
	public static final short CONNECT_ENDPOINT = 112;
	
	public static final short RS_ID = 113;
	public static final short AS_ID = 114;
	public static final short CAS_ID = 114;
	
	public static final short DEV_SCP_MAP = 115;
	
	public static final short REQUIRED_ROOT = 116;
}
