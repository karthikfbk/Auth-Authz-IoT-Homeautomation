package thesis.authz.federated_iot.db;

import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;

public interface FedIoT_DBConnector {
	/**
	 * The default database name
	 */
	public String dbName = "aceasdb";

	//******************New table********************************	

	/**
	 * The table of token claims
	 */
	public String claimsTable = "Claims";

	/**
	 * The column for token identifiers (Cti)
	 */
	public String ctiColumn = "Cti";

	/**
	 * The column for the token claim names
	 */
	public String claimNameColumn = "ClaimName";

	/**
	 * The column for the token claim values
	 */
	public String claimValueColumn = "ClaimValue"; 

	//******************New table********************************   

	/**
	 * The table invalid (expired or revoked) tokens
	 */
	public String oldTokensTable = "InvalidTokens";

	//******************New table********************************   	
	/**
	 * The table of devices
	 */
	public String deviceTable = "Devices";
	/**
	 * The column name for Device identifier
	 */
	public String deviceIdColumn = "DeviceId";

	/**
	 * The column name for the default audience use by the client
	 */
    public String defaultAud = "DefaultAud";
    
    /**
     * The column name for the default scope use by the client
     */
    public String defaultScope = "DefaultScope";
    
	/**
	 * The column name for pre-shared keys
	 */
	public String pskColumn = "PSK";

	/**
	 * The column name for raw public keys
	 */
	public String rpkColumn = "RPK";

	/**
	 * The column name for expiration defaults
	 */
	public String expColumn = "Exp";
	
	/**
     * The column name for noting that the client needs a client token
     */
    public String needClientToken = "NeedClientToken";

	//******************New table********************************   	
	/**
	 * The table of supported profiles
	 */
	public String profilesTable = "Profiles";

	/**
	 * The column name for identifiers that may be both Clients or RS
	 */
	public String idColumn = "Id";

	/**
	 * The column name for the profile
	 */
	public String profileColumn = "Profile";

	//******************New table********************************   
	/**
	 * The table of supported key types, using the values PSK and RPK.
	 */
	public String keyTypesTable = "KeyTypes";

	/**
	 * The column name for the key type
	 */
	public String keyTypeColumn = "Profile";

	//******************New table********************************   
	/**
	 * The table of scopes a Device supports
	 */
	public String scopesTable = "Scopes";

	/**
	 * The column name for the scope
	 */
	public String scopeColumn = "Scope";

	//******************New table********************************   
	/**
	 * The table of token types a Device supports, using the values CWT and REF
	 */
	public String tokenTypesTable = "TokenTypes";

	/**
	 * The column name for the token type
	 */
	public String tokenTypeColumn = "TokenType";


	//******************New table********************************   
	/**
	 * The table of audiences an Device identifies with
	 */
	public String audiencesTable = "Audiences";

	/**
	 * The column name for Audiences
	 */
	public String audColumn = "Aud";

	//******************New table********************************   
	/**
	 * The table listing the COSE configurations a Device supports
	 * for protecting access tokens
	 */
	public String coseTable = "CoseParams";

	/**
	 * The column name for COSE parameters
	 */
	public String coseColumn = "Cose";


	//******************New table********************************   
	/**
	 * The table saving the counter for generating cti's
	 */
	public String ctiCounterTable = "ctiCounterTable";

	/**
	 * The column name for cti counter
	 */
	public String ctiCounterColumn = "ctiCounter";

	//******************New table********************************   
	/**
	 * The table saving the association between cti and Device identifier
	 *     Note: This table uses ctiColumn and deviceIdColumn
	 */
	public String cti2deviceTable = "TokenLog";
	
	/**
	 * Gets a common profile supported by a specific audience and device.
	 * 
     * @param deviceId  the device identifier
	 * @param aud  the audiences
	 * 
	 * @return  a profile they all support or null if there isn't any
	 * 
	 * @throws AceException 
	 */
	public String getSupportedProfile(String devicetId, Set<String> aud) 
	            throws AceException;
	
	/**
     * Returns a common key type for the proof-of-possession
     * algorithm, or null if there isn't any.
     * 
     * @param deviceId  the  device identifier
     * @param aud  the audiences that this device is addressing 
     * 
     * @return  a key type both support or null
	 * @throws AceException 
     */
    public String getSupportedPopKeyType(String deviceId, Set<String> aud)
        throws AceException;
    
    /**
     * Returns a common token type, or null if there isn't any
     * 
     * @param aud  the audiences that are addressed
     * 
     * @return  a token type the audience supports or null
     * @throws AceException 
     */
    public Short getSupportedTokenType(Set<String> aud) throws AceException;
    
    /**
     * Returns a common set of COSE message parameters used to protect
     * the access token, for an audience, null if there is no common one.
     * 
     * Note: For a asymmetric key message like Sign0, we assume that the 
     * RS has the AS's public key and can handle public key operations.
     * 
     * @param aud  the audiences
     * @return  the COSE parameters or null
     * @throws AceException 
     * @throws CoseException 
     */
    public COSEparams getSupportedCoseParams(Set<String> aud) 
            throws AceException, CoseException;
    
    /**
     * Checks if the given audience supports the given scope.
     * 
     * @param aud  the audience that is addressed
     * @param scope  the scope
     * 
     * @return  true if the audience supports the scope, false otherwise
     * @throws AceException 
     */
    public boolean isScopeSupported(String aud, String scope)
            throws AceException;
    
    /**
     * Get the default scope of this device
     *  
     * @param deviceId  the device identifier
     * 
     * @return  the default scope used by this device if any
     * 
     * @throws AceException 
     */
    public String getDefaultScope(String deviceId) throws AceException;

    /**
     * Get the default audience of this device
     *  
     * @param deviceId  the device identifier
     * 
     * @return  the default audience used by this device if any
     * 
     * @throws AceException 
     */
    public String getDefaultAudience(String deviceId) throws AceException;  
    
    /**
     * Gets the Devices that are part of this audience.
     * 
     * @param aud  the audience identifier
     *
     * @return  the Device identifiers of those that are part of this audience 
     *  or null if that audience is not defined
     * 
     * @throws AceException 
     */
    public Set<String> getDevices(String aud) throws AceException;
    
	/**
	 * Gets all RSs.
	 *
	 * @return  all registered Device identifiers
	 *  or null if that audience is not defined
	 *
	 * @throws AceException
	 */
	public Set<String> getDevices() throws AceException;
	
    /**
     * Returns the smallest expiration time for the Device in this
     *     audience.
     *     
     * @param aud  the audiences of the access token
     * @return  the expiration time in milliseconds
     * 
     * @throws AceException 
     */
    public long getExpTime(Set<String> aud) throws AceException;
    
    /**
     * Gets the audiences that this Device is part of.
     * Note that the Device identifier is always a singleton audience itself.
     * 
     * @param deviceId  the device identifier
     *
     * @return  the audience identifiers that this Device is part of
     * 
     * @throws AceException 
     */
    public Set<String> getAudiences(String deviceId) 
                throws AceException;  
    
    /**
     * Get the shared symmetric key (PSK) with this Device
     *  
     * @param deviceId  the device identifier
     * 
     * @return  the shared symmetric key if there is any
     * 
     * @throws AceException 
     */
    public OneKey getDevicePSK(String deviceId)
        throws AceException;
    
    /**
     * Get the public key (RPK) of this RS
     *  
     * @param deviceId  the device identifier
     * 
     * @return  the public key if there is any
     * 
     * @throws AceException 
     */
    public OneKey getDeviceRPK(String deviceId)
        throws AceException;
    
	/**
	 * Creates a new Device. Must provide either a sharedKey or a publicKey.
	 * 
     * @param deviceId  the identifier for the Device
     * @param profiles  the profiles this Device supports
     * @param scopes  the scopes this Deivce supports
     * @param auds  the audiences this Deivce identifies with
     * @param keyTypes   the key types this Deivce supports
     * @param tokenTypes  the token types this Deivce supports.
     *     See <code>AccessTokenFactory</code>
     * @param cose the set of supported parameters of COSE wrappers for
     *   access tokens, empty if this RS does not process CWTs
     * @param expiration  the expiration time for access tokens for this Deivce 
     *     or 0 if the default value is used
     * @param sharedKey  the secret key shared with this Deivce or null if there
     *     is none
     * @param publicKey  the COSE-encoded public key of this Deivce or null if
     *     there is none
     *
	 * @throws AceException 
	 */
	public void addDevice(String deviceId, Set<String> profiles, String defaultScope,
			String defaultaud, Set<String> scopes, 
            Set<String> auds, Set<String> keyTypes, Set<Short> tokenTypes, 
            Set<COSEparams> cose, long expiration, OneKey sharedKey, 
            OneKey publicKey, boolean needClientToken) throws AceException;
	
	/**
	 * Deletes an Device and all related registration data.
	 * 
	 * @param deviceId  the identifier of the Device
	 * 
	 * @throws AceException
	 */
	public void deleteDevice(String deviceId) 
			throws AceException;
	
	/**
	 * @param Device  the identifier of the device 
	 * @return  Does this Device need a client token?
	 * 
	 * @throws AceException 
	 */
	public boolean needsClientToken(String device) throws AceException;
	
	/**
	 * Adds a new token to the database
	 * @param cti  the token identifier encoded Base64
	 * @param claims  the claims of this token
	 * 
	 * @throws AceException 
	 */
	public void addToken(String cti, Map<Short, CBORObject> claims) 
	        throws AceException;
	
	/**
     * Deletes an existing token from the database
     * @param cti  the token identifier encoded Base64
     * 
     * @throws AceException 
     */
    public void deleteToken(String cti) throws AceException;
    
    /**
     * Deletes all expired tokens from the database
     * 
     * @param now  the current time
     * 
     * @throws AceException 
     */
    public void purgeExpiredTokens(long now) throws AceException;
    
    /**
     * Returns the claims associated with this token.
     * 
     * @param cti  the token identifier encoded Base64
     * 
     * @return  the set of claims
     *  
     * @throws AceException
     */
    public Map<Short, CBORObject> getClaims(String cti) throws AceException;
    
    
    /**
     * Load the current cti counter of the token endpoint from the DB.
     * 
     * @return   the value of the cti counter in the DB
     * 
     * @throws AceException
     */
    public Long getCtiCounter() throws AceException;
    
    /**
     * Save the current cti counter from the token endpoint to the DB.
     * 
     * @param cti  the current value of the cti counter
     * 
     * @throws AceException 
     */
    public void saveCtiCounter(Long cti) throws AceException;
    
    /**
     * Save a mapping from token identifier to device identifier for
     *  a newly issued token.
     * @param cti  the token identifier Base64 encoded
     * @param deviceId  the device identifier
     * @throws AceException
     */
    public void addCti2Device(String cti, String deviceId) throws AceException;
    
    /**
     * Get the device identifier that holds a given token
     * identified by its cti.
     * 
     * @param cti  the cti of the token Base64 encoded
     * @return  the device identifier
     * @throws AceException 
     */
    public String getDevice4Cti(String cti) throws AceException;
    
    /**
     * Get the token identifiers (cti) for a given device.
     * 
     * @param deviceId  the device identifier
     * @return a set of token identifiers Base64 encoded
     * @throws AceException
     */
    public Set<String> getCtis4Device(String deviceId) throws AceException;
    
	/**
	 * Close the connections. After this any other method calls to this
	 * object will lead to an exception.
	 * 
	 * @throws AceException
	 */
	public void close() throws AceException;
}
