package thesis.authz.federated_iot.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.as.DBConnector;
import se.sics.ace.examples.MySQLDBAdapter;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.examples.SQLDBAdapter;

public class FedIoT_SQLConnector implements FedIoT_DBConnector, AutoCloseable{

	/**
	 * The default user of the database
	 */
	private String defaultUser = "aceuser";
	
	/**
	 * The default password of the default user. 
	 * CAUTION! Only use this for testing, this is very insecure
	 * (but then if you didn't figure that out youdeviceelf, I cannot help you
	 * anyway).
	 */
	private String defaultPassword = "password";
	
	/**
	 * The default connection URL for the database.
	 */
	private String defaultDbUrl = "";
	
	/**
	 * A prepared connection.
	 */
	private Connection conn = null;
	
	/**
	 * Records if the singleton connector is connected or disconnected
	 */
	private static boolean isConnected = false;

	/**
	 * A prepared INSERT statement to add a new Device
	 * 
	 * Parametedevice: device id, cose encoding, default expiration time, psk, rpk
	 */
	protected PreparedStatement insertDevice;

	/**
     * A prepared DELETE statement to remove a Device
     * 
     * Parameter: device id.
     */
	protected PreparedStatement deleteDevice;
    
    /**
     * A prepared SELECT statement to get a set of Device for an audience
     * 
     * Parameter: audience name
     */
	protected PreparedStatement selectDevice;

	/**
	 * A prepared SELECT statement to get all Devices
	 */
	protected PreparedStatement selectAllDevices;

	/**
	 * A prepared INSERT statement to add a profile supported
	 * by a Device
	 * 
	 * Parametedevice: id, profile name
	 */
	protected PreparedStatement insertProfile;
	
	/**
     * A prepared DELETE statement to remove the profiles supported
     * by a Device
     * 
     * Parameter: id
     */
	protected PreparedStatement deleteProfiles;
	
    /**
     * A prepared SELECT statement to get all profiles for 
     * an audience and a Device
     * 
     * Parametedevice: audience name, device id
     */
	protected PreparedStatement selectProfiles;
    
	/**
	 * A prepared INSERT statement to add the key types supported
     * by a Device
     * 
     * Parametedevice: id, key type
	 */
	protected PreparedStatement insertKeyType;
	 
	/**
     * A prepared DELETE statement to remove the key types supported
     * by a Device
     * 
     * Parameter: id
     */
	protected PreparedStatement deleteKeyTypes;
    
    /**
     * A prepared SELECT statement to get a set of key types
     * 
     * Parametedevice: audience name, device id
     */
	protected PreparedStatement selectKeyTypes;
	
	/**
     * A prepared INSERT statement to add the scopes supported
     * by a Device
     * 
     * Parametedevice: device id, scope name
     */
	protected PreparedStatement insertScope;
    
    /**
     * A prepared DELETE statement to remove the scopes supported
     * by a Device
     * 
     * Parameter: device id
     */
	protected PreparedStatement deleteScopes;
    
    /**
     * A prepared SELECT statement to get a set of Scopes for a specific Device
     * 
     * Parameter: device id
     */
	protected PreparedStatement selectScopes;
    
    /**
     * A prepared INSERT statement to add an audience a 
     * Device identifies with
     * 
     * Parameter: device id, audience name
     */
	protected PreparedStatement insertAudience;
	
    /**
     * A prepared DELETE statement to remove the audiences
     * a Device identifies with
     * 
     * Parameter: device id
     */
	protected PreparedStatement deleteAudiences;
    
    /**
     * A prepared SELECT statement to get a set of audiences for an device
     * 
     * Parameter: device id
     */
	protected PreparedStatement selectAudiences;
    
    /**
     * A prepared INSERT statement to add a token type a 
     * Device supports
     * 
     * Parametedevice: device id, token type
     */
	protected PreparedStatement insertTokenType;
    
    /**
     * A prepared DELETE statement to remove the token types a
     * a Device supports
     * 
     * Parameter: device id
     */
	protected PreparedStatement deleteTokenTypes;

    /**
     * A prepared SELECT statement to get a set of token types for an audience
     * 
     * Parameter: audience name
     */
	protected PreparedStatement selectTokenTypes;
    
		
	/**
     * A prepared SELECT statement to read whether the device needs a
     * client token.
     * 
     * Parameter: device id
     */
    protected PreparedStatement needClientToken;
	
	/**
	 * A prepared SELECT statement to get the default audience for a device.
	 * 
	 *  Parameter: device id
	 */
	protected PreparedStatement selectDefaultAudience;
	
	/**
     * A prepared SELECT statement to get the default scope for a device.
     * 
     *  Parameter: device id
     */
	protected PreparedStatement selectDefaultScope;

    
    /**
     * A prepared INSERT statement to add a new supported cose configuration
     * for protecting CWTs
     * 
     * Parametedevice: device id, cose config
     */
	protected PreparedStatement insertCose;
    
    /**
     * A prepared DELETE statement to remove a cose configuration
     * 
     * Parameter: device id
     */
	protected PreparedStatement deleteCose;
    
	/**
	 * A prepared SELECT statement to get the COSE configurations for
	 * an audience.
	 * 
	 * Parameter: audience name
	 */
	protected PreparedStatement selectCOSE;
	
	/**
     * A prepared SELECT statement to get the default expiration time for
     *     a device
     *     
     * Parameter: audience name
     */
	protected PreparedStatement selectExpiration;
	
    /**
     * A prepared SELECT statement to get a the pre-shared keys for
     *     an audience
     *     
     * Parameter: audience name
     */
	protected PreparedStatement selectdevicePSK;
    
    /**
     * A prepared SELECT statement to get the public keys of an audience.
     * 
     * Parameter: audience name
     */
	protected PreparedStatement selectdeviceRPK;
    
    /**
     * A prepared SELECT statement to fetch token ids and their
     * expiration time from the claims table.
     */
	protected PreparedStatement selectExpirationTime;
    
    /**
     * A prepared INSERT statement to add a claim of a token 
     * to the Claims table.
     * 
     * Parametedevice: token cti, claim name, claim value
     */
	protected PreparedStatement insertClaim;
    
    /**
     * A prepared DELETE statement to remove the claims of a token 
     * from the Claims table.
     * 
     * Parametedevice: token cti
     */
	protected PreparedStatement deleteClaims;
    
    /**
     * A prepared SELECT statement to select the claims of a token from
     * the Claims table.
     * 
     * Parameter: token cti
     */
	protected PreparedStatement selectClaims;
	
	/**
	 * A prepared INSERT statement to save a token's claims to the 
	 * InvalidTokens table.
	 */
	protected PreparedStatement logInvalidToken;	
    
    /**
     * A prepared SELECT statement to select the cti counter value from the 
     * cti counter table.
     */
	protected PreparedStatement selectCtiCtr;
    
    /**
     * A prepared UPDATE statement to update the saved cti counter value in the
     * cti counter table.
     */
	protected PreparedStatement updateCtiCtr;
    
    
    /**
     * A prepared INSERT statement to insert a new token to client mapping.
     */
    protected PreparedStatement insertCti2Device;
    
    /**
     * A prepared SELECT statement to select the client identifier holding a
     * token identified by its cti.
     */
    protected PreparedStatement selectDeviceByCti;


    /**
     * A prepared SELECT statement to select the token identifiedevice (cti) 
     * held by a client
     */
    protected PreparedStatement selectCtisByDevice;
    
    /**
     * The singleton instance of this connector
     */
    private static FedIoT_SQLConnector connector = null;
    
    /**
     * The DB adapter
     */
    private SQLDBAdapter adapter = null;
    
    /**
	 * Gets the singleton instance of this connector. Defaults to MySQL.
	 *
	 * @param dbUrl     the database URL, if null the default will be used
	 * @param user      the database user, if null the default will be used
	 * @param pwd       the database user's password, if null the default
	 *
	 * @return  the singleton instance
	 *
	 * @throws SQLException
	 */
	public static FedIoT_SQLConnector getInstance(String dbUrl, String user, String pwd)
			throws SQLException {
		return FedIoT_SQLConnector.getInstance(new FedIoT_MySQLDBAdapter(), dbUrl, user, pwd);
	}

    /**
     * Gets the singleton instance of this connector.
     * 
     * @param dbCreator a creator instance for the specific DB type being used.
     * @param dbUrl     the database URL, if null the default will be used
     * @param user      the database user, if null the default will be used
     * @param pwd       the database user's password, if null the default
     * 
     * @return  the singleton instance
     * 
     * @throws SQLException
     */
    public static FedIoT_SQLConnector getInstance(SQLDBAdapter dbCreator, 
            String dbUrl, String user, String pwd) throws SQLException {
        if (FedIoT_SQLConnector.connector == null) {
        	FedIoT_SQLConnector.connector 
                = new FedIoT_SQLConnector(dbCreator, dbUrl, user, pwd);
        }
        return FedIoT_SQLConnector.connector;
    }
    
	/**
	 * Create a new database connector either from given values or the
	 * defaults. Defaults to MySQL for the DB creation.
	 *
	 * @param dbUrl     the database URL, if null the default will be used
	 * @param user      the database user, if null the default will be used
	 * @param pwd       the database user's password, if null the default
	 * 				    will be used
	 * @throws SQLException
	 */
	protected FedIoT_SQLConnector(String dbUrl, String user, String pwd)
			throws SQLException {
		this(new FedIoT_MySQLDBAdapter(), dbUrl, user, pwd);
	}
    
	/**
	 * Create a new database connector either from given values or the 
	 * defaults.
	 *
     * @param dbAdapter handler for engine-db specific commands.
	 * @param dbUrl     the database URL, if null the default will be used
	 * @param user      the database user, if null the default will be used
	 * @param pwd       the database user's password, if null the default
	 * 				    will be used
	 * @throws SQLException 
	 */
	protected FedIoT_SQLConnector(SQLDBAdapter dbAdapter, String dbUrl, String user, 
	        String pwd) throws SQLException {
		if (dbUrl != null) {
			this.defaultDbUrl = dbUrl;
		}
		else
		{
			this.defaultDbUrl = dbAdapter.getDefaultDBURL();
		}
		if (user != null) {
			this.defaultUser = user;
		}
		if (pwd != null) {
			this.defaultPassword = pwd;
		}

		this.adapter = dbAdapter;
		
        dbAdapter.setParams(this.defaultUser, this.defaultPassword, 
                FedIoT_DBConnector.dbName, this.defaultDbUrl);

		Properties connectionProps = new Properties();      
		connectionProps.put("user", this.defaultUser);
		connectionProps.put("password", this.defaultPassword);
		this.conn = DriverManager.getConnection(this.defaultDbUrl + "/" 
		        + FedIoT_DBConnector.dbName, connectionProps);
		FedIoT_SQLConnector.isConnected = true;
	   
		this.insertDevice = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + FedIoT_DBConnector.deviceTable + " VALUES (?,?,?,?,?,?,?);"));
		
		this.deleteDevice = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + FedIoT_DBConnector.deviceTable + " WHERE " 
		                + FedIoT_DBConnector.deviceIdColumn + "=?;"));
		
		this.selectDevice = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.deviceIdColumn
		                + " FROM "
		                + FedIoT_DBConnector.audiencesTable
		                + " WHERE " + FedIoT_DBConnector.audColumn + "=? ORDER BY "
		                + FedIoT_DBConnector.deviceIdColumn + ";"));

		this.selectAllDevices = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.deviceIdColumn
		                + " FROM "
		                + FedIoT_DBConnector.deviceTable
		                + " ORDER BY "
		                + FedIoT_DBConnector.deviceIdColumn + ";"));

		this.insertProfile = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + FedIoT_DBConnector.profilesTable
		                + " VALUES (?,?);"));
		
		this.deleteProfiles = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + FedIoT_DBConnector.profilesTable
		                + " WHERE " + FedIoT_DBConnector.idColumn + "=?;"));
		
		this.selectProfiles = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT * FROM "
		                + FedIoT_DBConnector.profilesTable
		                + " WHERE " + FedIoT_DBConnector.idColumn + " IN (SELECT " 
		                + FedIoT_DBConnector.deviceIdColumn + " FROM " 
		                + FedIoT_DBConnector.audiencesTable
		                + " WHERE " + FedIoT_DBConnector.audColumn
		                + "=?) UNION SELECT * FROM " 
		                + FedIoT_DBConnector.profilesTable
		                + " WHERE " + FedIoT_DBConnector.idColumn + "=? ORDER BY "
		                + FedIoT_DBConnector.idColumn + ";"));

		this.insertKeyType = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + FedIoT_DBConnector.keyTypesTable
		                + " VALUES (?,?);"));

		this.deleteKeyTypes = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + FedIoT_DBConnector.keyTypesTable
		                + " WHERE " + FedIoT_DBConnector.idColumn + "=?;"));

		this.selectKeyTypes =  this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT * FROM "
		                + FedIoT_DBConnector.keyTypesTable
		                + " WHERE " + FedIoT_DBConnector.idColumn + " IN (SELECT " 
		                + FedIoT_DBConnector.deviceIdColumn + " FROM " 
		                + FedIoT_DBConnector.audiencesTable
		                + " WHERE " + FedIoT_DBConnector.audColumn + "=?)"
		                + " UNION SELECT * FROM "
		                + FedIoT_DBConnector.keyTypesTable + " WHERE " 
		                + FedIoT_DBConnector.idColumn + "=? ORDER BY "
		                + FedIoT_DBConnector.idColumn + ";"));

		this.insertScope = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + FedIoT_DBConnector.scopesTable
		                + " VALUES (?,?);"));

		this.deleteScopes = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + FedIoT_DBConnector.scopesTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + "=?;"));

		this.selectScopes = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT * FROM "
		                + FedIoT_DBConnector.scopesTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + " IN (SELECT " 
		                + FedIoT_DBConnector.deviceIdColumn + " FROM " 
		                + FedIoT_DBConnector.audiencesTable
		                + " WHERE " + FedIoT_DBConnector.audColumn + "=?) ORDER BY "
		                + FedIoT_DBConnector.deviceIdColumn + ";"));

		this.insertAudience = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + FedIoT_DBConnector.audiencesTable
		                + " VALUES (?,?);"));

		this.deleteAudiences = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + FedIoT_DBConnector.audiencesTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + "=?;"));

		this.selectAudiences = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.audColumn + " FROM "
		                + FedIoT_DBConnector.audiencesTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + "=? ORDER BY "
		                + FedIoT_DBConnector.audColumn + ";"));

		this.insertTokenType = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + FedIoT_DBConnector.tokenTypesTable
		                + " VALUES (?,?);"));

		this.deleteTokenTypes = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + FedIoT_DBConnector.tokenTypesTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + "=?;"));

		this.selectTokenTypes = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT * FROM "
		                + FedIoT_DBConnector.tokenTypesTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + " IN (SELECT " 
		                + FedIoT_DBConnector.deviceIdColumn + " FROM " 
		                + FedIoT_DBConnector.audiencesTable
		                + " WHERE " + FedIoT_DBConnector.audColumn + "=?) ORDER BY "
		                + FedIoT_DBConnector.deviceIdColumn + ";"));


		this.needClientToken = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.needClientToken + " FROM "
		                + FedIoT_DBConnector.deviceTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + "=?;"));

		this.selectDefaultAudience = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.defaultAud + " FROM " 
		                + FedIoT_DBConnector.deviceTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + "=?;"));

		this.selectDefaultScope = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.defaultScope + " FROM " 
		                + FedIoT_DBConnector.deviceTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + "=?;"));

		this.insertCose = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + FedIoT_DBConnector.coseTable
		                + " VALUES (?,?);"));

		this.deleteCose = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + FedIoT_DBConnector.coseTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + "=?;"));

		this.selectCOSE = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT * "
		                + " FROM "  + FedIoT_DBConnector.coseTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + " IN (SELECT "
		                + FedIoT_DBConnector.deviceIdColumn + " FROM " 
		                + FedIoT_DBConnector.audiencesTable
		                + " WHERE " + FedIoT_DBConnector.audColumn + "=?) ORDER BY "
		                + FedIoT_DBConnector.deviceIdColumn + ";"));

		this.selectExpiration = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.expColumn 
		                + " FROM "  + FedIoT_DBConnector.deviceTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + "=?;"));

		this.selectdevicePSK = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.pskColumn
		                + " FROM "  + FedIoT_DBConnector.deviceTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + " IN (SELECT "
		                + FedIoT_DBConnector.deviceIdColumn + " FROM " 
		                + FedIoT_DBConnector.audiencesTable
		                + " WHERE " + FedIoT_DBConnector.audColumn + "=?);"));

		this.selectdeviceRPK = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.rpkColumn
		                + " FROM "  + FedIoT_DBConnector.deviceTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + " IN (SELECT "
		                + FedIoT_DBConnector.deviceIdColumn + " FROM " 
		                + FedIoT_DBConnector.audiencesTable
		                + " WHERE " + FedIoT_DBConnector.audColumn + "=?);"));

		this.selectExpirationTime = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.ctiColumn + ","
		                + FedIoT_DBConnector.claimValueColumn
		                + " FROM "
		                + FedIoT_DBConnector.claimsTable
		                + " WHERE " + FedIoT_DBConnector.claimNameColumn + "=" 
		                + Constants.EXP + ";"));

		this.insertClaim = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + FedIoT_DBConnector.claimsTable
		                + " VALUES (?,?,?);"));

		this.deleteClaims = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + FedIoT_DBConnector.claimsTable
		                + " WHERE " + FedIoT_DBConnector.ctiColumn + "=?;"));

		this.selectClaims = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.claimNameColumn + ","
		                + FedIoT_DBConnector.claimValueColumn + " FROM " 
		                + FedIoT_DBConnector.claimsTable
		                + " WHERE " + FedIoT_DBConnector.ctiColumn + "=?;"));

		this.logInvalidToken = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + FedIoT_DBConnector.oldTokensTable
		                + " SELECT * FROM " + FedIoT_DBConnector.claimsTable
		                + " WHERE " + FedIoT_DBConnector.ctiColumn + "=?;")); 

		this.selectCtiCtr = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.ctiCounterColumn + " FROM "
		                + FedIoT_DBConnector.ctiCounterTable
		                + ";"));

		this.updateCtiCtr = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("UPDATE "
		                + FedIoT_DBConnector.ctiCounterTable
		                + " SET " + FedIoT_DBConnector.ctiCounterColumn + "=?;"));

		this.insertCti2Device = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + FedIoT_DBConnector.cti2deviceTable
		                + " VALUES (?,?);"));


		this.selectDeviceByCti = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.deviceIdColumn + " FROM "
		                + FedIoT_DBConnector.cti2deviceTable
		                + " WHERE " + FedIoT_DBConnector.ctiColumn + "=?;"));   

		this.selectCtisByDevice= this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + FedIoT_DBConnector.ctiColumn + " FROM "
		                + FedIoT_DBConnector.cti2deviceTable
		                + " WHERE " + FedIoT_DBConnector.deviceIdColumn + "=?;"));   

	}

	/**
	 * Create the necessary database and tables. Requires the
	 * root user password.
	 *
	 * @param rootPwd  the root user password
	 * @param username the username of the database owner, default if null
	 * @param userPwd  the password of the database owner, default if null
	 * @param dbName   the name of the database, default if null
	 * @param dbUrl    the URL of the database, default if null
	 * @throws AceException
	 */
	public static void createDB(String rootPwd, String username,
	        String userPwd, String dbName, String dbUrl) throws AceException {
	    if (rootPwd == null) {
	        throw new AceException(
	                "Cannot initialize the database without the password");
	    }

	    FedIoT_SQLConnector.createDB(new FedIoT_MySQLDBAdapter(), rootPwd, username, 
	            userPwd, dbName, dbUrl);
	}

	/**
	 * Create the necessary database and tables. Requires the
	 * root user password.
	 * @param dbAdapter 
	 * 
	 * @param rootPwd  the root user password
     * @param username the username of the database owner, default if null
     * @param userPwd  the password of the database owner, default if null
     * @param dbName   the name of the database, default if null
     * @param dbUrl    the URL of the database, default if null
	 * @throws AceException 
	 */
	public static void createDB(SQLDBAdapter dbAdapter, String rootPwd, String username,
								String userPwd, String dbName, String dbUrl) throws AceException {
		if (rootPwd == null) {
			throw new AceException(
					"Cannot initialize the database without the password");
		}
		dbAdapter.setParams(username, userPwd, dbName, dbUrl);
        dbAdapter.createDBAndTables(rootPwd);
	}

	/**
	 * Deletes the whole database assuming MySQL.
	 * 
	 * CAUTION: This method really does what is says, without asking you again!
     * It's main function is to clean the database during test runs.
     * 
	 * @param rootPwd  the root user password.
	 * 
	 * @throws AceException
	 */
	public static void wipeDatabase(String rootPwd) throws AceException {
		FedIoT_MySQLDBAdapter dbAdapter = new FedIoT_MySQLDBAdapter();
		FedIoT_SQLConnector.wipeDatabase(dbAdapter, rootPwd);
	}
	
	/**
	 * Deletes the whole database.
	 * 
	 * CAUTION: This method really does what is says, without asking you again!
	 * It's main function is to clean the database during test runs.
	 * 
	 * @param dbAdapter handler for engine-db specific commands
	 * @param rootPwd  the root password
	 * @throws AceException 
	 * @throws SQLException 
	 */
	public static void wipeDatabase(SQLDBAdapter dbAdapter, String rootPwd) throws AceException {
		dbAdapter.wipeDB(rootPwd);
	}
	
	/**
	 * Close the connections. After this any other method calls to this
	 * object will lead to an exception.
	 * 
	 * @throws AceException
	 */
	@Override
	public synchronized void close() throws AceException {
	    if (FedIoT_SQLConnector.isConnected) {
	        try {
	            this.conn.close();
	            FedIoT_SQLConnector.connector = null;
	            FedIoT_SQLConnector.isConnected = false;
	        } catch (SQLException e) {
	        	FedIoT_SQLConnector.isConnected = false;
	            throw new AceException(e.getMessage());
	        }	        
	    }
	}
	
	@Override
	public String getSupportedProfile(String devicetId, Set<String> aud) throws AceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getSupportedPopKeyType(String deviceId, Set<String> aud) throws AceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Short getSupportedTokenType(Set<String> aud) throws AceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public COSEparams getSupportedCoseParams(Set<String> aud) throws AceException, CoseException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isScopeSupported(String aud, String scope) throws AceException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String getDefaultScope(String deviceId) throws AceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getDefaultAudience(String deviceId) throws AceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Set<String> getDevices(String aud) throws AceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Set<String> getDevices() throws AceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long getExpTime(Set<String> aud) throws AceException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public Set<String> getAudiences(String deviceId) throws AceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public OneKey getDevicePSK(String deviceId) throws AceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public OneKey getDeviceRPK(String deviceId) throws AceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void addDevice(String deviceId, Set<String> profiles, String defaultScope, String defaultAud,
			Set<String> scopes, Set<String> auds, Set<String> keyTypes, Set<Short> tokenTypes, Set<COSEparams> cose,
			long expiration, OneKey sharedKey, OneKey publicKey, boolean needClientToken) throws AceException {
		   if (deviceId == null || deviceId.isEmpty()) {
	            throw new AceException("deviceId must have non-null, non-empty identifier");
	        }
	        
	        if (sharedKey == null && publicKey == null) {
	            throw new AceException("Cannot register a RS without a key");
	        }
	        
	        if (profiles.isEmpty()) {
	            throw new AceException("RS must support at least one profile");
	        }
	        
	        if (tokenTypes.isEmpty()) {
	            throw new AceException("RS must support at least one token type");
	        }
	        
	        if (keyTypes.isEmpty()) {
	            throw new AceException("RS must support at least one PoP key type");
	        }
	        
	        if (expiration <= 0L) {
	            throw new AceException("RS must have default expiration time > 0");
	        }       
	        
	        // Prevent adding an rs that has an identifier that is equal to an 
	        // existing audience
	        try {
	            this.selectDevice.setString(1, deviceId);
	            ResultSet result = this.selectDevice.executeQuery();
	            this.selectDevice.clearParameters();
	            if (result.next()) {
	                result.close();
	                throw new AceException(
	                        "RsId equal to existing audience id: " + selectDevice);
	            }
	            result.close();

	            this.insertDevice.setString(1, deviceId);
	            this.insertDevice.setString(2, defaultAud);
	            this.insertDevice.setString(3, defaultScope);
	            this.insertDevice.setLong(4, expiration);
	            if (sharedKey != null) {
	                this.insertDevice.setBytes(5, sharedKey.EncodeToBytes());
	            } else {
	                this.insertDevice.setBytes(5, null);
	            }
	            if (publicKey != null) {
	                this.insertDevice.setBytes(6, publicKey.EncodeToBytes());
	            } else {
	                this.insertDevice.setBytes(6, null);
	            }
	            this.insertDevice.setBoolean(7, needClientToken);
	            this.insertDevice.execute();
	            this.insertDevice.clearParameters();
	            
	            for (String profile : profiles) {
	                this.insertProfile.setString(1, deviceId);
	                this.insertProfile.setString(2, profile);
	                this.insertProfile.execute();
	            }
	            this.insertProfile.clearParameters();
	            
	            for (String scope : scopes) {
	                this.insertScope.setString(1, deviceId);
	                this.insertScope.setString(2, scope);
	                this.insertScope.execute();
	            }
	            this.insertScope.clearParameters();
	            
	            for (String aud : auds) {
	                this.insertAudience.setString(1, deviceId);
	                this.insertAudience.setString(2, aud);
	                this.insertAudience.execute();
	            }
	            this.insertAudience.clearParameters();
	            
	            //The Device always recognizes itself as a singleton audience
	            this.insertAudience.setString(1, deviceId);
	            this.insertAudience.setString(2, deviceId);
	            this.insertAudience.execute();
	            this.insertAudience.clearParameters();
	            
	            for (String keyType : keyTypes) {
	                this.insertKeyType.setString(1, deviceId);
	                this.insertKeyType.setString(2, keyType);
	                this.insertKeyType.execute();
	            }
	            this.insertKeyType.clearParameters();
	            
	            for (short tokenType : tokenTypes) {
	                this.insertTokenType.setString(1, deviceId);
	                this.insertTokenType.setString(2, 
	                        AccessTokenFactory.ABBREV[tokenType]);
	                this.insertTokenType.execute();
	            }
	            this.insertTokenType.clearParameters();
	            
	            for (COSEparams coseP : cose) {
	                this.insertCose.setString(1, deviceId);
	                this.insertCose.setString(2, coseP.toString());
	                this.insertCose.execute();
	            }
	            this.insertCose.clearParameters();
	        } catch (SQLException e) {
	            throw new AceException(e.getMessage());
	        }
		
	}

	@Override
	public void deleteDevice(String deviceId) throws AceException {
        if (deviceId == null) {
            throw new AceException("deleteDevice() requires non-null rsId");
        }
        try {
            this.deleteDevice.setString(1, deviceId);
            this.deleteDevice.execute();
            this.deleteDevice.clearParameters();

            this.deleteProfiles.setString(1, deviceId);
            this.deleteProfiles.execute();
            this.deleteProfiles.clearParameters();

            this.deleteScopes.setString(1, deviceId);
            this.deleteScopes.execute();
            this.deleteScopes.clearParameters();

            this.deleteAudiences.setString(1, deviceId);
            this.deleteAudiences.execute();
            this.deleteAudiences.clearParameters();

            this.deleteKeyTypes.setString(1, deviceId);
            this.deleteKeyTypes.execute();
            this.deleteKeyTypes.clearParameters();

            this.deleteTokenTypes.setString(1, deviceId);
            this.deleteTokenTypes.execute();
            this.deleteTokenTypes.clearParameters();    

            this.deleteCose.setString(1, deviceId);
            this.deleteCose.execute();
            this.deleteCose.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
		
	}

	@Override
	public boolean needsClientToken(String device) throws AceException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void addToken(String cti, Map<Short, CBORObject> claims) throws AceException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void deleteToken(String cti) throws AceException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void purgeExpiredTokens(long now) throws AceException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Map<Short, CBORObject> getClaims(String cti) throws AceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Long getCtiCounter() throws AceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void saveCtiCounter(Long cti) throws AceException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void addCti2Device(String cti, String deviceId) throws AceException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public String getDevice4Cti(String cti) throws AceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Set<String> getCtis4Device(String deviceId) throws AceException {
		// TODO Auto-generated method stub
		return null;
	}
	/**
	 * Creates the user that manages this database. Defaults to MySQL.
	 *
	 * @param rootPwd  the database root password
	 * @param username  the name of the user
	 * @param userPwd   the password for the user
	 * @param dbUrl  the URL of the database
	 *
	 * @throws AceException
	 */
	public synchronized static void createUser(String rootPwd, String username,
											   String userPwd, String dbUrl) throws AceException {
		FedIoT_SQLConnector.createUser(new FedIoT_MySQLDBAdapter(), rootPwd, username, userPwd, dbUrl);
	}
    
    /**
     * Creates the user that manages this database.
     *
	 * @param dbAdapter an adapter instance for the specific DB type being used.
     * @param rootPwd  the database root password
     * @param username  the name of the user
     * @param userPwd   the password for the user
     * @param dbUrl  the URL of the database
     * 
     * @throws AceException 
     */
    public synchronized static void createUser(SQLDBAdapter dbAdapter, String rootPwd, String username,
											   String userPwd, String dbUrl) throws AceException {
		dbAdapter.setParams(username, userPwd, FedIoT_DBConnector.dbName, dbUrl);
		dbAdapter.createUser(rootPwd);
    }
}
