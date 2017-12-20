package thesis.authz.federated_iot.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

import se.sics.ace.AceException;

import se.sics.ace.examples.SQLDBAdapter;

public class FedIoT_MySQLDBAdapter implements SQLDBAdapter {

	/**
	 * The default root-user name
	 */
	public static final String ROOT_USER = "root";

	/**
	 * The default connection URL for the database.
	 */
	public static final String DEFAULT_DB_URL = "jdbc:mysql://localhost:3306";

	protected String user;
	protected String password;
	protected String dbUrl;
	protected String dbName;

	@Override
	public void setParams(String user, String pwd, String dbName, String dbUrl) {
		// TODO Auto-generated method stub
		this.user = user;
		this.password = pwd;
		this.dbName = dbName;
		if(this.dbName == null)
		{
			this.dbName = FedIoT_DBConnector.dbName;
		}
		this.dbUrl = dbUrl;
		if(this.dbUrl == null)
		{
			this.dbUrl = DEFAULT_DB_URL;
		}
	}

	@Override
	public void createUser(String rootPwd) throws AceException {
		// TODO Auto-generated method stub
		Properties connectionProps = new Properties();
		connectionProps.put("user", FedIoT_MySQLDBAdapter.ROOT_USER);
		connectionProps.put("password", rootPwd);
		String cUser = "CREATE USER IF NOT EXISTS'" + this.user
				+ "'@'localhost' IDENTIFIED BY '" + this.password
				+ "';";
		String authzUser = "GRANT DELETE, INSERT, SELECT, UPDATE ON "
				+ this.dbName + ".* TO '" + this.user + "'@'localhost';";
		try (Connection rootConn = DriverManager.getConnection(
				this.dbUrl, connectionProps);
				Statement stmt = rootConn.createStatement();) {
			stmt.execute(cUser);
			stmt.execute(authzUser);
			stmt.close();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
	}

	@Override
	public void createDBAndTables(String rootPwd) throws AceException {
		String createDB = "CREATE DATABASE IF NOT EXISTS " + this.dbName
				+ " CHARACTER SET utf8 COLLATE utf8_bin;";

		//device id, cose encoding, default expiration time, psk, rpk
		String createDevices = "CREATE TABLE IF NOT EXISTS " + this.dbName
				+ "." + FedIoT_DBConnector.deviceTable + "("
				+ FedIoT_DBConnector.deviceIdColumn + " varchar(255) NOT NULL, "
				+ FedIoT_DBConnector.defaultAud + " varchar(255), "
				+ FedIoT_DBConnector.defaultScope + " varchar(255), "
				+ FedIoT_DBConnector.expColumn + " bigint NOT NULL, "
				+ FedIoT_DBConnector.pskColumn + " varbinary(64), "
				+ FedIoT_DBConnector.rpkColumn + " varbinary(255),"
				+ FedIoT_DBConnector.needClientToken + " tinyint(1), "
				+ " PRIMARY KEY (" + FedIoT_DBConnector.deviceIdColumn + "));";

		String createProfiles = "CREATE TABLE IF NOT EXISTS "
				+ this.dbName + "."
				+ FedIoT_DBConnector.profilesTable + "("
				+ FedIoT_DBConnector.idColumn + " varchar(255) NOT NULL, "
				+ FedIoT_DBConnector.profileColumn + " varchar(255) NOT NULL);";

		String createKeyTypes = "CREATE TABLE IF NOT EXISTS "
				+ this.dbName + "."
				+ FedIoT_DBConnector.keyTypesTable + "("
				+ FedIoT_DBConnector.idColumn + " varchar(255) NOT NULL, "
				+ FedIoT_DBConnector.keyTypeColumn + " enum('PSK', 'RPK', 'TST'));";

		String createScopes = "CREATE TABLE IF NOT EXISTS "
				+ this.dbName + "."
				+ FedIoT_DBConnector.scopesTable + "("
				+ FedIoT_DBConnector.deviceIdColumn + " varchar(255) NOT NULL, "
				+ FedIoT_DBConnector.scopeColumn + " varchar(255) NOT NULL);";

		String createTokenTypes = "CREATE TABLE IF NOT EXISTS "
				+ this.dbName + "."
				+ FedIoT_DBConnector.tokenTypesTable + "("
				+ FedIoT_DBConnector.deviceIdColumn + " varchar(255) NOT NULL, "
				+ FedIoT_DBConnector.tokenTypeColumn + " enum('CWT', 'REF', 'TST'));";

		String createAudiences = "CREATE TABLE IF NOT EXISTS "
				+ this.dbName + "."
				+ FedIoT_DBConnector.audiencesTable + "("
				+ FedIoT_DBConnector.deviceIdColumn + " varchar(255) NOT NULL, "
				+ FedIoT_DBConnector.audColumn + " varchar(255) NOT NULL);";

		String createCose =  "CREATE TABLE IF NOT EXISTS "
				+ this.dbName + "."
				+ FedIoT_DBConnector.coseTable + "("
				+ FedIoT_DBConnector.deviceIdColumn + " varchar(255) NOT NULL, "
				+ FedIoT_DBConnector.coseColumn + " varchar(255) NOT NULL);";

		String createClaims = "CREATE TABLE IF NOT EXISTS "
				+ this.dbName + "."
				+ FedIoT_DBConnector.claimsTable + "("
				+ FedIoT_DBConnector.ctiColumn + " varchar(255) NOT NULL, "
				+ FedIoT_DBConnector.claimNameColumn + " SMALLINT NOT NULL,"
				+ FedIoT_DBConnector.claimValueColumn + " varbinary(255));";

		String createOldTokens = "CREATE TABLE IF NOT EXISTS "
				+ this.dbName + "."
				+ FedIoT_DBConnector.oldTokensTable + "("
				+ FedIoT_DBConnector.ctiColumn + " varchar(255) NOT NULL, "
				+ FedIoT_DBConnector.claimNameColumn + " SMALLINT NOT NULL,"
				+ FedIoT_DBConnector.claimValueColumn + " varbinary(255));";

		String createCtiCtr = "CREATE TABLE IF NOT EXISTS "
				+ this.dbName + "."
				+ FedIoT_DBConnector.ctiCounterTable + "("
				+ FedIoT_DBConnector.ctiCounterColumn + " int unsigned);";

		String initCtiCtr = "INSERT INTO "
				+ this.dbName + "." 
				+ FedIoT_DBConnector.ctiCounterTable
				+ " VALUES (0);";

		String createTokenLog = "CREATE TABLE IF NOT EXISTS "
				+ FedIoT_DBConnector.dbName + "."
				+ FedIoT_DBConnector.cti2deviceTable + "("
				+ FedIoT_DBConnector.ctiColumn + " varchar(255) NOT NULL, "
				+ FedIoT_DBConnector.deviceIdColumn + " varchar(255) NOT NULL,"
				+ " PRIMARY KEY (" + FedIoT_DBConnector.ctiColumn + "));";

		Properties connectionProps = new Properties();
		connectionProps.put("user", FedIoT_MySQLDBAdapter.ROOT_USER);
		connectionProps.put("password", rootPwd);
		try (Connection rootConn = DriverManager.getConnection(
				this.dbUrl, connectionProps);
				Statement stmt = rootConn.createStatement()) {
			stmt.execute(createDB);
			stmt.execute(createDevices);
			stmt.execute(createProfiles);
			stmt.execute(createKeyTypes);
			stmt.execute(createScopes);
			stmt.execute(createTokenTypes);
			stmt.execute(createAudiences);
			stmt.execute(createCose);
			stmt.execute(createClaims);
			stmt.execute(createOldTokens);
			stmt.execute(createCtiCtr);
			stmt.execute(initCtiCtr);
			stmt.execute(createTokenLog);
			rootConn.close();
			stmt.close();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}


	}

	@Override
	public void wipeDB(String rootPwd) throws AceException {
		try
		{
			//Just to be sure if a previous test didn't exit cleanly
			Properties connectionProps = new Properties();
			connectionProps.put("user", ROOT_USER);
			connectionProps.put("password", rootPwd);
			Connection rootConn = DriverManager.getConnection(DEFAULT_DB_URL, connectionProps);
			String dropDB;
			if(this.dbName == null)
				dropDB = "DROP DATABASE IF EXISTS " + FedIoT_DBConnector.dbName + ";";
			else
				dropDB = "DROP DATABASE IF EXISTS " + this.dbName + ";";
			Statement stmt = rootConn.createStatement();
			stmt.execute(dropDB);
			stmt.close();
			rootConn.close();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}

	}

	@Override
	public String updateEngineSpecificSQL(String sqlQuery) {
		// Nothing to do here, as the default SQL statements in is compatible with MySQL.
		return sqlQuery;
	}

	@Override
	public String getDefaultDBURL() {
		return FedIoT_MySQLDBAdapter.DEFAULT_DB_URL;
	}

	@Override
	public String getDefaultRoot() {
		// TODO Auto-generated method stub
		return ROOT_USER;
	}

}
