package thesis.authz.federated_iot_core.hybrid;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import se.sics.ace.AceException;
import se.sics.ace.as.DBConnector;
import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.examples.SQLDBAdapter;

public class CoapDBConnector_hy extends CoapDBConnector implements DBConnector_hy{
	/**
     * The logger
     */	
    private static final Logger LOGGER 
        = Logger.getLogger(CoapDBConnector.class.getName() );
    
	public CoapDBConnector_hy(SQLDBAdapter dbAdapter, String dbUrl, String user, String pwd) throws SQLException {
		super(dbAdapter, dbUrl, user, pwd);
	}
	
	public CoapDBConnector_hy(String dbUrl, String user, String pwd) throws SQLException {
		super(dbUrl, user, pwd);
	}
	
	public Set<String> getRSScopes(String rs_id) throws AceException {
		String scp = null;
		Set<String> scopes = new HashSet();
		 try {
	            this.selectScopes.setString(1, rs_id);
	            ResultSet result = this.selectScopes.executeQuery();
	            this.selectScopes.clearParameters();
	            while (result.next()) {
	                scp = result.getString(DBConnector.scopeColumn);
	                scopes.add(scp);
	            }
	            result.close();
	        } catch (SQLException e) {
	            throw new AceException(e.getMessage());
	        }
		 if(scopes.size() >0)
			 return scopes;
		 else
			 return null;
	}
	
	

}
