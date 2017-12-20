package thesis.authz.federated_iot_core.hybrid;

import java.util.Set;

import se.sics.ace.AceException;
import se.sics.ace.as.DBConnector;

public interface DBConnector_hy extends DBConnector{

	  public Set<String> getRSScopes(String rs_id) throws AceException;
}
