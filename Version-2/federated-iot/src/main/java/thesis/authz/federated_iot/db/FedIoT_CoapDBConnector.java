package thesis.authz.federated_iot.db;

import java.net.InetSocketAddress;
import java.sql.SQLException;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.dtls.pskstore.PskStore;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.KeyKeys;
import COSE.OneKey;
import se.sics.ace.AceException;

import se.sics.ace.examples.SQLDBAdapter;



public class FedIoT_CoapDBConnector extends FedIoT_SQLConnector implements PskStore{

	 /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(FedIoT_CoapDBConnector.class.getName() );
    
    /**
     * Constructor.
     *  
     * @param dbUrl  the database URL, if null the default will be used
     * @param user   the database user, if null the default will be used
     * @param pwd    the database user's password, if null the default 
     *               will be used
     *
     * @throws SQLException
     */
    public FedIoT_CoapDBConnector(String dbUrl, String user, String pwd)
            throws SQLException {
        super(dbUrl, user, pwd);

    }

    /**
     * Constructor.
     *
     * @param dbAdapter handler for engine-db specific commands.
     * @param dbUrl     the database URL, if null the default will be used
     * @param user      the database user, if null the default will be used
     * @param pwd       the database user's password, if null the default
     *                  will be used
     *
     * @throws SQLException
     */
    public FedIoT_CoapDBConnector(SQLDBAdapter dbAdapter, String dbUrl, String user, String pwd)
            throws SQLException {
        super(dbAdapter, dbUrl, user, pwd);
    }

    @Override
    public byte[] getKey(String identity) {
        OneKey key = null;
        try {
            key = super.getDevicePSK(identity);
        } catch (AceException e) {
            LOGGER.severe(e.getMessage());
            return null;
        }
        if (key == null) { //Key not found
           return null;
        }
        CBORObject val = key.get(KeyKeys.KeyType);
        if (val.equals(KeyKeys.KeyType_Octet)) {
            val = key.get(KeyKeys.Octet_K);
            if ((val== null) || (val.getType() != CBORType.ByteString)) {
                return null; //Malformed key
            }
            return val.GetByteString();
        }
        return null; //Wrong KeyType
          
        
    }

    @Override
    public String getIdentity(InetSocketAddress inetAddress) {
        return null;
    }

}
