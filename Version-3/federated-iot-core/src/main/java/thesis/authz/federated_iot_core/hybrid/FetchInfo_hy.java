package thesis.authz.federated_iot_core.hybrid;

import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.crypto.InvalidCipherTextException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.OneKey;
import se.sics.ace.AccessToken;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.as.DBConnector;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import thesis.authz.federated_iot_core.AuthzInfo_ma;
import thesis.authz.federated_iot_core.ConnectedAS;
import thesis.authz.federated_iot_core.Constants_ma;

public class FetchInfo_hy implements Endpoint, AutoCloseable{

	/**
	 * The logger
	 */
	private static final Logger LOGGER 
	= Logger.getLogger(FetchInfo_hy.class.getName());

	/**
	 * The time provider for this AS.
	 */
	private TimeProvider time;

	/**
	 * The default expiration time of an access token
	 */
	private static long expiration = 1000 * 60 * 10; //10 minutes
	private String asId;

	private OneKey privatekey;

	private ConnectedAS mypartners;

	private static Set<Short> defaultClaims = new HashSet<>();

	static {
		defaultClaims.add(Constants.CTI);
		defaultClaims.add(Constants.SUB);
		defaultClaims.add(Constants.ISS);
		defaultClaims.add(Constants.EXP);
		defaultClaims.add(Constants.AUD);
		defaultClaims.add(Constants.SCOPE);
		defaultClaims.add(Constants.CNF);
		defaultClaims.add(Constants.IAT);
		defaultClaims.add(Constants_ma.DEV_SCP_MAP);
	}


	private Set<Short> claims;

	/**
	 * The database connector for storing and retrieving stuff.
	 */
	private DBConnector_hy db;
	public FetchInfo_hy(String asId, OneKey privatekey, ConnectedAS partners,TimeProvider time,DBConnector_hy db) throws AceException{
		//Time for checks
		if (asId == null || asId.isEmpty()) {
			LOGGER.severe("Query endpoint's AS identifier was null or empty");
			throw new AceException(
					"AS identifier must be non-null and non-empty");
		}
		if (privatekey == null) {
			LOGGER.severe("Query endpoint's private was null");
			throw new AceException(
					"Query endpoint's private must be non-null");
		}

		if (partners == null) {
			LOGGER.severe("Query endpoint's partners was null");
			throw new AceException(
					"Query endpoint's partners must be non-null");
		}
		if (time == null) {
			LOGGER.severe("Query endpoint's TimeProvider was null");
			throw new AceException("Query endpoint's TimeProvider "
					+ "must be non-null");
		}
		if (db == null) {
			LOGGER.severe("Token_ma endpoint's DBConnector was null");
			throw new AceException(
					"Token_ma endpoint's DBConnector must be non-null");
		}


		this.asId = asId;
		this.privatekey = privatekey;
		this.mypartners = partners;
		this.claims = defaultClaims;
		this.time = time;
		this.db = db;
	}

	@Override
	public Message processMessage(Message msg) {
		//Start working from here tomorrow
		//Get the CAS_INFO from the requests
		//Generate Signed ID token with the scopes of the rs
		LOGGER.log(Level.INFO, "FetchInfo received message to fetch RS details: " + msg);

		// Get the sender id
		//In case of hybrid, it will be RPK id
		String id = msg.getSenderId();

		//Get the RS ID
		CBORObject cbor = msg.getParameter(Constants_ma.RS_ID);
		String rs_id;
		if (cbor != null && cbor.getType().equals(CBORType.TextString)) {
			rs_id = cbor.AsString();
		}
		else
		{
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, 
					" Invalid RS_ID ");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "Invalid RS_ID");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

		//Get the CAS ID
		cbor = msg.getParameter(Constants_ma.CAS_ID);
		String cas_id;
		if (cbor != null && cbor.getType().equals(CBORType.TextString)) {
			cas_id = cbor.AsString();
		}
		else
		{
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, 
					" Invalid CAS_ID ");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "Invalid CAS_ID");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

		// Check if the CAS_ID is already my connected partners.
		if(!this.mypartners.getPartners().containsKey(cas_id)) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants_ma.INVALID_TARGET);
			map.Add(Constants.ERROR_DESCRIPTION, "No CAS found for message");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "No CAS found for message");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

		//Next retreive the scopes of the RS
		Set<String> scopes;
		try {
			scopes = this.db.getRSScopes(rs_id);
		} catch (AceException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		List<String> scp_list = new ArrayList<String>(scopes);
		CBORObject devscpmap = CBORObject.NewMap();
		devscpmap.Add(rs_id, CBORObject.FromObject(scp_list));
		Map<Short, CBORObject> claims = new HashMap<>();
		//ISS SUB AUD EXP NBF IAT CTI SCOPE CNF
		for (Short c : this.claims) {
			switch (c) {
			case Constants.ISS:
				claims.put(Constants.ISS, CBORObject.FromObject(this.asId));        
				break;
			case Constants.SUB:
				claims.put(Constants.SUB, CBORObject.FromObject(id));
				break;
			case Constants.AUD:
				claims.put(Constants.AUD, CBORObject.FromObject(cas_id));
				break;
			case Constants.EXP:		//do nothing		
				break;
			case Constants.NBF:		//do nothing		
				break;
			case Constants.IAT:		//do nothing		
				break;
			case Constants.SCOPE:  //do nothing
				break;
			case Constants_ma.DEV_SCP_MAP:
				claims.put(Constants_ma.DEV_SCP_MAP, devscpmap);
				break;
			case Constants.CTI: //do nothing
				break;
			case Constants.CNF: //do nothing
				break;
			default:
				LOGGER.severe("Unknown claim type in /query "
						+ "endpoint configuration: " + c);
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			}
		}

		//Generate an ID_Token for client
		AccessToken token = null;
		try {
			token = AccessTokenFactory.generateToken(AccessTokenFactory.CWT_TYPE, claims);
		} catch (AceException e) {			
			LOGGER.severe("Message processing aborted when creating token "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		CBORObject Resp = CBORObject.NewMap();

		//Since this is an ID Token request
		//Find common crypto context with the target and not the audience
		CwtCryptoCtx ctx = null;
		try {
			//Just sign the token using the private key of this AS
			ctx = CwtCryptoCtx.sign1Create(
					this.privatekey, AlgorithmID.ECDSA_256.AsCBOR());
		} catch (Exception e) {
			LOGGER.severe("Message processing aborted when creating a signature "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		if (ctx == null) {

			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, 
					"No common security context found for audience");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "No common security context found for audience");
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, map);
		}
		CWT cwt = (CWT)token;
		try {
			Resp.Add(Constants_ma.ID_TOKEN, cwt.encode(ctx));
		} catch (IllegalStateException | InvalidCipherTextException
				| CoseException | AceException e) {

			LOGGER.severe("Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}

		LOGGER.log(Level.INFO, " ###### Returning ID Token ##### ");
		LOGGER.log(Level.INFO, cwt.toString());
		return msg.successReply(Message.CREATED, Resp);
	}

	@Override
	public void close() throws AceException {
		// TODO Auto-generated method stub

	}

}
