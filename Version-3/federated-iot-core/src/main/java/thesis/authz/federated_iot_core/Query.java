package thesis.authz.federated_iot_core;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.OneKey;
import COSE.Sign1Message;
import se.sics.ace.AccessToken;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

public class Query implements ProvisionEndpoint, AutoCloseable{

	/**
	 * The logger
	 */
	private static final Logger LOGGER 
	= Logger.getLogger(Query.class.getName());


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
	}


	private Set<Short> claims;

	public Query(String asId, OneKey privatekey, ConnectedAS partners,TimeProvider time) throws AceException {
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

		this.asId = asId;
		this.privatekey = privatekey;
		this.mypartners = partners;
		this.claims = defaultClaims;
		this.time = time;
	}


	@Override
	public Message processMessage(Message msg,CoapProvisionInfo myresource) {
		// TODO Auto-generated method stub

		LOGGER.log(Level.INFO, " ##### Query endpoint received message: ##### " 
				+ msg.getParameters());

		if(msg.getParameter(Constants_ma.REQUEST_TYPE) == null) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "Null Request type");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
		}

		CBORObject cbor = msg.getParameter(Constants_ma.REQUEST_TYPE);

		LOGGER.log(Level.INFO, "Query Endpoint Received Request Type " + cbor.AsInt16());
		if(cbor.equals(CBORObject.FromObject(Constants_ma.CONNECT))) {
			return (processConnectReq(msg, myresource));
		}
		else if(cbor.equals(CBORObject.FromObject(Constants_ma.QUERY))) {
			return (processQueryReq(msg, myresource));
		}
		else {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "Invalid request type");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
		}

	}

	private Message processQueryReq(Message msg,CoapProvisionInfo myresource) {
		LOGGER.log(Level.INFO, " ##### Received Query Request: #####" 
				+ msg.getParameters());

		//Get Sender id or client id
		String id = msg.getSenderId();  

		//3. Check if the Target is there
		CBORObject cbor = msg.getParameter(Constants_ma.TAR);
		String target = null;
		if (cbor == null ) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, "No target found for message");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "No target found for message");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		} else {
			target = cbor.AsString();
		}

		// Check if the target is already my connected partners.
		if(!this.mypartners.getPartners().containsKey(target)) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants_ma.INVALID_TARGET);
			map.Add(Constants.ERROR_DESCRIPTION, "No target found for message");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "No target found for message");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

		// Check if Audience is there.
		cbor = msg.getParameter(Constants.AUD);	
		String aud = null;
		//Set<String> aud = new HashSet<>();

		if(cbor == null || !cbor.getType().equals(CBORType.TextString)) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, 
					"Audience malformed");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "Audience malformed");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);			
		}
		aud = cbor.AsString();


		//Check the provisioning type of the client.
		//If client is provisioned with asymmetric model, then we can trust the RS scopes sent by the client.
		//If client is provisioned with hybrid model, then it requires ID_Token signed by AS where RS belongs
		//3. Check if the Target is there
		cbor = msg.getParameter(Constants_ma.PROVISION_TYPE);
		if (cbor == null ) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, "No provision type found for message");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "No provision type found for message");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

		if(!cbor.getType().equals(CBORType.Number)) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, " Malformed provision type value ");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "Malformed provision type value");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

		CBORObject scopes = null;
		if(cbor.AsInt16() == Constants_ma.ASYMMETRIC) {
			//Take decision based on scopes sent by client

			//Right now we do not implement any PDP
			//So just trust what client sents and sent it back
			cbor = msg.getParameter(Constants.SCOPE);
			if(!cbor.getType().equals(CBORType.TextString)) {
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
				map.Add(Constants.ERROR_DESCRIPTION, " Malformed Scope value ");
				LOGGER.log(Level.INFO, "Message processing aborted: "
						+ "Malformed scope value");
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
			scopes = cbor;
		}
		else if(cbor.AsInt16() == Constants_ma.HYBRID) {
			//Take decision based on scopes present in ID_Token
			// Get the ID Token
			CBORObject ID_TOKEN = msg.getParameter(Constants_ma.ID_TOKEN);
			COSE.Message idtoken_rawmessage;
			//Signed COSE are always of type array
			if(ID_TOKEN.getType().equals(CBORType.Array)) {
				idtoken_rawmessage = null;
				try {
					idtoken_rawmessage = COSE.Message.DecodeFromBytes(ID_TOKEN.EncodeToBytes());
				} catch (CoseException e3) {
					LOGGER.severe(" Corrupted ID Token "
							+ e3.getMessage());
					return msg.failReply(Message.FAIL_BAD_REQUEST, null);
				}
			}
			else {
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
				map.Add(Constants.ERROR_DESCRIPTION,"ID Token not of type CBORType.Array");
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
			String Iss = null;
			if (idtoken_rawmessage instanceof Sign1Message) {
				Sign1Message signed = (Sign1Message)idtoken_rawmessage;

				//First get the raw token with signature
				CWT IDtoken_cwt = null;
				try {
					IDtoken_cwt = new CWT(Constants.getParams(
							CBORObject.DecodeFromBytes(signed.GetContent())));
				} catch (AceException e2) {
					LOGGER.severe(" Corrupted ID Token "
							+ e2.getMessage());
					return msg.failReply(Message.FAIL_BAD_REQUEST, null);
				}
				//Get the Issuer of the Token
				Iss = IDtoken_cwt.getClaim(Constants.ISS).AsString();

				OneKey publicKey= null;
				try {
					publicKey = this.mypartners.getPublicKey(Iss);
				} catch (Exception e1) {
					LOGGER.severe(" Cannot Get the Verification key for " + Iss 
							+ e1.getMessage());
					return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
				}
				if(publicKey == null) {
					LOGGER.severe(" Cannot Get the Verification key for " + Iss );
					return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
				}

				CwtCryptoCtx ctx = CwtCryptoCtx.sign1Verify(publicKey, AlgorithmID.ECDSA_256.AsCBOR());

				try {
					IDtoken_cwt = CWT.processCOSE(ID_TOKEN.EncodeToBytes(), ctx);
				} catch (Exception e) {
					CBORObject map = CBORObject.NewMap();
					map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
					LOGGER.severe("##### ID_TOKEN VERIFICATION FAILED ##### ");
					LOGGER.severe("ID TOKEN ISSUED BY "+ Iss);
					LOGGER.severe(e.getMessage());
					return msg.failReply(Message.FAIL_BAD_REQUEST, map);
				}

				//Check if the issuer is same as the target that client queried for
				
				if(!Iss.equals(target)) {
					CBORObject map = CBORObject.NewMap();
					map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
					LOGGER.severe(" Mismatch in Issuer of the token with Query Target. Token issued by " + Iss);
					return msg.failReply(Message.FAIL_BAD_REQUEST, map);
				}
				//If the signature validation is success
				//Then check the sub claim agains the sender id
				String sub = IDtoken_cwt.getClaim(Constants.SUB).AsString();
				if(!sub.equals(id)) {

					CBORObject map = CBORObject.NewMap();
					map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
					LOGGER.severe(" Mismatch in Sub Claim and Sender Id for Token issued by " + Iss);
					return msg.failReply(Message.FAIL_BAD_REQUEST, map);
				}
				LOGGER.log(Level.INFO, "#### ID_TOKEN VALIDATION SUCCESS ####");
				//Get the rs id scopes map present in the ID_TOken
				CBORObject rsidscpmap = IDtoken_cwt.getClaim(Constants_ma.DEV_SCP_MAP);

				if(rsidscpmap.getType().equals(CBORType.Map)) {
					if(rsidscpmap.ContainsKey(CBORObject.FromObject(aud))){
						scopes = rsidscpmap.get(CBORObject.FromObject(aud));
						StringBuilder tmp = new StringBuilder();
						for (int i=0; i<scopes.size(); i++) {
							CBORObject scp = scopes.get(i);
							tmp.append(scp.AsString());
							tmp.append(" ");
						}
						scopes = CBORObject.FromObject(tmp.toString().trim());						
						//After retreiving the scopes..
						//Just return it to the client, because we are not implementing any PDP for now
					}					
				}
				else {
					CBORObject map = CBORObject.NewMap();
					map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
					map.Add(Constants.ERROR_DESCRIPTION,"ID Token not of type Map");
					return msg.failReply(Message.FAIL_BAD_REQUEST, map);
				}
			}
			else {
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
				map.Add(Constants.ERROR_DESCRIPTION,"ID Token not of type COSE Sign1");
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
		}
		else {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, " Invalid provision type value ");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "Invalid provision type value");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

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
				//Since for an ID_Token the audience is always an another AS or CAS
				//Put the first entry of the audience parameter which should always be another AS or CAS
				claims.put(Constants.AUD, CBORObject.FromObject(target));

				break;
			case Constants.EXP:
				long now = this.time.getCurrentTime();
				long exp = Long.MAX_VALUE;

				//using default
				exp = now + expiration;

				claims.put(Constants.EXP, CBORObject.FromObject(exp));
				break;
			case Constants.NBF:
				//XXX: NBF is not configurable in this version
				now = this.time.getCurrentTime();
				claims.put(Constants.NBF, CBORObject.FromObject(now));
				break;
			case Constants.IAT:
				now = this.time.getCurrentTime();
				claims.put(Constants.IAT, CBORObject.FromObject(now));
				break;
			case Constants.SCOPE: //do nothing
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
		try {/*
			@SuppressWarnings("unchecked")
			Map<String, Object> target_cose = (Map<String, Object>)this.targets.get(target);
			COSEparams cose = null;
			cose = (COSEparams)target_cose.get("coseparams");

			CBORObject key = (CBORObject)target_cose.get("sign_key");

			OneKey privateKey = null;
			privateKey = new OneKey(key);*/

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
			Resp.Add(Constants.SCOPE, scopes);
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

	private Message processConnectReq(Message msg,CoapProvisionInfo myresource) {
		// TODO Auto-generated method stub
		LOGGER.log(Level.INFO, " ##### Received Connect Request: #####" 
				+ msg.getParameters());

		//Get Sender id or client id
		String id = msg.getSenderId();  

		//3. Check if the Target is there
		CBORObject cbor = msg.getParameter(Constants_ma.TAR);
		String target = null;
		if (cbor == null ) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, "No target found for message");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "No target found for message");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		} else {
			target = cbor.AsString();
		}
		LOGGER.log(Level.INFO, " ### Printing Target ### " + target );

		CBORObject result = CBORObject.NewMap();
		//check if target is already connected
		//if connected just send its rootca
		if(this.mypartners.getPartners().containsKey(target)) {
			Certificate rootca = this.mypartners.getRootCertificate(target);			
			byte[] rootcabytes = null;
			try {
				rootcabytes = rootca.getEncoded();
			} catch (CertificateEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			result.Add(Constants_ma.ROOT_CERT, CBORObject.FromObject(rootcabytes));
			LOGGER.log(Level.INFO, " ###### Returning ROOTCA CERT to CLIENT ##### ");
			return msg.successReply(Message.CREATED, result);

		}

		else {
			LOGGER.log(Level.INFO, " ### Target not already present in mypartners ### " + target );
			CBORObject map1 = CBORObject.NewMap();	
			map1.Add(Constants.ERROR, " Target cannot be connected or error in connection");
			map1.Add(Constants.ERROR_DESCRIPTION, "Target is not present in mypartners error in connection");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "Target connection error");
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, map1);


			/*
			cbor = msg.getParameter(Constants_ma.CONNECT_ENDPOINT);
			String toconnect = null;
			if (cbor == null ) {
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
				map.Add(Constants.ERROR_DESCRIPTION, "No connect endpoint found message");
				LOGGER.log(Level.INFO, "Message processing aborted: "
						+ "No connect endpoint found for message");
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			} else {
				toconnect = cbor.AsString();
			}			
			LOGGER.log(Level.INFO, " ### toconnect endpoint ### " + toconnect );
			//if not present then send a connect request
			try {
				DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(0));
				//builder.setAddress(new InetSocketAddress(0));

				builder.setIdentity((PrivateKey)myresource.getServer().getkeyStore().getKey(
						myresource.getServer().getalias(), 
						myresource.getServer().getkeystorepassword().toCharArray()),
						myresource.getServer().getkeyStore().getCertificateChain(
								myresource.getServer().getalias()), false);

				builder.setTrustStore(myresource.getServer().getCurrentturstedCertificateList());
				builder.setClientOnly();
				builder.setSupportedCipherSuites(new CipherSuite[]{
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});


				DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
				CoapEndpoint e = new CoapEndpoint(dtlsConnector, NetworkConfig.getStandard());
				CoapClient client = new CoapClient();
				// see https://github.com/eclipse/californium/issues/235
				client.setTimeout(30000);
				client.setEndpoint(e);
				dtlsConnector.start();

				client.setURI(toconnect);				
				CBORObject connectparam = CBORObject.NewMap();			
				Certificate certificate;
				certificate = myresource.getServer().gettrustStore().getCertificate(
						myresource.getServer().getrootalias());

				byte[] rootcertbytes = certificate.getEncoded();				
				OneKey pubkey = this.privatekey.PublicKey();
				byte[] mypubkeybytes = pubkey.EncodeToBytes();

				connectparam.Add(Constants_ma.PUBLIC_KEY, CBORObject.FromObject(mypubkeybytes));
				connectparam.Add(Constants_ma.ROOT_CERT, CBORObject.FromObject(rootcertbytes));

				LOGGER.log(Level.INFO, " ### sending post request to endpoint ### " + toconnect );

				CoapResponse response = client.post(
						connectparam.EncodeToBytes(), 
						MediaTypeRegistry.APPLICATION_CBOR);  			

				CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
				Map<Short, CBORObject> rmap = Constants.getParams(res);


				//Get the public key from the connect request
				cbor = rmap.get(Constants_ma.PUBLIC_KEY);
				OneKey pub = null;
				if (cbor.getType().equals(CBORType.ByteString)) {
					byte[] publicKeyBytes = cbor.GetByteString();
					try {
						CBORObject receivedpubkey = CBORObject.DecodeFromBytes(publicKeyBytes);
						pub = new OneKey(receivedpubkey);

					} catch (Exception e1) {
						LOGGER.severe("Message processing aborted: "
								+ e1.getMessage());
						return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
					}
				}
				else {
					CBORObject map = CBORObject.NewMap();			
					map.Add(Constants.ERROR_DESCRIPTION, "Invalid format of public key parameter");
					LOGGER.log(Level.INFO, "Message processing aborted: "
							+ "Invalid format of public key");
					return msg.failReply(Message.FAIL_UNSUPPORTED_CONTENT_FORMAT, map);
				}

				//Get the RootCA Certificate from connect request
				cbor = msg.getParameter(Constants_ma.ROOT_CERT);
				X509Certificate cert = null;
				if (cbor.getType().equals(CBORType.ByteString)) {
					byte[] certbytes = cbor.GetByteString();

					try {
						CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
						InputStream in = new ByteArrayInputStream(certbytes);
						cert = (X509Certificate)certFactory.generateCertificate(in);

					} catch (CertificateException e1) {
						LOGGER.severe("Message processing aborted: "
								+ e1.getMessage());
						return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
					}
				}
				else {
					CBORObject map = CBORObject.NewMap();			
					map.Add(Constants.ERROR_DESCRIPTION, "Invalid format of certificate parameter");
					LOGGER.log(Level.INFO, "Message processing aborted: "
							+ "Invalid format of Certificate");
					return msg.failReply(Message.FAIL_UNSUPPORTED_CONTENT_FORMAT, map);
				}

				if(pub != null && cert != null) {
					Map<Short, Object> map = new HashMap<Short, Object>();
					map.put(Constants_ma.PUBLIC_KEY, pub);
					map.put(Constants_ma.ROOT_CERT, cert);
					this.mypartners.addPartner(target, map);

					result = CBORObject.NewMap();
					byte[] rootcabytes = cert.getEncoded();
					result.Add(Constants_ma.ROOT_CERT, CBORObject.FromObject(rootcabytes));
					LOGGER.log(Level.INFO, " ###### Returning ROOTCA CERT to CLIENT ##### ");
					return msg.successReply(Message.CREATED, result);
				}
				else {
					return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
				}
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.getMessage();
				return msg.failReply(Message.FAIL_UNSUPPORTED_CONTENT_FORMAT, null);
			}		
			 */
		}

	}


	@Override
	public void close() throws AceException {
		// TODO Auto-generated method stub

	}

}
