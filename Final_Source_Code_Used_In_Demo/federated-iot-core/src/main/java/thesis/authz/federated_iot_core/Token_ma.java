package thesis.authz.federated_iot_core;

import java.net.InetSocketAddress;

/*******************************************************************************
 * Copyright (c) 2017, RISE SICS AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import COSE.Recipient;
import COSE.Sign1Message;
import se.sics.ace.AccessToken;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.as.DBConnector;
import se.sics.ace.as.PDP;
import se.sics.ace.AceException;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * Implements the /token endpoint on the authorization server.
 * 
 * Note: If a client requests a scope that is not supported by (parts) of the 
 * audience this endpoint will just ignore that, assuming that the client will
 * be denied by the PDP anyway. This requires a default deny policy in the PDP.
 * 
 * Note: This endpoint assigns a cti to each issued token based on a counter. 
 * The same value is also used as kid for the proof-of-possession key
 * associated to the token by means of the 'cnf' claim.
 * 
 * @author Ludwig Seitz
 *
 */
public class Token_ma implements Endpoint, AutoCloseable {

	/**
	 * The logger
	 */
	private static final Logger LOGGER 
	= Logger.getLogger(Token_ma.class.getName());

	/**
	 * The PDP this endpoint uses to make access control decisions.
	 */
	private PDP pdp;

	/**
	 * The database connector for storing and retrieving stuff.
	 */
	private DBConnector db;

	/**
	 * The identifier of this AS for the iss claim.
	 */
	private String asId;

	/**
	 * The time provider for this AS.
	 */
	private TimeProvider time;

	/**
	 * The default expiration time of an access token
	 */
	private static long expiration = 1000 * 60 * 10; //10 minutes

	/**
	 * The counter for generating the cti
	 */
	private Long cti = 0L;

	/**
	 * The private key of the AS or null if there isn't any
	 */
	private OneKey privateKey;

	/**
	 * The client credentials grant type as CBOR-string
	 */
	public static CBORObject clientCredentials 
	= CBORObject.FromObject(Constants.GT_CLI_CRED);

	/**
	 * Converter to create the byte array from the cti number
	 */
	private static ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);

	/**
	 * The claim types included in tokens generated by this Token_ma instance
	 */
	private Set<Short> claims;

	Map<String,String> mydevices;
	private ConnectedAS partners;

	private static Set<Short> defaultClaims = new HashSet<>();

	Certificate[] mychain;
	Certificate[] mytrustanchor;

	private Map<String,Boolean> updatedRs;


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

	/**
	 * Constructor using default set of claims.
	 * 
	 * @param asId  the identifier of this AS
	 * @param pdp   the PDP for deciding access
	 * @param db  the database connector
	 * @param time  the time provider
	 * @param privateKey  the private key of the AS or null if there isn't any
	 * 
	 * @throws AceException  if fetching the cti from the database fails
	 */
	public Token_ma(String asId, PDP pdp, DBConnector db, 
			TimeProvider time, OneKey privateKey, ConnectedAS partners,Map<String,String> mydevices,Certificate[] chain, Certificate[] trustanchor) throws AceException {
		this(asId, pdp, db, time, privateKey, defaultClaims, partners, mydevices,chain,trustanchor);
	}

	/**
	 * Constructor that allows configuration of the claims included in the token.
	 *  
	 * @param asId  the identifier of this AS
	 * @param pdp   the PDP for deciding access
	 * @param db  the database connector
	 * @param time  the time provider
	 * @param privateKey  the private key of the AS or null if there isn't any
	 * @param claims  the claim types to include in tokens issued by this 
	 *                Token_ma instance
	 * 
	 * @throws AceException  if fetching the cti from the database fails
	 */
	public Token_ma(String asId, PDP pdp, DBConnector db, 
			TimeProvider time, OneKey privateKey, Set<Short> claims, ConnectedAS partners,Map<String,String> mydevices,Certificate[] chain, Certificate[] trustanchor) throws AceException {     
		//Time for checks
		if (asId == null || asId.isEmpty()) {
			LOGGER.severe("Token_ma endpoint's AS identifier was null or empty");
			throw new AceException(
					"AS identifier must be non-null and non-empty");
		}
		if (pdp == null) {
			LOGGER.severe("Token_ma endpoint's PDP was null");
			throw new AceException(
					"Token_ma endpoint's PDP must be non-null");
		}
		if (db == null) {
			LOGGER.severe("Token_ma endpoint's DBConnector was null");
			throw new AceException(
					"Token_ma endpoint's DBConnector must be non-null");
		}
		if (time == null) {
			LOGGER.severe("Token_ma endpoint's TimeProvider was null");
			throw new AceException("Token_ma endpoint's TimeProvider "
					+ "must be non-null");
		}
		//All checks passed
		this.asId = asId;
		this.pdp = pdp;
		this.db = db;
		this.time = time;
		this.privateKey = privateKey;
		this.cti = db.getCtiCounter();
		this.claims = new HashSet<>();
		this.claims.addAll(claims);
		this.partners = partners;
		this.mydevices = mydevices;
		this.mychain = chain;
		this.mytrustanchor = trustanchor;
		this.updatedRs = new HashMap<String,Boolean>();
	}
	/*
	 * HYBRID INTERDOMAIN TOKEN REQUEST
	 */
	private Message processHybridInterDomainRequest(Message msg) {
		LOGGER.log(Level.INFO, " ##### Received Hybrid inter domain token Request: #####" 
				+ msg.getParameters());
		//Get sender id
		String id = msg.getSenderId();  

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
				publicKey = this.partners.getPublicKey(Iss);
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

			//If the signature validation is success
			//Then check the sub claim agains the sender id

			String sub = IDtoken_cwt.getClaim(Constants.SUB).AsString();
			if(!sub.equals(id)) {

				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
				LOGGER.severe(" Mismatch in Sub Claim and Sender Id for Token issued by " + Iss);
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}

			//Check if this token in intended to me, check the aud
			String aud = IDtoken_cwt.getClaim(Constants.AUD).AsString();
			if(!aud.equals(this.asId)) {

				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
				LOGGER.severe(" Mismatch in Aud Claim and AS ID for Token issued by " + Iss);
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}

			LOGGER.log(Level.INFO, "#### ID_TOKEN VALIDATION SUCCESS ####");
			//TODO
			//Check for validity of token, like issued at and expiration
		}
		else {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION,"ID Token not of type COSE Sign1");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}
		//3. Check if the request has a scope
		CBORObject cbor = msg.getParameter(Constants.SCOPE);
		String scope = null;
		if (cbor == null ) {
			LOGGER.severe("Message processing aborted: Scopes is null");
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		else {
			scope = cbor.AsString();
		}
		if (scope == null) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, "No scope found for message");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "No scope found for message");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

		//4. Check if the request has an audience or if there is a default aud
		cbor = msg.getParameter(Constants.AUD);
		Set<String> aud = new HashSet<>();
		if (cbor == null) {			
			LOGGER.severe("Message processing aborted: Audience is null");
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		else {
			if (cbor.getType().equals(CBORType.Array)) {
				for (int i=0; i<cbor.size(); i++) {
					CBORObject audE = cbor.get(i);
					if (audE.getType().equals(CBORType.TextString)) {
						aud.add(audE.AsString());
					} //XXX: Silently skip non-text string audiences
				}
			} else if (cbor.getType().equals(CBORType.TextString)) {
				aud.add(cbor.AsString()); 
			} else {//error
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
				map.Add(Constants.ERROR_DESCRIPTION, 
						"Audience malformed");
				LOGGER.log(Level.INFO, "Message processing aborted: "
						+ "Audience malformed");
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
		}
		if (aud.isEmpty()) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, 
					"No audience found for message");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "No audience found for message");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}


		//5. Check if the scope is allowed
		String allowedScopes = null;
		try {
			allowedScopes = this.pdp.canAccess(msg.getSenderId(), aud, scope);
		} catch (AceException e) {
			LOGGER.severe("Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		if (allowedScopes == null) {	
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "invalid_scope");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}		

		byte[] ctiB = buffer.putLong(0, this.cti).array();
		String ctiStr = Base64.getEncoder().encodeToString(ctiB);
		this.cti++;

		Map<Short, CBORObject> claims = new HashMap<>();
		//ISS SUB AUD EXP NBF IAT CTI SCOPE CNF
		for (Short c : this.claims) {
			switch (c) {
			case Constants.ISS:
				claims.put(Constants.ISS, CBORObject.FromObject(this.asId));        
				break;
			case Constants.SUB: // For Hybrid, we know that client is going to use DTLS_PSK to RS. So put the subject claim
				// as PSK KEY ID TOO. Go to CNF claim section where SUB claim is added.
				//claims.put(Constants.SUB, CBORObject.FromObject(id));
				break;
			case Constants.AUD:
				//Check if AUD is a singleton
				if (aud.size() == 1) {
					claims.put(Constants.AUD, CBORObject.FromObject(
							aud.iterator().next()));
				} else {
					claims.put(Constants.AUD, CBORObject.FromObject(aud));
				}
				break;
			case Constants.EXP:
				long now = this.time.getCurrentTime();
				long exp = now + expiration;				
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
			case Constants.CTI:
				claims.put(Constants.CTI, CBORObject.FromObject(ctiB));
				break;
			case Constants.SCOPE:
				claims.put(Constants.SCOPE, 
						CBORObject.FromObject(allowedScopes));
				break;
			case Constants.CNF:
				//We need CNF for Hybrid
				//Right now for HYBRID we are only using symmetric pop keys
				try {
					KeyGenerator kg = KeyGenerator.getInstance("AES");
					SecretKey key = kg.generateKey();
					CBORObject keyData = CBORObject.NewMap();
					keyData.Add(KeyKeys.KeyType.AsCBOR(), 
							KeyKeys.KeyType_Octet);
					keyData.Add(KeyKeys.Octet_K.AsCBOR(), 
							CBORObject.FromObject(key.getEncoded()));
					//Note: kid is the same as cti 
					byte[] kid = ctiB;               
					keyData.Add(KeyKeys.KeyId.AsCBOR(), kid);

					OneKey psk = new OneKey(keyData);
					CBORObject coseKey = CBORObject.NewMap();
					coseKey.Add(Constants.COSE_KEY, psk.AsCBOR());
					claims.put(Constants.CNF, coseKey);
					
					 CBORObject cborsub = CBORObject.NewMap();
				        cborsub.Add(KeyKeys.KeyId.AsCBOR(), kid);
				        String subject = Base64.getEncoder().encodeToString(
				        		cborsub.EncodeToBytes());
					claims.put(Constants.SUB, CBORObject.FromObject(subject));
				} catch (NoSuchAlgorithmException | CoseException e) {
					this.cti--; //roll-back
					LOGGER.severe("Message processing aborted: "
							+ e.getMessage());
					return msg.failReply(
							Message.FAIL_INTERNAL_SERVER_ERROR, null);
				}       

				break;
			default:
				LOGGER.severe("Unknown claim type in /token "
						+ "endpoint configuration: " + c);
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			}
		}		
		AccessToken token = null;
		try {
			token = AccessTokenFactory.generateToken(AccessTokenFactory.CWT_TYPE, claims);
		} catch (AceException e) {
			this.cti--; //roll-back
			LOGGER.severe("Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		CBORObject rsInfo = CBORObject.NewMap();

		//For PSK POP key send the psk key as part of rsinfo
		rsInfo.Add(Constants.CNF, claims.get(Constants.CNF));

		if (!allowedScopes.equals(scope)) {
			rsInfo.Add(Constants.SCOPE, CBORObject.FromObject(allowedScopes));
		}

		if (token instanceof CWT) {

			CwtCryptoCtx ctx = null;
			try {
				ctx = makeCommonCtx(aud);
			} catch (AceException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			} catch (CoseException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			}
			if (ctx == null) {
				this.cti--; //roll-back
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, 
						"No common security context found for audience");
				LOGGER.log(Level.INFO, "Message processing aborted: "
						+ "No common security context found for audience");
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, map);
			}
			CWT cwt = (CWT)token;

			try {
				rsInfo.Add(Constants.ACCESS_TOKEN, cwt.encode(ctx));
			} catch (IllegalStateException | InvalidCipherTextException
					| CoseException | AceException e) {
				this.cti--; //roll-back
				LOGGER.severe("Message processing aborted: "
						+ e.getMessage());
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			}
			LOGGER.log(Level.INFO, "##### Returning Access Token #####");
			LOGGER.log(Level.INFO, cwt.toString());
		} else {
			rsInfo.Add(Constants.ACCESS_TOKEN, token.encode());
		}

		try {
			this.db.addToken(ctiStr, claims);
			this.db.addCti2Client(ctiStr, id);
			this.db.saveCtiCounter(this.cti);
		} catch (AceException e) {
			this.cti--; //roll-back
			LOGGER.severe("Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}

		LOGGER.log(Level.INFO, " Access Token Identifier " + ctiStr);

		//In hybrid we dont need to send an update of the client root certificate to the rs
		//Authentication happens via pop key
		/*
		//Before sending reply to client, send update to the rs with the root cert of client domain.
		//this way rs can authenticate the client during resource access
		try {
			//Send update if its not sent already
			if(!this.updatedRs.containsKey(aud+Iss))
				sendUpdate(aud,id,Iss);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/

		return msg.successReply(Message.CREATED, rsInfo);

	}

	/*
	 * ASYMMETRIC INTERDOMAIN TOKEN REQUEST
	 */
	private Message processAsymmetricInterdomainRequest(Message msg) {
		LOGGER.log(Level.INFO, " ##### Received Asymmetric inter domain token Request: #####" 
				+ msg.getParameters());
		//Get sender id
		String id = msg.getSenderId();  

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
				publicKey = this.partners.getPublicKey(Iss);
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

			//If the signature validation is success
			//Then check the sub claim agains the sender id

			String sub = IDtoken_cwt.getClaim(Constants.SUB).AsString();
			if(!sub.equals(id)) {

				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
				LOGGER.severe(" Mismatch in Sub Claim and Sender Id for Token issued by " + Iss);
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
			//Check if this token in intended to me, check the aud
			String aud = IDtoken_cwt.getClaim(Constants.AUD).AsString();
			if(!aud.equals(this.asId)) {

				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
				LOGGER.severe(" Mismatch in Aud Claim and AS ID for Token issued by " + Iss);
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
			LOGGER.log(Level.INFO, "#### ID_TOKEN VALIDATION SUCCESS ####");
			//TODO
			//Check for validity of token, like issued at and expiration
		}
		else {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION,"ID Token not of type COSE Sign1");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}
		//3. Check if the request has a scope
		CBORObject cbor = msg.getParameter(Constants.SCOPE);
		String scope = null;
		if (cbor == null ) {
			LOGGER.severe("Message processing aborted: Scopes is null");
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		else {
			scope = cbor.AsString();
		}
		if (scope == null) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, "No scope found for message");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "No scope found for message");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

		//4. Check if the request has an audience or if there is a default aud
		cbor = msg.getParameter(Constants.AUD);
		Set<String> aud = new HashSet<>();
		if (cbor == null) {			
			LOGGER.severe("Message processing aborted: Audience is null");
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		else {
			if (cbor.getType().equals(CBORType.Array)) {
				for (int i=0; i<cbor.size(); i++) {
					CBORObject audE = cbor.get(i);
					if (audE.getType().equals(CBORType.TextString)) {
						aud.add(audE.AsString());
					} //XXX: Silently skip non-text string audiences
				}
			} else if (cbor.getType().equals(CBORType.TextString)) {
				aud.add(cbor.AsString()); 
			} else {//error
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
				map.Add(Constants.ERROR_DESCRIPTION, 
						"Audience malformed");
				LOGGER.log(Level.INFO, "Message processing aborted: "
						+ "Audience malformed");
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
		}
		if (aud.isEmpty()) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, 
					"No audience found for message");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "No audience found for message");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}


		//5. Check if the scope is allowed
		String allowedScopes = null;
		try {
			allowedScopes = this.pdp.canAccess(msg.getSenderId(), aud, scope);
		} catch (AceException e) {
			LOGGER.severe("Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		if (allowedScopes == null) {	
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "invalid_scope");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}		

		byte[] ctiB = buffer.putLong(0, this.cti).array();
		String ctiStr = Base64.getEncoder().encodeToString(ctiB);
		this.cti++;

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
				//Check if AUD is a singleton
				if (aud.size() == 1) {
					claims.put(Constants.AUD, CBORObject.FromObject(
							aud.iterator().next()));
				} else {
					claims.put(Constants.AUD, CBORObject.FromObject(aud));
				}
				break;
			case Constants.EXP:
				long now = this.time.getCurrentTime();
				long exp = now + expiration;				
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
			case Constants.CTI:
				claims.put(Constants.CTI, CBORObject.FromObject(ctiB));
				break;
			case Constants.SCOPE:
				claims.put(Constants.SCOPE, 
						CBORObject.FromObject(allowedScopes));
				break;
			case Constants.CNF:
				// We dont need CNF for asymmetric. Because we are using bearer token						
				break;
			default:
				LOGGER.severe("Unknown claim type in /token "
						+ "endpoint configuration: " + c);
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			}
		}		
		AccessToken token = null;
		try {
			token = AccessTokenFactory.generateToken(AccessTokenFactory.CWT_TYPE, claims);
		} catch (AceException e) {
			this.cti--; //roll-back
			LOGGER.severe("Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		CBORObject rsInfo = CBORObject.NewMap();


		if (!allowedScopes.equals(scope)) {
			rsInfo.Add(Constants.SCOPE, CBORObject.FromObject(allowedScopes));
		}

		if (token instanceof CWT) {

			CwtCryptoCtx ctx = null;
			//ctx = makeCommonCtx(aud);
			ctx = CwtCryptoCtx.sign1Create(
					this.privateKey, AlgorithmID.ECDSA_256.AsCBOR());
			if (ctx == null) {
				this.cti--; //roll-back
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, 
						"No common security context found for audience");
				LOGGER.log(Level.INFO, "Message processing aborted: "
						+ "No common security context found for audience");
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, map);
			}
			CWT cwt = (CWT)token;

			try {
				rsInfo.Add(Constants.ACCESS_TOKEN, cwt.encode(ctx));
			} catch (IllegalStateException | InvalidCipherTextException
					| CoseException | AceException e) {
				this.cti--; //roll-back
				LOGGER.severe("Message processing aborted: "
						+ e.getMessage());
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			}
			LOGGER.log(Level.INFO, "##### Returning Access Token #####");
			LOGGER.log(Level.INFO, cwt.toString());
		} else {
			rsInfo.Add(Constants.ACCESS_TOKEN, token.encode());
		}

		try {
			this.db.addToken(ctiStr, claims);
			this.db.addCti2Client(ctiStr, id);
			this.db.saveCtiCounter(this.cti);
		} catch (AceException e) {
			this.cti--; //roll-back
			LOGGER.severe("Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}

		LOGGER.log(Level.INFO, " Access Token Identifier " + ctiStr);

		//Before sending reply to client, send update to the rs with the root cert of client domain.
		//this way rs can authenticate the client during resource access
		try {
			//Send update if its not sent already
			if(!this.updatedRs.containsKey(aud+Iss))
				sendUpdate(aud,id,Iss);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		Scanner kbd = new Scanner (System.in);
		System.out.println("Smoke Detector is trying to access the Hue Bridge to indicate exit during fire. Do you allow (yes/no) ?");

        String decision = kbd.nextLine();

        switch(decision){
        case "yes":
             break;
        case "no": 
        	CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
			map.Add(Constants.ERROR_DESCRIPTION, " Requested denied by user");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ " Request denied by user");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        default : 
        	map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
			map.Add(Constants.ERROR_DESCRIPTION, " Requested denied by user");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ " Request denied by user");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
		return msg.successReply(Message.CREATED, rsInfo);
	}

	private void sendUpdate(Set<String> aud, String id, String target) throws Exception {
		Certificate root_cert = this.partners.getRootCertificate(target);
		CBORObject result = CBORObject.NewMap();
		byte[] rootcabytes = null;
		try {
			rootcabytes = root_cert.getEncoded();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		result.Add(Constants_ma.ROOT_CERT, CBORObject.FromObject(rootcabytes));

		for(String aude:aud) {
			String uri = this.mydevices.get(aude);
			String updateuri = uri;
			CoapClient c = new CoapClient();


			DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(0));
			//builder.setAddress(new InetSocketAddress(this.sport));		
			builder.setIdentity(this.privateKey.AsPrivateKey(),
					this.mychain, false);
			builder.setTrustStore(this.mytrustanchor);
			builder.setSupportedCipherSuites(new CipherSuite[]{
					CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
			});
			DTLSConnector connector= new DTLSConnector(builder.build());				
			CoapEndpoint e = new CoapEndpoint(connector, NetworkConfig.getStandard());

			c.setEndpoint(e);
			c.setURI(updateuri);
			CoapResponse response = c.post(
					result.EncodeToBytes(), 
					MediaTypeRegistry.APPLICATION_CBOR);
			//The RS will send a response only if something goes wrong
			//if everything goes well it will not send any response.
			if(response != null && response.getCode() != ResponseCode.CREATED) {
				LOGGER.log(Level.INFO, aude + " Not updated with Root CERT . Received " + response.getCode());
			}
			else
				this.updatedRs.put(aud+target, true); // updated with root certificate of other domain
		}
	}

	@Override
	public Message processMessage(Message msg) {
		LOGGER.log(Level.INFO, " ##### Token endpoint received message: ##### " 
				+ msg.getParameters());

		CBORObject granttype = msg.getParameter(Constants.GRANT_TYPE);

		//Check if its an inter domain access token request
		if(granttype.equals(CBORObject.FromObject(Constants_ma.ASYMMETRIC))) {
			return processAsymmetricInterdomainRequest(msg);
		}
		if(granttype.equals(CBORObject.FromObject(Constants_ma.HYBRID))) {
			return processHybridInterDomainRequest(msg);
		}

		LOGGER.log(Level.INFO, "##### Received Intra Domain Access Token Request: #####" 
				+ msg.getParameters());

		//1. Check that this is a client credentials grant type    
		if (msg.getParameter(Constants.GRANT_TYPE) == null 
				|| !msg.getParameter(Constants.GRANT_TYPE)
				.equals(clientCredentials)) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.UNSUPPORTED_GRANT_TYPE);
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "unsupported_grant_type");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
		}

		//2. Check if this client can request tokens
		String id = msg.getSenderId();  
		try {
			if (!this.pdp.canAccessToken(id)) {
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
				LOGGER.log(Level.INFO, "Message processing aborted: "
						+ "unauthorized client: " + id);
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
		} catch (AceException e) {
			LOGGER.severe("Database error: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}

		//3. Check if the request has a scope
		CBORObject cbor = msg.getParameter(Constants.SCOPE);
		String scope = null;
		if (cbor == null ) {
			try {
				scope = this.db.getDefaultScope(id);
			} catch (AceException e) {
				LOGGER.severe("Message processing aborted: "
						+ e.getMessage());
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			}
		} else {
			scope = cbor.AsString();
		}
		if (scope == null) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, "No scope found for message");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "No scope found for message");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

		//4. Check if the request has an audience or if there is a default aud
		cbor = msg.getParameter(Constants.AUD);
		Set<String> aud = new HashSet<>();
		if (cbor == null) {
			try {
				String dAud = this.db.getDefaultAudience(id);
				if (dAud != null) {
					aud.add(dAud);
				}
			} catch (AceException e) {
				LOGGER.severe("Message processing aborted: "
						+ e.getMessage());
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			}
		} else {
			if (cbor.getType().equals(CBORType.Array)) {
				for (int i=0; i<cbor.size(); i++) {
					CBORObject audE = cbor.get(i);
					if (audE.getType().equals(CBORType.TextString)) {
						aud.add(audE.AsString());
					} //XXX: Silently skip non-text string audiences
				}
			} else if (cbor.getType().equals(CBORType.TextString)) {
				aud.add(cbor.AsString()); 
			} else {//error
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
				map.Add(Constants.ERROR_DESCRIPTION, 
						"Audience malformed");
				LOGGER.log(Level.INFO, "Message processing aborted: "
						+ "Audience malformed");
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
		}
		if (aud.isEmpty()) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
			map.Add(Constants.ERROR_DESCRIPTION, 
					"No audience found for message");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "No audience found for message");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}


		//5. Check if the scope is allowed
		String allowedScopes = null;
		try {
			allowedScopes = this.pdp.canAccess(msg.getSenderId(), aud, scope);
		} catch (AceException e) {
			LOGGER.severe("Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		if (allowedScopes == null) {	
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "invalid_scope");
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

		//6. Create token
		//Find supported token type
		Short tokenType = null;
		try {
			tokenType = this.db.getSupportedTokenType(aud);
		} catch (AceException e) {
			LOGGER.severe("Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		if (tokenType == null) {
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, "Audience incompatible on token type");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "Audience incompatible on token type");
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, 
					map);
		}


		byte[] ctiB = buffer.putLong(0, this.cti).array();
		String ctiStr = Base64.getEncoder().encodeToString(ctiB);
		this.cti++;


		//Find supported profile
		String profile = null;
		try {
			profile = this.db.getSupportedProfile(id, aud);
		} catch (AceException e) {
			this.cti--; //roll-back
			LOGGER.severe("Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		if (profile == null) {
			this.cti--; //roll-back
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, "No compatible profile found");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "No compatible profile found");
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, map);
		}

		if (tokenType != AccessTokenFactory.CWT_TYPE 
				&& tokenType != AccessTokenFactory.REF_TYPE) {
			this.cti--; //roll-back
			CBORObject map = CBORObject.NewMap();
			map.Add(Constants.ERROR, "Unsupported token type");
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ "Unsupported token type");
			return msg.failReply(Message.FAIL_NOT_IMPLEMENTED, map);
		}

		String keyType = null; //Save the key type for later
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
				//Check if AUD is a singleton
				if (aud.size() == 1) {
					claims.put(Constants.AUD, CBORObject.FromObject(
							aud.iterator().next()));
				} else {
					claims.put(Constants.AUD, CBORObject.FromObject(aud));
				}
				break;
			case Constants.EXP:
				long now = this.time.getCurrentTime();
				long exp = Long.MAX_VALUE;
				try {
					exp = this.db.getExpTime(aud);
				} catch (AceException e) {
					LOGGER.severe("Message processing aborted: "
							+ e.getMessage());
					return msg.failReply(
							Message.FAIL_INTERNAL_SERVER_ERROR, null);
				}
				if (exp == Long.MAX_VALUE) { // == No expiration time found
					//using default
					exp = now + expiration;
				} else {
					exp = now + exp;
				}
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
			case Constants.CTI:
				claims.put(Constants.CTI, CBORObject.FromObject(ctiB));
				break;
			case Constants.SCOPE:
				claims.put(Constants.SCOPE, 
						CBORObject.FromObject(allowedScopes));
				break;
			case Constants.CNF:
				//Check if client requested a specific kid,
				// if so, assume the client knows what it's doing
				// i.e. that the RS has that key and can process it
				CBORObject cnf = msg.getParameter(Constants.CNF);
				if (cnf != null && cnf.ContainsKey(Constants.COSE_KID_CBOR)) {
					//Check that the kid is well-formed
					CBORObject kidC = cnf.get(Constants.COSE_KID_CBOR);
					if (!kidC.getType().equals(CBORType.ByteString)) {
						this.cti--; //roll-back
						LOGGER.info("Message processing aborted: "
								+ " Malformed kid in request parameter 'cnf'");
						CBORObject map = CBORObject.NewMap();
						map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
						map.Add(Constants.ERROR_DESCRIPTION, 
								"Malformed kid in 'cnf' parameter");
						return msg.failReply(Message.FAIL_BAD_REQUEST, map);
					}
					keyType = "KID";
					claims.put(Constants.CNF, cnf);
				} else {    
					//Find supported key type for proof-of-possession
					try {
						keyType = this.db.getSupportedPopKeyType(id, aud);
					} catch (AceException e) {
						this.cti--; //roll-back
						LOGGER.severe("Message processing aborted: "
								+ e.getMessage());
						return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
					}
					switch (keyType) {
					case "PSK":
						try {
							KeyGenerator kg = KeyGenerator.getInstance("AES");
							SecretKey key = kg.generateKey();
							CBORObject keyData = CBORObject.NewMap();
							keyData.Add(KeyKeys.KeyType.AsCBOR(), 
									KeyKeys.KeyType_Octet);
							keyData.Add(KeyKeys.Octet_K.AsCBOR(), 
									CBORObject.FromObject(key.getEncoded()));
							//Note: kid is the same as cti 
							byte[] kid = ctiB;               
							keyData.Add(KeyKeys.KeyId.AsCBOR(), kid);

							OneKey psk = new OneKey(keyData);
							CBORObject coseKey = CBORObject.NewMap();
							coseKey.Add(Constants.COSE_KEY, psk.AsCBOR());
							claims.put(Constants.CNF, coseKey);
						} catch (NoSuchAlgorithmException | CoseException e) {
							this.cti--; //roll-back
							LOGGER.severe("Message processing aborted: "
									+ e.getMessage());
							return msg.failReply(
									Message.FAIL_INTERNAL_SERVER_ERROR, null);
						}       
						break;
					case "RPK":
						if (cnf == null) {
							this.cti--; //roll-back
							CBORObject map = CBORObject.NewMap();
							map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
							map.Add(Constants.ERROR_DESCRIPTION, 
									"Client failed to provide RPK");
							LOGGER.log(Level.INFO, "Message processing aborted: "
									+ "Client failed to provide RPK");
							return msg.failReply(Message.FAIL_BAD_REQUEST, map);
						}
						OneKey rpk = null;
						try {
							rpk = getKey(cnf, id);
						} catch (AceException | CoseException e) {
							this.cti--; //roll-back
							LOGGER.severe("Message processing aborted: "
									+ e.getMessage());
							if (e.getMessage().startsWith("Malformed")) {
								CBORObject map = CBORObject.NewMap();
								map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
								map.Add(Constants.ERROR_DESCRIPTION, 
										"Malformed 'cnf' parameter in request");
								return msg.failReply(Message.FAIL_BAD_REQUEST, map);
							} 
							return msg.failReply(
									Message.FAIL_INTERNAL_SERVER_ERROR, null);
						}
						if (rpk == null) {
							this.cti--; //roll-back
							CBORObject map = CBORObject.NewMap();
							map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
							map.Add(Constants.ERROR_DESCRIPTION, 
									"Client failed to provide RPK");
							LOGGER.log(Level.INFO, "Message processing aborted: "
									+ "Client failed to provide RPK");
							return msg.failReply(Message.FAIL_BAD_REQUEST, map);
						}
						CBORObject coseKey = CBORObject.NewMap();
						coseKey.Add(Constants.COSE_KEY, rpk.AsCBOR());
						claims.put(Constants.CNF, coseKey);
						break;
					default :
						this.cti--; //roll-back
						CBORObject map = CBORObject.NewMap();
						map.Add(Constants.ERROR, Constants.UNSUPPORTED_POP_KEY);
						LOGGER.log(Level.INFO, "Message processing aborted: "
								+ "Unsupported pop key");
						return msg.failReply(Message.FAIL_BAD_REQUEST, map);
					}
				}
				break;
			default:
				LOGGER.severe("Unknown claim type in /token "
						+ "endpoint configuration: " + c);
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			}
		}

		AccessToken token = null;
		try {
			token = AccessTokenFactory.generateToken(tokenType, claims);
		} catch (AceException e) {
			this.cti--; //roll-back
			LOGGER.severe("Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		CBORObject rsInfo = CBORObject.NewMap();


		try {
			if (!this.db.hasDefaultProfile(id)) {
				rsInfo.Add(Constants.PROFILE, CBORObject.FromObject(profile));
			}
		} catch (AceException e) {
			this.cti--; //roll-back
			LOGGER.severe("Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}

		if (keyType != null && keyType.equals("PSK")) {
			rsInfo.Add(Constants.CNF, claims.get(Constants.CNF));
		}  else if (keyType != null && keyType.equals("RPK")) {
			Set<String> rss = new HashSet<>();
			for (String audE : aud) {
				try {
					rss.addAll(this.db.getRSS(audE));
				} catch (AceException e) {
					this.cti--; //roll-back
					LOGGER.severe("Message processing aborted: "
							+ e.getMessage());
					return msg.failReply(
							Message.FAIL_INTERNAL_SERVER_ERROR, null);
				}
			}
			for (String rs : rss) {
				try {
					OneKey rsKey = this.db.getRsRPK(rs);
					CBORObject rscnf = CBORObject.NewMap();
					rscnf.Add(Constants.COSE_KEY_CBOR, rsKey.AsCBOR());
					rsInfo.Add(Constants.RS_CNF, rscnf);
				} catch (AceException e) {
					this.cti--; //roll-back
					LOGGER.severe("Message processing aborted: "
							+ e.getMessage());
					return msg.failReply(
							Message.FAIL_INTERNAL_SERVER_ERROR, null);
				}
			}
		} //Skip cnf if client requested specific KID.

		if (!allowedScopes.equals(scope)) {
			rsInfo.Add(Constants.SCOPE, CBORObject.FromObject(allowedScopes));
		}

		if (token instanceof CWT) {

			CwtCryptoCtx ctx = null;
			try {
				ctx = makeCommonCtx(aud);
			} catch (AceException | CoseException e) {
				this.cti--; //roll-back
				LOGGER.severe("Message processing aborted: "
						+ e.getMessage());
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			}
			if (ctx == null) {
				this.cti--; //roll-back
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, 
						"No common security context found for audience");
				LOGGER.log(Level.INFO, "Message processing aborted: "
						+ "No common security context found for audience");
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, map);
			}
			CWT cwt = (CWT)token;
			try {
				rsInfo.Add(Constants.ACCESS_TOKEN, cwt.encode(ctx));
			} catch (IllegalStateException | InvalidCipherTextException
					| CoseException | AceException e) {
				this.cti--; //roll-back
				LOGGER.severe("Message processing aborted: "
						+ e.getMessage());
				return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			}
		} else {
			rsInfo.Add(Constants.ACCESS_TOKEN, token.encode());
		}

		try {
			this.db.addToken(ctiStr, claims);
			this.db.addCti2Client(ctiStr, id);
			this.db.saveCtiCounter(this.cti);
		} catch (AceException e) {
			this.cti--; //roll-back
			LOGGER.severe("Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		LOGGER.log(Level.INFO, "Returning token: " + ctiStr);
		return msg.successReply(Message.CREATED, rsInfo);
	}



	/**
	 * Retrieves a key from a cnf structure.
	 * 
	 * @param cnf  the cnf structure
	 * 
	 * @return  the key
	 * 
	 * @throws AceException 
	 * @throws CoseException 
	 */
	private OneKey getKey(CBORObject cnf, String id) 
			throws AceException, CoseException {
		CBORObject crpk = null; 
		if (cnf.ContainsKey(Constants.COSE_KEY_CBOR)) {
			crpk = cnf.get(Constants.COSE_KEY_CBOR);
			if (crpk == null) {
				return null;
			}
			return new OneKey(crpk);
		} else if (cnf.ContainsKey(Constants.COSE_ENCRYPTED_CBOR)) {
			Encrypt0Message msg = new Encrypt0Message();
			CBORObject encC = cnf.get(Constants.COSE_ENCRYPTED_CBOR);
			try {
				msg.DecodeFromCBORObject(encC);
				OneKey psk = this.db.getCPSK(id);
				if (psk == null) {
					LOGGER.severe("Couldn't find a key to decrypt cnf parameter");
					throw new AceException(
							"No key found to decrypt cnf parameter");
				}
				CBORObject key = psk.get(KeyKeys.Octet_K);
				if (key == null || !key.getType().equals(CBORType.ByteString)) {
					LOGGER.severe("Corrupt key retrieved from database");
					throw new AceException("Key error in the database");  
				}
				msg.decrypt(key.GetByteString());
				CBORObject keyData = CBORObject.DecodeFromBytes(msg.GetContent());
				return new OneKey(keyData);
			} catch (CoseException | InvalidCipherTextException e) {
				LOGGER.severe("Error while decrypting a cnf claim: "
						+ e.getMessage());
				throw new AceException("Error while decrypting a cnf parameter");
			}
		} //Note: We checked the COSE_KID_CBOR case before 
		throw new AceException("Malformed cnf structure");
	}

	/**
	 * Remove expired tokens from the storage.
	 * 
	 * @throws AceException 
	 */
	public void purgeExpiredTokens() throws AceException {
		this.db.purgeExpiredTokens(this.time.getCurrentTime());
	}

	/**
	 * Removes a token from the registry
	 * 
	 * @param cti  the token identifier Base64 encoded
	 * @throws AceException 
	 */
	public void removeToken(String cti) throws AceException {
		this.db.deleteToken(cti);
	}

	/**
	 * Create a common CWT crypto context for the given audience.
	 * 
	 * @param aud  the audiences

	 * @return  a common crypto context or null if there isn't any
	 * 
	 * @throws CoseException 
	 * @throws AceException 
	 */
	private CwtCryptoCtx makeCommonCtx(Set<String> aud) 
			throws AceException, CoseException {
		COSEparams cose = this.db.getSupportedCoseParams(aud);
		if (cose == null) {
			return null;
		}
		MessageTag tag = cose.getTag();
		switch (tag) {
		case Encrypt:
			AlgorithmID ealg = cose.getAlg();
			return CwtCryptoCtx.encrypt(makeRecipients(aud, cose), 
					ealg.AsCBOR());
		case Encrypt0:
			byte[] ekey = getCommonSecretKey(aud);
			if (ekey == null) {
				return null;
			}
			return CwtCryptoCtx.encrypt0(ekey, cose.getAlg().AsCBOR());
		case MAC:

			return CwtCryptoCtx.mac(makeRecipients(aud, cose), 
					cose.getAlg().AsCBOR());
		case MAC0:
			byte[] mkey = getCommonSecretKey(aud);
			if (mkey == null) {
				return null;
			}
			return CwtCryptoCtx.mac0(mkey, cose.getAlg().AsCBOR());
		case Sign:
			// Access tokens with multiple signers not supported
			return null;
		case Sign1:

			return CwtCryptoCtx.sign1Create(
					this.privateKey, cose.getAlg().AsCBOR());
		default:
			throw new IllegalArgumentException("Unknown COSE message type");
		}
	}

	/**
	 * Create a recipient list for an audience.
	 * 
	 * @param aud  the audience
	 * @return  the recipient list
	 * @throws AceException 
	 * @throws CoseException 
	 */
	private List<Recipient> makeRecipients(Set<String> aud, COSEparams cose)
			throws AceException, CoseException {
		List<Recipient> rl = new ArrayList<>();
		for (String audE : aud) {
			for (String rs : this.db.getRSS(audE)) {
				Recipient r = new Recipient();
				r.addAttribute(HeaderKeys.Algorithm, 
						cose.getKeyWrap().AsCBOR(), 
						Attribute.UNPROTECTED);
				CBORObject key = CBORObject.NewMap();
				key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
				key.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(
						this.db.getRsPSK(rs)));
				OneKey coseKey = new OneKey(key);
				r.SetKey(coseKey); 
				rl.add(r);
			}
		}
		return rl;
	}

	/**
	 * Tries to find a common PSK for the given audience.
	 * 
	 * @param aud  the audience
	 * @return  a common PSK or null if there isn't any
	 * @throws AceException 
	 */
	private byte[] getCommonSecretKey(Set<String> aud) throws AceException {
		Set<String> rss = new HashSet<>();
		for (String audE : aud) {
			rss.addAll(this.db.getRSS(audE));
		}
		byte[] key = null;
		for (String rs : rss) {
			OneKey cose = this.db.getRsPSK(rs);
			if (cose == null) {
				return null;
			}
			byte[] secKey = cose.get(KeyKeys.Octet_K).GetByteString();
			if (key == null) {
				key = Arrays.copyOf(secKey, secKey.length);
			} else {
				if (!Arrays.equals(key, secKey)) {
					return null;
				}
			}
		}
		return key;
	}

	@Override
	public void close() throws AceException {
		this.db.saveCtiCounter(this.cti);
		this.db.close();
	}
}
