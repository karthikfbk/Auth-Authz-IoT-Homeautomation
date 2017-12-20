package thesis.authz.federated_iot_core;




import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.json.JSONObject;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.TimeProvider;
import se.sics.ace.as.Introspect;
import se.sics.ace.as.PDP;
import se.sics.ace.as.Token;
import se.sics.ace.coap.as.CoapAceEndpoint;
import se.sics.ace.coap.as.CoapDBConnector;
import thesis.authz.federated_iot_core.hybrid.CoapDBConnector_hy;
import thesis.authz.federated_iot_core.hybrid.CoapFetchInfo_hy;
import thesis.authz.federated_iot_core.hybrid.DBConnector_hy;
import thesis.authz.federated_iot_core.hybrid.FetchInfo_hy;

/**
 * An authorization server listening to CoAP requests
 * over DTLS.
 * 
 * Create an instance of this server with the constructor then call
 * CoapsAS_ma.start();
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapsAS_ma extends CoapServer implements AutoCloseable {

	/**
	 * The logger
	 */
	private static final Logger LOGGER 
	= Logger.getLogger(CoapsAS_ma.class.getName());


	/**
	 * The token endpoint
	 */
	Token_ma t = null;

	/**
	 * The introspect endpoint
	 */
	Introspect i = null;

	Connect c = null;

	Query q = null;
	FetchInfo_hy f = null;

	private CoapAceEndpoint token;

	private CoapAceEndpoint introspect;

	private CoapProvisionInfo connect;

	private CoapProvisionInfo query;
	
	private CoapFetchInfo_hy fetch;

	private KeyStore keyStore;
	private String keyStorepassword;
	private KeyStore trustStore;
	private int sport;
	private final String rootcaalias;
	private ConnectedAS partners;
	private final String myalias;
	private Certificate[] trustedCertificates;
	private Map<String,String> mydevices;
	private JSONObject partner;

	/**
	 * Constructor.
	 * 
	 * @param asId  identifier of the AS
	 * @param db    database connector of the AS
	 * @param pdp   PDP for deciding who gets which token
	 * @param time  time provider, must not be null
	 * @param asymmetricKey  asymmetric key pair of the AS for RPK handshakes,
	 *   can be null if the AS only ever does PSK handshakes
	 * @param port  the port number to run the server on
	 * 
	 * @throws AceException 
	 * @throws CoseException 
	 * 
	 */
	public CoapsAS_ma(String asId, CoapDBConnector db, PDP pdp, TimeProvider time,
			int port, 
			String keyStorelocation, String trustStorelocation, 
			String keyStorepassword, String trustStorepassword,
			String alias, String rootalias, Map<String,String> devices, JSONObject partner) throws AceException, CoseException {
		InputStream in = null;
		this.myalias = alias;
		this.sport = port;
		this.rootcaalias = rootalias;
		this.keyStorepassword = keyStorepassword;
		this.partner = partner;
		this.mydevices = devices;
		try {
			// load the key store
			this.keyStore = KeyStore.getInstance("JKS");			
			in = new FileInputStream(keyStorelocation);			
			this.keyStore.load(in, keyStorepassword.toCharArray());			
			in.close();


			// load the trust store
			this.trustStore = KeyStore.getInstance("JKS");
			InputStream inTrust = new FileInputStream(trustStorelocation);
			this.trustStore.load(inTrust, trustStorepassword.toCharArray());

			PrivateKey key = (PrivateKey)keyStore.getKey(alias, keyStorepassword.toCharArray());
			java.security.cert.Certificate cert = keyStore.getCertificate(alias); 
			Certificate[] chain = keyStore.getCertificateChain(alias);

			PublicKey pubkey = cert.getPublicKey();
			OneKey asykey = convertToOneKey(pubkey,key);
			DTLSConnector connector = null;
			this.partners = new ConnectedAS();

			// You can load multiple certificates if needed
			//Certificate[] trustedCertificates = new Certificate[2];
			//trustedCertificates[0] = trustStore.getCertificate("rootca1");
			//trustedCertificates[1] = trustStore.getCertificate("rootca2");
			System.out.println("Adding root" + this.rootcaalias);
			addTrustedCertificate(trustStore.getCertificate(this.rootcaalias));

			// add trusted roots for partners

			if(this.partner != null) {
				Certificate root_certi = trustStore.getCertificate(this.partner.getString("root_alias"));
				Certificate partner_certi = trustStore.getCertificate(this.partner.getString("alias_name"));
				OneKey Certi_Pubkey = convertToOneKey_publickey(partner_certi.getPublicKey());
				addTrustedCertificate(root_certi);
				Map<Short, Object> map = new HashMap<Short, Object>();
				map.put(Constants_ma.PUBLIC_KEY, Certi_Pubkey);
				map.put(Constants_ma.ROOT_CERT, root_certi);
				this.partners.addPartner(this.partner.getString("distinguished_name"), map);
			}


			DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(this.sport));
			//builder.setAddress(new InetSocketAddress(this.sport));		
			builder.setIdentity((PrivateKey)this.keyStore.getKey(this.myalias, this.keyStorepassword.toCharArray()),
					this.keyStore.getCertificateChain(this.myalias), false);
			builder.setTrustStore(this.trustedCertificates);
			builder.setSupportedCipherSuites(new CipherSuite[]{
					CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
			});
			builder.setClientAuthenticationRequired(true);
			connector= new DTLSConnector(builder.build());		
			addEndpoint(new CoapEndpoint(connector, NetworkConfig.getStandard()));



			if (asykey == null) {
				this.i = new Introspect(pdp, db, time, null);
			} else {
				this.i = new Introspect(pdp, db, time, asykey.PublicKey());
			}			

			

			this.t = new Token_ma(asId, pdp, db, time, asykey, this.partners,this.mydevices,chain,this.trustedCertificates); 
			this.q = new Query(asId, asykey, this.partners, time);
			this.c = new Connect(asId);
			
			this.f = new FetchInfo_hy(asId, asykey, this.partners, time, (CoapDBConnector_hy)db);
			

			this.token = new CoapAceEndpoint("token",this.t);
			this.introspect = new CoapAceEndpoint(this.i);
			this.connect = new CoapProvisionInfo("connect",this,this.c);
			this.query = new CoapProvisionInfo("query",this,this.q);
			this.fetch = new CoapFetchInfo_hy(this.f);


			add(this.token);
			add(this.introspect);
			add(this.connect);
			add(this.query);
			add(this.fetch);



			//			String names[] = this.part_alias.split(" ");
			//			
			//			for(String name:names) {
			//				System.out.println("Adding root" + name);
			//				addTrustedCertificate(trustStore.getCertificate(name));
			//			}
			//addTrustedCertificate(trustStore.getCertificate(CoapsAS_ma.BASE_ROOT1));
			//addTrustedCertificate(trustStore.getCertificate(CoapsAS_ma.BASE_ROOT2));			




		}catch (GeneralSecurityException | IOException e) {
			LOGGER.log(Level.SEVERE, "Could not load the keystore", e);
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					LOGGER.log(Level.SEVERE, "Cannot close key store file", e);
				}
			}
		}


	}

	/*
	 * Starts a Coaps Endpoint using DTLS and trustedcertificate list
	 * Stops and Starts the endpoint if an existing one is running.
	 */
	public void startCoapsEndpoint(int port) throws Exception {

		//Check if an endpoint is running.
		//if its running destroy it.
		CoapEndpoint p = (CoapEndpoint) this.getEndpoint(port);
		if(p.isStarted()) {
			p.destroy();
		}

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(port));
		//builder.setAddress();		
		builder.setIdentity((PrivateKey)this.keyStore.getKey(this.myalias, this.keyStorepassword.toCharArray()),
				this.keyStore.getCertificateChain(this.myalias), false);
		builder.setTrustStore(this.trustedCertificates);
		builder.setSupportedCipherSuites(new CipherSuite[]{
				CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
				CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
		builder.setClientAuthenticationRequired(true);
		DTLSConnector connector = new DTLSConnector(builder.build());		
		addEndpoint(new CoapEndpoint(connector, NetworkConfig.getStandard()));
		this.getEndpoint(port).start();

	}

	public Certificate[] getCurrentturstedCertificateList() {

		return this.trustedCertificates;
	}

	public void addTrustedCertificate(Certificate trustcert) {

		if(trustcert != null) {
			int length = 0;
			if(this.trustedCertificates != null)
				length = this.trustedCertificates.length;
			else {
				this.trustedCertificates = new Certificate[1];
				this.trustedCertificates[0] = trustcert;
				return;
			}


			Certificate[] newcertlist = new Certificate[length+1];
			int i=0;
			for(i=0;i<length;i++) {
				Certificate c = this.trustedCertificates[i];
				if(c!=null) {
					newcertlist[i] = c;
				}
			}
			newcertlist[i] = trustcert;
			this.trustedCertificates = newcertlist;
		}
	}
	/**
	 * Constructor.
	 * 
	 * @param asId  identifier of the AS
	 * @param db    database connector of the AS
	 * @param pdp   PDP for deciding who gets which token
	 * @param time  time provider, must not be null
	 * @param asymmetricKey  asymmetric key pair of the AS for RPK handshakes,
	 *   can be null if the AS only ever does PSK handshakes
	 * @throws AceException 
	 * @throws CoseException 
	 * 
	 */
	public CoapsAS_ma(String asId, CoapDBConnector db, PDP pdp, TimeProvider time, 
			String keyStorelocation, String trustStorelocation, 
			String keyStorepassword, String trustStorepassword, String alias, String rootalias, Map<String,String> devices,
			JSONObject partner,int port) throws AceException, CoseException {
		this(asId, db, pdp, time, port, keyStorelocation, trustStorelocation, 
				keyStorepassword, trustStorepassword, alias, rootalias,devices, partner);
	}

	public KeyStore gettrustStore() {
		return this.trustStore;
	}

	public KeyStore getkeyStore() {
		return this.keyStore;
	}
	public int getsport() {
		return this.sport;
	}
	public String getrootalias() {
		return this.rootcaalias;
	}
	public String getalias() {
		return this.myalias;
	}

	public String getkeystorepassword() {
		return this.keyStorepassword;
	}

	@Override
	public void close() throws Exception {
		LOGGER.info("Closing down CoapsAS_ma ...");
		this.token.close();
		this.introspect.close();
	}
	private OneKey convertToOneKey(PublicKey pubkey, PrivateKey key) {
		ECPublicKey mypub = (ECPublicKey) pubkey;

		byte[] X = mypub.getW().getAffineX().toByteArray();		

		byte[] Y = mypub.getW().getAffineY().toByteArray();		

		// assumes that x and y are (unsigned) big endian encoded
		BigInteger xbi = new BigInteger(1, X);
		BigInteger ybi = new BigInteger(1, Y);
		X9ECParameters x9 = ECNamedCurveTable.getByName("secp256r1");
		ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID("secp256r1");
		ECCurve curve = x9.getCurve();
		ECPoint point = curve.createPoint(xbi, ybi);
		ECNamedDomainParameters dParams = new ECNamedDomainParameters(oid,
				x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
		ECPublicKeyParameters pubKey = new ECPublicKeyParameters(point, dParams);
		System.out.println(pubKey);


		byte[] rgbX = pubKey.getQ().normalize().getXCoord().getEncoded();
		byte[] rgbY = pubKey.getQ().normalize().getYCoord().getEncoded();

		ECPrivateKey mypri = (ECPrivateKey) key;

		byte[] rgbD = mypri.getS().toByteArray();

		OneKey key1 = new OneKey();

		key1.add(KeyKeys.KeyType, KeyKeys.KeyType_EC2);
		key1.add(KeyKeys.EC2_Curve, KeyKeys.EC2_P256);
		key1.add(KeyKeys.EC2_X, CBORObject.FromObject(rgbX));
		key1.add(KeyKeys.EC2_Y, CBORObject.FromObject(rgbY));
		key1.add(KeyKeys.EC2_D, CBORObject.FromObject(rgbD));

		return key1;
	}

	private OneKey convertToOneKey_publickey(PublicKey pubkey) {
		ECPublicKey mypub = (ECPublicKey) pubkey;

		byte[] X = mypub.getW().getAffineX().toByteArray();		

		byte[] Y = mypub.getW().getAffineY().toByteArray();		

		// assumes that x and y are (unsigned) big endian encoded
		BigInteger xbi = new BigInteger(1, X);
		BigInteger ybi = new BigInteger(1, Y);
		X9ECParameters x9 = ECNamedCurveTable.getByName("secp256r1");
		ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID("secp256r1");
		ECCurve curve = x9.getCurve();
		ECPoint point = curve.createPoint(xbi, ybi);
		ECNamedDomainParameters dParams = new ECNamedDomainParameters(oid,
				x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
		ECPublicKeyParameters pubKey = new ECPublicKeyParameters(point, dParams);
		System.out.println(pubKey);

		byte[] rgbX = pubKey.getQ().normalize().getXCoord().getEncoded();
		byte[] rgbY = pubKey.getQ().normalize().getYCoord().getEncoded();	

		OneKey key1 = new OneKey();
		key1.add(KeyKeys.KeyType, KeyKeys.KeyType_EC2);
		key1.add(KeyKeys.EC2_Curve, KeyKeys.EC2_P256);
		key1.add(KeyKeys.EC2_X, CBORObject.FromObject(rgbX));
		key1.add(KeyKeys.EC2_Y, CBORObject.FromObject(rgbY));


		return key1;
	}
}
