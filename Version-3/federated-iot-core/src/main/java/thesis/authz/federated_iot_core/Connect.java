package thesis.authz.federated_iot_core;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.KeyKeys;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;

public class Connect implements ProvisionEndpoint, AutoCloseable{


	/**
	 * The logger
	 */
	private static final Logger LOGGER 
	= Logger.getLogger(Connect.class.getName());

	private String asId;
	
	public Connect(String asId) throws AceException {
		//Time for checks
		if (asId == null || asId.isEmpty()) {
			LOGGER.severe("Query endpoint's AS identifier was null or empty");
			throw new AceException(
					"AS identifier must be non-null and non-empty");
		}		
		this.asId = asId;		
	}

	public Message processMessage(Message msg,CoapProvisionInfo myresource) {
		// TODO Auto-generated method stub

		LOGGER.log(Level.INFO, " ##### Received Connect Request: #####" 
				+ msg.getParameters());

		CertificateFactory certFactory = null;
		X509Certificate cert = null;
		PublicKey publicKey = null;

		//Get the public key from the connect request
		CBORObject cbor = msg.getParameter(Constants_ma.PUBLIC_KEY);
		if (cbor.getType().equals(CBORType.ByteString)) {
			byte[] publicKeyBytes = cbor.GetByteString();

			try {
				KeyFactory kf = KeyFactory.getInstance("EC");
				publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

			} catch (Exception e) {
				LOGGER.severe("Message processing aborted: "
						+ e.getMessage());
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
		if (cbor.getType().equals(CBORType.ByteString)) {
			byte[] certbytes = cbor.GetByteString();

			try {
				certFactory = CertificateFactory.getInstance("X.509");
				InputStream in = new ByteArrayInputStream(certbytes);
				cert = (X509Certificate)certFactory.generateCertificate(in);

			} catch (CertificateException e) {
				LOGGER.severe("Message processing aborted: "
						+ e.getMessage());
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

		CBORObject result = CBORObject.NewMap();

		try {
			Certificate myrootcertificate = myresource.getServer().gettrustStore().getCertificate(myresource.getServer().getrootalias());

			byte[] rootcertbytes = myrootcertificate.getEncoded();
			Certificate mycertificate;
			mycertificate = myresource.getServer().getkeyStore().getCertificate(myresource.getServer().getalias());


			PrivateKey privatek =(PrivateKey)myresource.getServer().getkeyStore().getKey(myresource.getServer().getalias(), 
					myresource.getServer().getkeystorepassword().toCharArray());
			PublicKey pubk = mycertificate.getPublicKey();
			OneKey key = convertToOneKey(pubk,privatek);
			byte[] mypubkeybytes = key.PublicKey().EncodeToBytes();
			result.Add(Constants_ma.PUBLIC_KEY, CBORObject.FromObject(mypubkeybytes));
			result.Add(Constants_ma.ROOT_CERT, CBORObject.FromObject(rootcertbytes));

			myresource.getServer().addTrustedCertificate(cert);
			myresource.restartserverendpoint = true;

			return msg.successReply(Message.CREATED, result);
		} catch (Exception e) {
			// TODO Auto-generated catch block

			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}

	}

	@Override
	public void close() throws AceException {
		// TODO Auto-generated method stub

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

}
