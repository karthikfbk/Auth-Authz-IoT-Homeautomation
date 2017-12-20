package thesis.authz.federated_iot_client.hybrid;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URL;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ErrorHandler;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.json.JSONArray;
import org.json.JSONObject;


import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.Constants;
import se.sics.ace.as.Token;
import se.sics.ace.coap.client.DTLSProfileRequests;
import se.sics.ace.cwt.CWT;
import se.sics.ace.examples.KissPDP;
import thesis.authz.federated_iot_core.Constants_ma;
import thesis.authz.federated_iot_core.Token_ma;
import COSE.AlgorithmID;
import COSE.CoseException;

import COSE.KeyKeys;
import COSE.MAC0Message;
import COSE.Message;
import COSE.OneKey;
import COSE.Sign1Message;




/**
 * Hello world!
 *
 */
public class App 
{

	//	static {
	//		ScandiumLogger.initialize();
	//		ScandiumLogger.setLevel(Level.FINE);
	//	}

	private static short retry_counter = 3;

	public static void main( String[] args ) throws Exception, Exception
	{

		JSONObject cconfig = readFile(args[0]);


		String trustStorelocation = cconfig.getString("truststorelocation");

		String trustStorepassword = cconfig.getString("truststorepass");

		String clientname = cconfig.getString("name");
		String rootalias = cconfig.getString("root");
		String cas_name = cconfig.getString("cas_name");
		InputStream in = null;


		// load the trust store
		KeyStore trustStore = KeyStore.getInstance("JKS");
		InputStream inTrust = new FileInputStream(trustStorelocation);
		trustStore.load(inTrust, trustStorepassword.toCharArray());

		//You can load multiple certificates if needed
		Certificate[] trustedCertificates = new Certificate[1];
		trustedCertificates[0] = trustStore.getCertificate(rootalias);	

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(0));		

		OneKey asykey = new OneKey(
				CBORObject.DecodeFromBytes(Base64.getDecoder().decode(cconfig.getString("client_asykey"))));
		builder.setIdentity(asykey.AsPrivateKey(),asykey.AsPublicKey());
		builder.setRetransmissionTimeout(20000);
		builder.setTrustStore(trustedCertificates);
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

		/*
		 * DISCOVERY OF RS
		 */
		String RS_id = null;
		List<String> scp = null;
		String AS_id = null;

		String AS_tokenendpoint = null;
		CoapClient dis_client = new CoapClient();
		dis_client.setTimeout(30000);
		dis_client.setURI(cconfig.getString("rsaddress"));

		System.out.println(" DISCOVERING...... ");
		Set<WebLink> discovered_links = dis_client.discover();

		if(discovered_links != null && discovered_links.size() > 0) {
			for (WebLink s : discovered_links) {
				if(s.getURI().equals("/Info")) {
					RS_id = s.getAttributes().getAttributeValues("rsid").get(0);
					scp = s.getAttributes().getAttributeValues("rsscopes");
					AS_id = s.getAttributes().getAttributeValues("asid").get(0);
					AS_tokenendpoint = s.getAttributes().getAttributeValues("astokenendpoint").get(0);
				}
			}
		}
		System.out.println(" DISCOVERY RESULT .....");

		String RSscopes = "";
		for(String s:scp) {
			RSscopes = RSscopes + s + " ";			
		}
		System.out.println(" RS id " + RS_id);
		System.out.println(" RSscopes " + RSscopes);
		System.out.println(" AS_id " + AS_id);

		System.out.println(" AS_tokenendpoint " + AS_tokenendpoint);

		if(RSscopes != null) {
			/*
			 * QUERY REQUEST for received scopes from RS
			 */

			CBORObject idtoken = null;
			CBORObject accesstoken = null;
			CBORObject filtered_scopes=null;

			JSONObject query_request = (JSONObject) cconfig.get("QUERY_REQUEST");


			Map<Short, CBORObject> params = new HashMap<>();
			params.put(Constants_ma.REQUEST_TYPE, CBORObject.FromObject(Constants_ma.QUERY));
			params.put(Constants_ma.TAR, CBORObject.FromObject(AS_id));
			params.put(Constants.AUD, CBORObject.FromObject(RS_id));
			params.put(Constants_ma.REQUIRED_ROOT, CBORObject.FromObject(true));
			params.put(Constants.SCOPE, CBORObject.FromObject(RSscopes));

			String uri = query_request.getString("uri");
			client.setURI(uri);

			CoapResponse response;
			CBORObject res;
			Map<Short, CBORObject> map;
			if(query_request.getBoolean("execute")) {
				System.out.println(" ##### SENDING QUERY REQUEST TO ##### " + uri);
				response = client.post(
						Constants.getCBOR(params).EncodeToBytes(), 
						MediaTypeRegistry.APPLICATION_CBOR); 			

				res = CBORObject.DecodeFromBytes(response.getPayload());
				map = Constants.getParams(res);
				idtoken = map.get(Constants_ma.ID_TOKEN);
				filtered_scopes = map.get(Constants.SCOPE);
				System.out.println("Receided Id Token Response " + map);
				System.out.println(" ##### Printing ID Token ##### " + idtoken);

				CBORObject ROOTCA = map.get(Constants_ma.ROOT_CERT);


				if(ROOTCA.getType().equals(CBORType.ByteString)) {
					byte[] certbytes = ROOTCA.GetByteString();

					try {
						CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
						InputStream in1 = new ByteArrayInputStream(certbytes);
						Certificate cert = certFactory.generateCertificate(in1);
						//Next add to client trusted certificates.
						Certificate existingtrust = trustedCertificates[0];
						trustedCertificates = new Certificate[2];
						trustedCertificates[0] = existingtrust;
						trustedCertificates[1] = cert;

						builder.setTrustStore(trustedCertificates);
						client.getEndpoint().destroy();

						dtlsConnector = new DTLSConnector(builder.build());	
						e = new CoapEndpoint(dtlsConnector, NetworkConfig.getStandard());							
						client.setEndpoint(e);
						dtlsConnector.start();
					} catch (CertificateException e1) {
						System.out.println("Message processing aborted: "
								+ e1.getMessage());							
					}
				}
			}

			params.clear();

			/*
			 * ACCESS TOKEN REQUEST
			 */
			JSONObject access_token_request = (JSONObject) cconfig.get("ACCESS_TOKEN_REQUEST");
			client.setURI(AS_tokenendpoint);

			//Send again Access Token Request				
			params.put(Constants.GRANT_TYPE, CBORObject.FromObject(Constants_ma.HYBRID));
			params.put(Constants_ma.ID_TOKEN, idtoken);
			params.put(Constants.SCOPE, filtered_scopes);				
			params.put(Constants.AUD, CBORObject.FromObject(RS_id));

			CBORObject cose_key = null;
			if(access_token_request.getBoolean("execute")) {
				System.out.println(" ##### SENDING ACCESS TOKEN REQUEST TO ##### " + AS_tokenendpoint);
				response = client.post(
						Constants.getCBOR(params).EncodeToBytes(), 
						MediaTypeRegistry.APPLICATION_CBOR);    
				res = CBORObject.DecodeFromBytes(response.getPayload());
				map = Constants.getParams(res);

				accesstoken = map.get(Constants.ACCESS_TOKEN);
				cose_key = map.get(Constants.CNF);
				System.out.println("Receided Access Token Response " );
				System.out.println(" ##### Printing ACCESS Token ##### " + accesstoken);

				dis_client.setURI(cconfig.getString("authz_info_uri_hy"));
				response = dis_client.post(accesstoken.EncodeToBytes(), 
						MediaTypeRegistry.APPLICATION_CBOR);
				res = CBORObject.DecodeFromBytes(response.getPayload());
				map = Constants.getParams(res);
				System.out.println("Receided Response from authorz-info " + map);
			}				

			params.clear();
			//PARSE RESOURCES_ACCESS_REQUEST
			JSONObject resource_access_request = (JSONObject)cconfig.get("RESOURCES_ACCESS_REQUEST");
			ResponseCode c = null;


			CBORObject pskkey = cose_key.get(CBORObject.FromObject(Constants.COSE_KEY));
			OneKey psk = new OneKey(pskkey);

			CBORObject kid = psk.get(KeyKeys.KeyId);
			uri = resource_access_request.getString("resource");
			//just change the protocol to http to use existing methods to get the host name and port
			URL url = new URL(uri.replaceAll(".*//","http://"));			
			String host = url.getHost();
			int port = url.getPort();

			CoapClient pskclient = DTLSProfileRequests.getPskClient(new InetSocketAddress(host,port), kid.GetByteString(), psk);

			pskclient.setURI(uri);
			if(resource_access_request.getBoolean("execute")) {
				switch(resource_access_request.getString("method")) {
				case "GET":
					System.out.println(" ##### SENDING RESOURCE ACCESS GET REQUEST TO ##### ");
					response = pskclient.get();
					c = response.getCode();
					switch(c) {
					case UNAUTHORIZED:
						System.out.println("Received UNAUTHORIZED response");
						res = CBORObject.DecodeFromBytes(response.getPayload());
						System.out.println("Printing Received payload " + res.toString());
						break;
					case FORBIDDEN:
						System.out.println("Received FORBIDDEN response");
						res = CBORObject.DecodeFromBytes(response.getPayload());
						System.out.println("Printing Received payload " + res.toString());
						break;

					case METHOD_NOT_ALLOWED:
						System.out.println("Received METHOD_NOT_ALLOWED response");
						res = CBORObject.DecodeFromBytes(response.getPayload());
						System.out.println("Printing Received payload " + res.toString());
						break;
					case CONTENT:
						System.out.println("Received CONTENT response");

						System.out.println("Printing Received Content " + response.getResponseText());
						break;
					default:
						break;
					}

					break;
				case "PUT":
					System.out.println(" ##### SENDING RESOURCE ACCESS PUT REQUEST TO ##### ");
					response = pskclient.put("", MediaTypeRegistry.APPLICATION_CBOR);
					c = response.getCode();
					switch(c) {
					case UNAUTHORIZED:
						System.out.println("Received UNAUTHORIZED response");
						res = CBORObject.DecodeFromBytes(response.getPayload());
						System.out.println("Printing Received payload " + res.toString());
						break;
					case FORBIDDEN:
						System.out.println("Received FORBIDDEN response");
						res = CBORObject.DecodeFromBytes(response.getPayload());
						System.out.println("Printing Received payload " + res.toString());
						break;

					case METHOD_NOT_ALLOWED:
						System.out.println("Received METHOD_NOT_ALLOWED response");
						res = CBORObject.DecodeFromBytes(response.getPayload());
						System.out.println("Printing Received payload " + res.toString());
						break;
					case CONTENT:
						System.out.println("Received CONTENT response");
						System.out.println("Printing Received Content " + response.getResponseText());
						break;
					default:
						break;
					}
					break;
				default:
					break;
				}
			}
		}






	}




	/*

		CBORObject idtoken = null;
		CBORObject accesstoken = null;

		//PARSE ID_TOKEN ACCESS REQUEST
		JSONObject id_token_request = (JSONObject) cconfig.get("ID_TOKEN_REQUEST");

		//Send ID Token Request
		Map<Short, CBORObject> params = new HashMap<>();
		params.put(Constants.TOKEN_TYPE, CBORObject.FromObject(Constants_ma.ID_TOKEN));
		params.put(Constants_ma.TAR, 
				CBORObject.FromObject(id_token_request.getString("tar")));
		params.put(Constants.AUD, CBORObject.FromObject(id_token_request.getString("aud")));

		String uri = id_token_request.getString("uri");
		client.setURI(uri);

		if(id_token_request.getBoolean("execute")) {
			System.out.println(" ##### SENDING ID_TOKEN REQUEST TO ##### " + uri);
			CoapResponse response = client.post(
					Constants.getCBOR(params).EncodeToBytes(), 
					MediaTypeRegistry.APPLICATION_CBOR); 			

			CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
			Map<Short, CBORObject> map = Constants.getParams(res);
			idtoken = map.get(Constants_ma.ID_TOKEN);

			System.out.println("Receided Id Token Response " + map);
			System.out.println(" ##### Printing ID Token ##### " + idtoken);
		}

		params.clear();

		//PARSE ACCESS TOKEN REQUEST
		JSONObject access_token_request = (JSONObject) cconfig.get("ACCESS_TOKEN_REQUEST");
		uri = access_token_request.getString("uri");
		client.setURI(uri);

		//Send again Access Token Request
		if(access_token_request.getString("grant_type").equals("asymmetric"))
			params.put(Constants.GRANT_TYPE, Token_ma.asymmetric);
		params.put(Constants.TOKEN_TYPE, CBORObject.FromObject(Constants.ACCESS_TOKEN));
		params.put(Constants_ma.ID_TOKEN, idtoken);

		JSONArray scopes = access_token_request.getJSONArray("scopes");
		StringBuilder tmp = new StringBuilder();

		tmp.append((Object)scopes.get(0).toString());
		for(int i=1;i<scopes.length();i++) {
			Object o=scopes.get(i);
			tmp.append(" ");
			tmp.append(o.toString());			
		}
		params.put(Constants.SCOPE, 
				CBORObject.FromObject(tmp.toString()));
		params.put(Constants.AUD, CBORObject.FromObject(access_token_request.getString("aud")));

		if(access_token_request.getBoolean("execute")) {
			System.out.println(" ##### SENDING ACCESS TOKEN REQUEST TO ##### " + uri);
			CoapResponse response = client.post(
					Constants.getCBOR(params).EncodeToBytes(), 
					MediaTypeRegistry.APPLICATION_CBOR);    
			CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
			Map<Short, CBORObject> map = Constants.getParams(res);

			accesstoken = map.get(Constants.ACCESS_TOKEN);
			System.out.println("Receided Access Token Response " );
			System.out.println(" ##### Printing ACCESS Token ##### " + accesstoken);

			client.setURI(cconfig.getString("authz_info_uri"));
			response = client.post(accesstoken.EncodeToBytes(), 
					MediaTypeRegistry.APPLICATION_CBOR);
			res = CBORObject.DecodeFromBytes(response.getPayload());
			 map = Constants.getParams(res);
			System.out.println("Receided Response from authorz-info " + map);
		}

		/*
		Message coseRaw = Message.DecodeFromBytes(accesstoken.EncodeToBytes());
		if(coseRaw instanceof MAC0Message) {
			MAC0Message maced = (MAC0Message)coseRaw;

			CWT itok = new CWT(Constants.getParams(
					CBORObject.DecodeFromBytes(maced.GetContent())));
			System.out.println("Printing received access token " + itok.toString());
		}*/		


	/*
		CoapResponse response;
		CBORObject res ;

		params.clear();
		//PARSE RESOURCES_ACCESS_REQUEST
		JSONObject resource_access_request = (JSONObject) cconfig.get("RESOURCES_ACCESS_REQUEST");
		ResponseCode c = null;
		client.setURI(resource_access_request.getString("resource"));
		if(resource_access_request.getBoolean("execute")) {
			switch(resource_access_request.getString("method")) {
			case "GET":
				System.out.println(" ##### SENDING RESOURCE ACCESS GET REQUEST TO ##### ");
				response = client.get();
				c = response.getCode();
				switch(c) {
				case UNAUTHORIZED:
					System.out.println("Received UNAUTHORIZED response");
					res = CBORObject.DecodeFromBytes(response.getPayload());
					System.out.println("Printing Received payload " + res.toString());
					break;
				case FORBIDDEN:
					System.out.println("Received FORBIDDEN response");
					res = CBORObject.DecodeFromBytes(response.getPayload());
					System.out.println("Printing Received payload " + res.toString());
					break;

				case METHOD_NOT_ALLOWED:
					System.out.println("Received METHOD_NOT_ALLOWED response");
					res = CBORObject.DecodeFromBytes(response.getPayload());
					System.out.println("Printing Received payload " + res.toString());
					break;
				case CONTENT:
					System.out.println("Received CONTENT response");

					System.out.println("Printing Received Content " + response.getResponseText());
					break;
				default:
					break;
				}

				break;
			case "PUT":
				System.out.println(" ##### SENDING RESOURCE ACCESS PUT REQUEST TO ##### ");
				response = client.put("", MediaTypeRegistry.APPLICATION_CBOR);
				c = response.getCode();
				switch(c) {
				case UNAUTHORIZED:
					System.out.println("Received UNAUTHORIZED response");
					res = CBORObject.DecodeFromBytes(response.getPayload());
					System.out.println("Printing Received payload " + res.toString());
					break;
				case FORBIDDEN:
					System.out.println("Received FORBIDDEN response");
					res = CBORObject.DecodeFromBytes(response.getPayload());
					System.out.println("Printing Received payload " + res.toString());
					break;

				case METHOD_NOT_ALLOWED:
					System.out.println("Received METHOD_NOT_ALLOWED response");
					res = CBORObject.DecodeFromBytes(response.getPayload());
					System.out.println("Printing Received payload " + res.toString());
					break;
				case CONTENT:
					System.out.println("Received CONTENT response");
					System.out.println("Printing Received Content " + response.getResponseText());
					break;
				default:
					break;
				}
				break;
			default:
				break;
			}

		}

	 */

	//		Message coseRaw = Message.DecodeFromBytes(idtoken.EncodeToBytes());
	//		
	//		if (coseRaw instanceof Sign1Message) {
	//			Sign1Message signed = (Sign1Message)coseRaw;
	//			
	//				CWT IDtoken = new CWT(Constants.getParams(
	//					CBORObject.DecodeFromBytes(signed.GetContent())));
	//				System.out.println(IDtoken.toString());
	//			}
	//		System.out.println("Receided Response " + map);
	//		System.out.println("Printing ID Token " + idtoken);



	static void generateSimpleOneKey() {
		OneKey asymmKey=null;
		try {
			asymmKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
		} catch (CoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		String val = asymmKey.AsCBOR().toString();
		byte[] b =val.getBytes();
		System.out.println("Key including public parameters");
		System.out.println(val);
		System.out.println(new String((Base64.getEncoder().encode(asymmKey.EncodeToBytes()))));

		OneKey publicKey = asymmKey.PublicKey();
		val = publicKey.AsCBOR().toString();
		b =val.getBytes();
		System.out.println("Key with only public parameters");
		System.out.println(val);
		System.out.println(new String((Base64.getEncoder().encode(publicKey.EncodeToBytes()))));


	}

	static void generateSimpleSymmetricKey() {

		KeyGenerator kg=null;
		try {
			kg = KeyGenerator.getInstance("HmacSHA256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		SecretKey key = kg.generateKey();
		System.out.println(new String((Base64.getEncoder().encode(key.getEncoded()))));
	}
	static JSONObject readFile(String Filename) {

		String result = "";

		try {
			BufferedReader br = new BufferedReader(new FileReader(Filename));
			StringBuilder sb = new StringBuilder();
			String line = br.readLine();
			while(line != null) {
				sb.append(line);
				line=br.readLine();
			}
			result = sb.toString();
			br.close();
		} catch(Exception e) {
			e.printStackTrace();
		}
		return new JSONObject(result);
	}

	/*
	static void convertX509toOneKey() {
		PrivateKey key = (PrivateKey)keyStore.getKey(alias, keyStorepassword.toCharArray());
		java.security.cert.Certificate cert = keyStore.getCertificate(alias); 

		System.out.println(new String((Base64.getEncoder().encode(key.getEncoded()))));
		PublicKey pubkey = cert.getPublicKey();

		System.out.println(new String((Base64.getEncoder().encode(pubkey.getEncoded()))));

		ECPublicKey mypub = (ECPublicKey) pubkey;

		byte[] X = mypub.getW().getAffineX().toByteArray();

		System.out.println(" X coordinate length " + X.length);
		byte[] Y = mypub.getW().getAffineY().toByteArray();

		System.out.println(" Y coordinate length " + Y.length);


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

	        String val = key1.AsCBOR().toString();
			byte[] b =val.getBytes();
			System.out.println("Key including public parameters");
			System.out.println(val);
			System.out.println(new String((Base64.getEncoder().encode(key1.EncodeToBytes()))));

			OneKey publicKey = key1.PublicKey();
			val = publicKey.AsCBOR().toString();
			b =val.getBytes();
			System.out.println("Key with only public parameters");
			System.out.println(val);
			System.out.println(new String((Base64.getEncoder().encode(publicKey.EncodeToBytes()))));


			PrivateKey key2 = key1.AsPrivateKey();
			System.out.println(new String((Base64.getEncoder().encode(key2.getEncoded()))));
			PublicKey pubkey2 = key1.AsPublicKey();
			System.out.println(new String((Base64.getEncoder().encode(pubkey2.getEncoded()))));
	}*/
}
