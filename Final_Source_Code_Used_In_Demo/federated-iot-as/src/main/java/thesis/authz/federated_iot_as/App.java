package thesis.authz.federated_iot_as;

import java.io.BufferedReader;
import java.io.FileReader;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;

import org.eclipse.californium.scandium.ScandiumLogger;
import org.json.JSONArray;
import org.json.JSONObject;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.coap.as.CoapsAS;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.SQLConnector;
import thesis.authz.federated_iot_core.CoapsAS_ma;
import thesis.authz.federated_iot_core.hybrid.CoapDBConnector_hy;

public class App {
	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.FINE);
	}


	private static CoapDBConnector_hy db = null;
	private static String dbPwd = "Admin_Root";
	private static CoapsAS as = null; 
	private static KissPDP pdp = null;

	public static void main(String[] args) throws Exception {
		int Port = Integer.parseInt(args[1]);
		
	

		JSONObject asconfig = readFile(args[0]);

		String dbip = asconfig.getString("dbip");
		//Just to be sure no old test pollutes the DB
		SQLConnector.wipeDatabase(dbPwd);

		SQLConnector.createUser(dbPwd, "aceuser", "password", 
				"jdbc:mysql://" +dbip+":3306");
		SQLConnector.createDB(dbPwd, "aceuser", "password", null,
				"jdbc:mysql://" +dbip+ ":3306");

		db = new CoapDBConnector_hy("jdbc:mysql://"+dbip+":3306", "aceuser", "password");

		KissTime time = new KissTime();

		pdp = new KissPDP(dbPwd, db);

		String keyStorelocation = asconfig.getString("keystorelocation");
		String trustStorelocation = asconfig.getString("truststorelocation");
		String keyStorepassword = asconfig.getString("keystorepass");
		String trustStorepassword = asconfig.getString("truststorepass");
		String alias = asconfig.getString("alias");
		String rootalias = asconfig.getString("root");
		String asname = asconfig.getString("name");
		Map<String, String> devices = null;
		if(asconfig.has("CLIENTS")) {
			//Read Clients
			JSONArray clients = asconfig.getJSONArray("CLIENTS");
			if(clients != null) {
				if(clients.length() > 0) {
					for(int i=0; i<clients.length();i++) {
						JSONObject client = (JSONObject) clients.get(i);

						String name = client.getString("name");
						Set<String> profiles = getSetfromJSONArray(client.getJSONArray("profiles"));
						Set<String> keytypes = getSetfromJSONArray(client.getJSONArray("keytypes"));
						CBORObject keyData = CBORObject.NewMap();
						keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
						keyData.Add(KeyKeys.Octet_K.AsCBOR(), 
								CBORObject.FromObject(client.getString("skey").getBytes()));
						OneKey skey = new OneKey(keyData);			        
						db.addClient(name, profiles, null, null, 
								keytypes, skey, null, false);   
					}
				}
			}
		}
		if(asconfig.has("RSS")) {
			//Read RS
			JSONArray Rss = asconfig.getJSONArray("RSS");
			if(Rss != null) {
				if(Rss.length() > 0) {
					devices = new HashMap<String,String>();
					for(int i=0; i<Rss.length();i++) {
						JSONObject rs = (JSONObject) Rss.get(i);
						
						String name = rs.getString("name");
						String uri = rs.getString("uri");
						Set<String> profiles = getSetfromJSONArray(rs.getJSONArray("profiles"));
						Set<String> keytypes = getSetfromJSONArray(rs.getJSONArray("keytypes"));		
						Set<String> tokentypes = getSetfromJSONArray(rs.getJSONArray("tokentypes"));	
						Set<String> scopes = getSetfromJSONArray(rs.getJSONArray("scopes"));	


						Set<Short> tokenTypes = new HashSet<>();

						for(String tt : tokentypes){
							switch(tt) {
							case "CWT":
								tokenTypes.add(AccessTokenFactory.CWT_TYPE);
								break;
							case "REF":
								tokenTypes.add(AccessTokenFactory.REF_TYPE);
								break;
							default:
								break;
							}
						}
						tokenTypes.add(AccessTokenFactory.CWT_TYPE);

						Set<COSEparams> cose = new HashSet<>();

						//This the coseparam that this server (as/cas) shares with rs1
						//Using this it will MAC the tokens.
						//skey will be used as the symmentric key

						JSONArray cose_param = rs.getJSONArray("cose_param");


						String messagetag = cose_param.getString(0);

						MessageTag mt = null;
						AlgorithmID algid = null;
						AlgorithmID keywrapid = null;
						if(messagetag.equals("ENCRYPT0")) {
							mt = MessageTag.Encrypt0;
						}
						String algId = cose_param.getString(1);

						if(algId.equals("AES_GCM_256")) {
							algid = AlgorithmID.AES_GCM_256;
						}
						String keywrap = cose_param.getString(2);

						if(keywrap.equals("Direct")) {
							keywrapid = AlgorithmID.Direct;
						}
						COSEparams coseP = new COSEparams(mt,algid,keywrapid);
						cose.add(coseP);


						long expiration = rs.getLong("expiration");
						CBORObject keyData = CBORObject.NewMap();
						keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
						keyData.Add(KeyKeys.Octet_K.AsCBOR(), 
								CBORObject.FromObject(Base64.getDecoder().decode(rs.getString("skey"))));
						OneKey skey = new OneKey(keyData);	
						//just add an empty not null audience list
						Set<String> auds = new HashSet<>();
						db.addRS(name, profiles, scopes, auds, keytypes, tokenTypes, cose,
								expiration, skey, null);		        
						devices.put(name, uri);
					}
				}
			}
		}

		if(asconfig.has("ADDTOKENACCESS")) {
			// Add token endpoint access

			JSONArray clientstoadd = asconfig.getJSONArray("ADDTOKENACCESS");
			if(clientstoadd != null) {
				for(Object c:clientstoadd) {
					System.out.println("Adding token access to client " + c.toString());
					pdp.addTokenAccess(c.toString());
				}
			}
		}

		if(asconfig.has("ADDACCESS")) {
			// Add which client can access which rs and with what scopes
			JSONArray addaccess = asconfig.getJSONArray("ADDACCESS");
			if(addaccess != null) {
				for(Object o:addaccess) {
					JSONObject toadd = (JSONObject) o;
					String client = toadd.getString("client");
					String server = toadd.getString("server");

					String scope = toadd.getString("scope");
					pdp.addAccess(client,server,scope);
				}
			}
		}
//		if(asconfig.has("PARTNERS")) {
//			//GET the PARTNERS FOR THIS AS/CAS and their shared security details
//			//INTER Authorization domain communication
//			JSONArray partners = asconfig.getJSONArray("PARTNERS");
//
//			if(partners != null) {
//				cose_sign_targets = new HashMap<String, Object>();
//				for(Object o:partners) {
//
//					JSONObject cose_params = (JSONObject) o;
//					for (Object key : cose_params.keySet()) { //there should be only one key which is the target partner
//						String target = (String)key;
//						JSONObject keyvalue = (JSONObject) cose_params.get(target);
//
//						JSONObject sign1 = (JSONObject) keyvalue.get("sign1");
//						
//						System.out.println("Printing cose_signkey " + sign1.getString("cose_signkey"));
//						System.out.println("Printing cose_verifykey " + sign1.getString("cose_verifykey"));
//						
//						Map<String, Object> cosemap = new HashMap<String, Object>();
//
//						if(sign1 != null) {
//							OneKey my_key_tosign = new OneKey(
//									CBORObject.DecodeFromBytes(Base64.getDecoder().decode(sign1.getString("cose_signkey"))));
//							OneKey partner_key_toverify = new OneKey(
//									CBORObject.DecodeFromBytes(Base64.getDecoder().decode(sign1.getString("cose_verifykey"))));
//							COSEparams cosesign = new COSEparams(MessageTag.Sign1, 
//									AlgorithmID.ECDSA_256, AlgorithmID.Direct);
//							cosemap.put("coseparams", cosesign);
//							cosemap.put("sign_key", my_key_tosign.AsCBOR());
//							cosemap.put("verify_key", partner_key_toverify.AsCBOR());
//
//							cose_sign_targets.put(target, cosemap);
//						}
//					}
//
//				}
//			}
//		}
		
		// Continue from here
		//get all the partner root alias names
		//.....
		//String part_alias = null;
		JSONObject partner = null;
		if(asconfig.has("PARTNER_ALIAS")) {
			
			partner = asconfig.getJSONObject("PARTNER_ALIAS");
		}
		
		// TODO Auto-generated method stub
		CoapsAS_ma as = new CoapsAS_ma(asname, db, pdp, time,
				keyStorelocation , trustStorelocation,
				keyStorepassword, trustStorepassword, alias, rootalias, devices, partner,Port);
		as.start();
		System.out.println("Server starting");
	}

	//	private static byte[] objectToBytArray( Object ob ){
	//		
	//		byte[] b = new byte[32];
	//		
	//		JSONArray jo = (JSONArray) ob;
	//		int length = jo.length();
	//		String [] temp = new String[length];
	//
	//		for(int i=0 ; i< length; i++) {
	//			temp[i] = jo.getString(i);
	//		}
	//		
	//		char s = o.getString(0).charAt(0);
	//		return ((ob.toString()).getBytes());
	//	}

	private static Set<String> getSetfromJSONArray(JSONArray jsonArray) {
		Set<String> result = new HashSet<>();
		for(int i=0;i<jsonArray.length();i++) {
			result.add(jsonArray.getString(i));
		}
		if(result.isEmpty())
			return null;
		return result;
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



}
