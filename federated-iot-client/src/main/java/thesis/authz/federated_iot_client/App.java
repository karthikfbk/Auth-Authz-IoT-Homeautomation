package thesis.authz.federated_iot_client;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.Arrays;
import java.util.Base64;

import org.json.JSONObject;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.OneKey;
import thesis.authz.federated_iot.Client_Params;
//import thesis.authz.federated_iot.client.CLIENT;
import thesis.authz.federated_iot.client.CLIENT;



/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws Exception, Exception
    {
    	if (args.length > 0) {
    		
    		Client_Params params = new Client_Params();
            
    		String jsonData = readFile(args[0]);
			JSONObject jobj = new JSONObject(jsonData);
			
			params.Fill(jobj);
			CLIENT raspberryclient = new CLIENT(params);
			//Execute the Client
			raspberryclient.execute();
			raspberryclient.close();
		}
		else {
			System.out.println("Required ClientConfig JSON file as argument");
			System.exit(0);
		}
    	
    }
    static String readFile(String Filename) {

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
		return result;
	}
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
		 System.out.println(val);
		 System.out.println(new String((Base64.getEncoder().encode(asymmKey.EncodeToBytes()))));
    }
}
