package thesis.authz.federated_iot_as;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;

import org.json.JSONObject;

import thesis.authz.federated_iot.AS_Params;
import thesis.authz.federated_iot.as.AS;




/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws Exception
    {   	
    	AS raspberryas;
    	AS_Params params;
    	if (args.length > 0) {
    		params = new AS_Params();
            
    		String jsonData = readFile(args[0]);
			JSONObject jobj = new JSONObject(jsonData);
			
			params.Fill(jobj);
			raspberryas = new AS(params);
			raspberryas.start();		
		}
		else {
			System.out.println("Required AS_Config JSON file as argument");
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
}
