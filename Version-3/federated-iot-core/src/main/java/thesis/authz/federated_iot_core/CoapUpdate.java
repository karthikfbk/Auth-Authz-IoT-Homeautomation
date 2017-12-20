package thesis.authz.federated_iot_core;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.auth.X509CertPath;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Message;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.coap.CoapRes;

public class CoapUpdate extends CoapResource {

	/**
	 * The logger
	 */
	private static final Logger LOGGER 
	= Logger.getLogger(CoapUpdate.class.getName());

	private String rs_id;
	private String as_id;
	private CoapServer server;
	private String alias;
	private String root_alias;
	private KeyStore keyStore;
	private KeyStore trustStore;
	private String keyStorepassword;
	private String trustStorepassword;
	private Certificate[] trustedCertificates;
	private int sPort;

	public CoapUpdate(String rs_id, String as_id,CoapServer server,
			String root_alias, String alias, KeyStore keyStore, String keyStorepassword, KeyStore trustStore,
			String trustStorepassword, Certificate[] trustedCertificates, int sPort) {
		super("update");
		this.rs_id = rs_id;
		this.as_id = as_id;
		this.server = server;

		this.alias = alias;
		this.root_alias = root_alias;
		this.keyStore = keyStore;
		this.trustStore = trustStore;
		this.keyStorepassword = keyStorepassword;
		this.trustStorepassword = trustStorepassword;
		this.trustedCertificates = trustedCertificates;
		this.sPort = sPort;
	}

	@Override
	public void handlePOST(CoapExchange exchange) {
		
		
		LOGGER.log(Level.INFO," Update endpoint received udpate request");
		//First accept the exchange to send an ACK to the AS
		Request req = new Request(exchange.getRequestCode());
		req.setPayload(exchange.getRequestPayload());
		//Process the request only if the handshake is done via X509Certificates.
		//Reject if its based on RPK.
		Principal p = exchange.advanced().getRequest().getSenderIdentity();
		req.setSenderIdentity(exchange.advanced().getRequest().getSenderIdentity());
		CoapReq msg=null;
		try {
			msg = CoapReq.getInstance(req);
		} catch (AceException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			CBORObject res = null;
			CoapRes r = new CoapRes(ResponseCode.INTERNAL_SERVER_ERROR, res);
			exchange.respond(r.getCode(),r.getRawPayload(),MediaTypeRegistry.APPLICATION_CBOR);
		}
		if(p instanceof X509CertPath) {
			//Get the RootCA Certificate sent by AS
			CBORObject cbor = msg.getParameter(Constants_ma.ROOT_CERT);
			if (cbor.getType().equals(CBORType.ByteString)) {
				byte[] certbytes = cbor.GetByteString();
				X509Certificate cert = null;
				try {
					CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
					InputStream in = new ByteArrayInputStream(certbytes);
					cert = (X509Certificate)certFactory.generateCertificate(in);

					int len = this.trustedCertificates.length;
					Certificate[] newtrust = new Certificate[len + 1];
					int i;
					for(i=0;i<len;i++) {
						newtrust[i] = this.trustedCertificates[i];
					}
					newtrust[i] = cert;
					this.trustedCertificates = newtrust;
					DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(this.sPort));
					//builder.setAddress();		
					builder.setIdentity((PrivateKey)this.keyStore.getKey(this.alias, this.keyStorepassword.toCharArray()),
							this.keyStore.getCertificateChain(this.alias), false);
					builder.setTrustStore(this.trustedCertificates);
					builder.setSupportedCipherSuites(new CipherSuite[]{
							CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
					builder.setClientAuthenticationRequired(true);
					DTLSConnector connector = new DTLSConnector(builder.build());	
					System.out.println("Printing origin of exchange " +exchange.advanced().getOrigin());
					//exchange.accept();
					CoapRes r = (CoapRes) msg.successReply(Message.CREATED, null);
					exchange.respond(r.getCode(),r.getRawPayload(),MediaTypeRegistry.APPLICATION_CBOR);
					//Check if an endpoint is running.
					//if its running destroy it.
					CoapEndpoint point = (CoapEndpoint) this.server.getEndpoint(this.sPort);
					if(point.isStarted()) {
						point.destroy();
					}
					this.server.addEndpoint(new CoapEndpoint(connector, NetworkConfig.getStandard()));
					this.server.getEndpoint(this.sPort).start();
				} 
				catch (Exception e) {
					LOGGER.severe("Message processing aborted: "
							+ e.getMessage());
					CoapRes r = (CoapRes) msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
					exchange.respond(r.getCode(),r.getRawPayload(),MediaTypeRegistry.APPLICATION_CBOR);
				}
			}
			else {
				CBORObject map = CBORObject.NewMap();			
				map.Add(Constants.ERROR_DESCRIPTION, "Invalid format of root cert parameter");
				LOGGER.log(Level.INFO, "Message processing aborted: "
						+ "Invalid format of root cert key");
				CoapRes r = (CoapRes) msg.failReply(Message.FAIL_UNSUPPORTED_CONTENT_FORMAT, map);
				exchange.respond(r.getCode(),r.getRawPayload(),MediaTypeRegistry.APPLICATION_CBOR);
			}
		}    
		else {
			CBORObject map = CBORObject.NewMap();				
			map.Add(Constants.ERROR, Constants.INVALID_REQUEST);			
			LOGGER.log(Level.INFO, "Message processing aborted: "
					+ " Exhange not done via X509CERT ");
			CoapRes r = (CoapRes) msg.failReply(Message.FAIL_UNAUTHORIZED, map);
			exchange.respond(r.getCode(),r.getRawPayload(),MediaTypeRegistry.APPLICATION_CBOR);
		}  
	}
}


