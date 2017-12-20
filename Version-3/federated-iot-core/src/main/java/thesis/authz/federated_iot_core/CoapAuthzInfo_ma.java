package thesis.authz.federated_iot_core;

import java.security.Principal;

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


import java.util.logging.Logger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.scandium.auth.X509CertPath;

import se.sics.ace.AceException;
import se.sics.ace.Message;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.coap.CoapRes;
import se.sics.ace.rs.AuthzInfo;


/**
 * A CoAP resource implementing the authz-info endpoint at the RS 
 * for the DTLS profile.
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapAuthzInfo_ma extends CoapResource {

    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CoapAuthzInfo_ma.class.getName());
    
    /**
     * The underlying authz-info library
     */
    private AuthzInfo_ma ai;
    
   /**
    * Constructor.
    * 
    * @param ai  the internal authorization information handler 
    */ 
    public CoapAuthzInfo_ma(AuthzInfo_ma ai) {
        super("authz-info");
        this.ai = ai;
    }
    
    @Override
    public void handlePOST(CoapExchange exchange) {
        exchange.accept();
        Request req = new Request(exchange.getRequestCode());
        req.setPayload(exchange.getRequestPayload());
        
        //Now if its an DTLS connection with CERTFICATES, you can also set the sender identity,
        //Because the sender is already authenticated based on CERTS
        //But for RPK an out of band establishment is needed.
        Principal p = exchange.advanced().getRequest().getSenderIdentity();
        if(p instanceof X509CertPath) {
        	 req.setSenderIdentity(exchange.advanced().getRequest().getSenderIdentity());
        }       
        try {
            CoapReq msg = CoapReq.getInstance(req);
            Message reply = this.ai.processMessage(msg);
            //Safe to cast, since CoapReq only ever renders a CoapRes
            CoapRes response = (CoapRes)reply; 
            exchange.respond(response.getCode(), response.getRawPayload(),
                    MediaTypeRegistry.APPLICATION_CBOR);
        } catch (AceException e) {
            LOGGER.severe("Error while handling incoming POST: " 
                    + e.getMessage());
            return;
        }  
    }
}

