/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.protocol;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.apache.log4j.Logger;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.protocol.scep.ScepRequestMessage;


/**
 * Helper class to handle SCEP (draft-nourse-scep-06.txt) requests.
 *
 * @version  $Id$
 */
public class ScepPkiOpHelper {
    private static Logger log = Logger.getLogger(ScepPkiOpHelper.class);
    private AuthenticationToken admin = null;
    private SignSessionLocal signsession;

    /**
     * Creates a new ScepPkiOpHelper object.
     *
     * @param admin administrator performing this
     * @param signsession signsession used to request certificates
     */
    public ScepPkiOpHelper(AuthenticationToken admin, SignSessionLocal signsession) {
    	if (log.isTraceEnabled()) {
    		log.trace(">ScepPkiOpHelper");
    	}
        this.admin = admin;
        this.signsession = signsession;
    	if (log.isTraceEnabled()) {
    		log.trace("<ScepPkiOpHelper");
    	}
    }

    /**
     * Handles SCEP certificate request
     *
     * @param msg buffer holding the SCEP-request (DER encoded).
     *
     * @return byte[] containing response to be sent to client.
     * @throws AuthorizationDeniedException 
     * @throws CesecoreException 
     */
    public byte[] scepCertRequest(byte[] msg, boolean includeCACert)
            throws EjbcaException, CesecoreException, AuthorizationDeniedException {
        byte[] ret = null;
        if (log.isTraceEnabled()) {
        	log.trace(">getRequestMessage(" + msg.length + " bytes)");
        }
        try {
            final ScepRequestMessage reqmsg = new ScepRequestMessage(msg, includeCACert);

            if (reqmsg.getErrorNo() != 0) {
                log.error("Error '" + reqmsg.getErrorNo() + "' receiving Scep request message.");
                return null;
            }
            if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_PKCSREQ) {
                // Get the certificate
                ResponseMessage resp = signsession.createCertificate(admin, reqmsg, org.ejbca.core.protocol.scep.ScepResponseMessage.class, null);
                if (resp != null) {
                    ret = resp.getResponseMessage();
                }
            }
            if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_GETCRL) {
                // create the stupid encrypted CRL message, the below can actually only be made 
                // at the CA, since CAs private key is needed to decrypt
                ResponseMessage resp = signsession.getCRL(admin, reqmsg, org.ejbca.core.protocol.scep.ScepResponseMessage.class);
                if (resp != null) {
                    ret = resp.getResponseMessage();
                }
            }
        } catch (IOException e) {
            log.error("Error receiving ScepMessage: ", e);
        } catch (GeneralSecurityException e) {
            log.error("Error receiving ScepMessage: ", e);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<getRequestMessage():" + ((ret == null) ? 0 : ret.length));
        }
        return ret;
    }
}
