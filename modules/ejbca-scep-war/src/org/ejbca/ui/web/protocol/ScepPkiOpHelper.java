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
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.scep.ScepRequestMessage;


/**
 * Helper class to handle SCEP (draft-nourse-scep-06.txt) requests.
 *
 * @version  $Id$
 */
public class ScepPkiOpHelper {
    private static Logger log = Logger.getLogger(ScepPkiOpHelper.class);
    private ScepRequestMessage reqmsg = null;
    private Admin admin = null;
    private ISignSessionLocal signsession = null;

    /**
     * Creates a new ScepPkiOpHelper object.
     *
     * @param admin administrator performing this
     * @param signsession signsession used to request certificates
     */
    public ScepPkiOpHelper(Admin admin, ISignSessionLocal signsession) {
        log.trace(">ScepPkiOpHelper");
        this.admin = admin;
        this.signsession = signsession;
        log.trace("<ScepPkiOpHelper");
    }

    /**
     * Handles SCEP certificate request
     *
     * @param msg buffer holding the SCEP-request (DER encoded).
     *
     * @return byte[] containing response to be sent to client.
     */
    public byte[] scepCertRequest(byte[] msg, boolean includeCACert)
            throws EjbcaException {
        byte[] ret = null;
        if (log.isTraceEnabled()) {
        	log.trace(">getRequestMessage(" + msg.length + " bytes)");
        }
        try {
            reqmsg = new ScepRequestMessage(msg, includeCACert);

            if (reqmsg.getErrorNo() != 0) {
                log.error("Error '" + reqmsg.getErrorNo() + "' receiving Scep request message.");
                return null;
            }
            if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_PKCSREQ) {
                // Get the certificate
                IResponseMessage resp = signsession.createCertificate(admin, reqmsg, -1,
                        Class.forName(org.ejbca.core.protocol.scep.ScepResponseMessage.class.getName()));
                if (resp != null) {
                    ret = resp.getResponseMessage();
                }
            }
            if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_GETCRL) {
                // create the stupid encrypted CRL message, the below can actually only be made 
                // at the CA, since CAs privvate key is needed to decrypt
                IResponseMessage resp = signsession.getCRL(admin, reqmsg,
                        Class.forName(org.ejbca.core.protocol.scep.ScepResponseMessage.class.getName()));
                if (resp != null) {
                    ret = resp.getResponseMessage();
                }
            }
        } catch (IOException e) {
            log.error("Error receiving ScepMessage: ", e);
        } catch (GeneralSecurityException e) {
            log.error("Error receiving ScepMessage: ", e);
        } catch (ClassNotFoundException e) {
            log.error("Error createing response message template: ", e);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<getRequestMessage():" + ((ret == null) ? 0 : ret.length));
        }
        return ret;
    }
}
