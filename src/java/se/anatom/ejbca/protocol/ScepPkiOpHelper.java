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

package se.anatom.ejbca.protocol;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.CADoesntExistsException;
import se.anatom.ejbca.ca.exception.IllegalKeyException;
import se.anatom.ejbca.ca.exception.SignRequestException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.log.Admin;

import javax.ejb.ObjectNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;


/**
 * Helper class to handle SCEP (draft-nourse-scep-06.txt) requests.
 *
 * @version  $Id: ScepPkiOpHelper.java,v 1.27 2004-11-20 22:54:28 sbailliez Exp $
 */
public class ScepPkiOpHelper {
    private static Logger log = Logger.getLogger(ScepPkiOpHelper.class);
    private ScepRequestMessage reqmsg = null;
    private Admin admin = null;
    private ISignSessionRemote signsession = null;

    /**
     * Creates a new ScepPkiOpHelper object.
     *
     * @param admin administrator performing this
     * @param signsession signsession used to request certificates
     */
    public ScepPkiOpHelper(Admin admin, ISignSessionRemote signsession) {
        log.debug(">ScepPkiOpHelper");
        this.admin = admin;
        this.signsession = signsession;
        log.debug("<ScepPkiOpHelper");
    }

    /**
     * Handles SCEP certificate request
     *
     * @param msg buffer holding the SCEP-request (DER encoded).
     *
     * @return byte[] containing response to be sent to client.
     */
    public byte[] scepCertRequest(byte[] msg)
            throws ObjectNotFoundException, AuthorizationDeniedException, AuthLoginException,
            SignRequestException, AuthStatusException, IllegalKeyException,
            SignRequestSignatureException, CertificateEncodingException {
        byte[] ret = null;
        log.debug(">getRequestMessage(" + msg.length + " bytes)");

        try {
            reqmsg = new ScepRequestMessage(msg);

            if (reqmsg.getErrorNo() != 0) {
                log.error("Error '" + reqmsg.getErrorNo() + "' receiving Scep request message.");
                return null;
            }
            if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_PKCSREQ) {
                // Get the certificate
                IResponseMessage resp = signsession.createCertificate(admin, reqmsg, -1,
                        Class.forName("se.anatom.ejbca.protocol.ScepResponseMessage"));
                if (resp != null) {
                    ret = resp.getResponseMessage();
                }
            }
            if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_GETCRL) {
                // create the stupid encrypted CRL message, the below can actually only be made 
                // at the CA, since CAs privvate key is needed to decrypt
                IResponseMessage resp = signsession.getCRL(admin, reqmsg,
                        Class.forName("se.anatom.ejbca.protocol.ScepResponseMessage"));
                if (resp != null) {
                    ret = resp.getResponseMessage();
                }
            }
        } catch (IOException e) {
            log.error("Error receiving ScepMessage: ", e);
        } catch (CMSException e) {
            log.error("Error receiving ScepMessage: ", e);
        } catch (GeneralSecurityException e) {
            log.error("Error receiving ScepMessage: ", e);
        } catch (ClassNotFoundException e) {
            log.error("Error createing response message template: ", e);
        } catch (CADoesntExistsException e) {
            log.error("Requested CA does not exist: ", e);
        }

        log.debug("<getRequestMessage():" + ((ret == null) ? 0 : ret.length));

        return ret;
    }
}
