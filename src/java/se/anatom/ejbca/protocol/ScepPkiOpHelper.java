package se.anatom.ejbca.protocol;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.ejb.ObjectNotFoundException;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;

import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.IllegalKeyException;
import se.anatom.ejbca.ca.exception.SignRequestException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import java.security.cert.CertificateEncodingException;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;

/**
 * Helper class to handle SCEP (draft-nourse-scep-06.txt) requests.
 *
 * @version  $Id: ScepPkiOpHelper.java,v 1.16 2003-06-14 11:29:10 anatom Exp $
 */
public class ScepPkiOpHelper {

    private static Logger log = Logger.getLogger(ScepPkiOpHelper.class);

    private ScepRequestMessage reqmsg = null;
    private Admin admin = null;
    private ISignSessionRemote signsession = null;
        
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
     * @return byte[] containing response to be sent to client.
     */
    public  byte[] scepCertRequest(byte[] msg) 
    throws ObjectNotFoundException, AuthorizationDeniedException, AuthLoginException, SignRequestException, AuthStatusException, IllegalKeyException, SignRequestSignatureException, CertificateEncodingException 
    {
        byte[] ret = null;
        log.debug(">getRequestMessage("+msg.length+" bytes)");
        try {
            reqmsg = new ScepRequestMessage(msg);
            if (reqmsg.getError() != 0) {
                log.error("Error '"+reqmsg.getError()+"' receiving Scep request message.");
                return null;
            }
            // Get the certificate
            IResponseMessage resp = signsession.createCertificate(admin, reqmsg, -1, Class.forName("se.anatom.ejbca.protocol.ScepResponseMessage"));
            if (resp != null) {
                ret = resp.getResponseMessage();
            }
        } catch (IOException e) {
            log.error("Error receiving ScepMessage: ",e);
        } catch (CMSException e) {
            log.error("Error receiving ScepMessage: ",e);
        } catch (GeneralSecurityException e) {
            log.error("Error receiving ScepMessage: ",e);
        } catch (ClassNotFoundException e) {
            log.error("Error createing response message template: ",e);
        } 
        log.debug("<getRequestMessage():" + (ret == null ? 0 : ret.length));
        return ret;
    }

}
