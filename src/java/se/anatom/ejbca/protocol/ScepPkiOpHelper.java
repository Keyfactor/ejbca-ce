package se.anatom.ejbca.protocol;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.ejb.FinderException;
import javax.ejb.ObjectNotFoundException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.IllegalKeyException;
import se.anatom.ejbca.ca.exception.SignRequestException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import java.security.cert.CertificateEncodingException;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;


/**
 * Helper class to handle SCEP (draft-nourse-scep-06.txt) requests.
 *
 * @version  $Id: ScepPkiOpHelper.java,v 1.9 2003-06-05 13:08:31 anatom Exp $
 */
public class ScepPkiOpHelper {

    private static Logger log = Logger.getLogger(ScepPkiOpHelper.class);

    private ScepRequestMessage reqmsg = null;
    private Admin admin = null;
    private IUserAdminSessionRemote adminsession = null;
    private ISignSessionRemote signsession = null;
        
    public ScepPkiOpHelper(Admin admin, IUserAdminSessionRemote adminsession, ISignSessionRemote signsession) {
        log.debug(">ScepPkiOpHelper");
        this.admin = admin;
        this.adminsession = adminsession;
        this.signsession = signsession; 
        log.debug("<ScepPkiOpHelper");
    }
    
    /**
     * Handles SCEP certificate request
     *
     * @param msg buffer holding the SCEP-request (DER encoded).
     * @return byte[] containing DER-encoded certificate.
     */
    public  byte[] scepCertRequest(byte[] msg) 
    throws ObjectNotFoundException, AuthorizationDeniedException, AuthLoginException, SignRequestException, AuthStatusException, IllegalKeyException, SignRequestSignatureException, CertificateEncodingException 
    {
        byte[] ret = null;
        log.debug(">getRequestMessage("+msg.length+" bytes)");
        try {
            reqmsg = new ScepRequestMessage(msg);
            // Get DN and extract Common Name, this is our username
            String username = reqmsg.getRequestDN();
            try{
                UserAdminData data = adminsession.findUser(admin, username);
                if(data == null)
                  throw new ObjectNotFoundException();
            } catch (FinderException fe) {
                throw new ObjectNotFoundException();
            }
            // Get challenge password from PKCS#10 request
            String password = reqmsg.getRequestPassword();
            // Get the certificate
            X509Certificate cert = (X509Certificate) signsession.createCertificate(admin, username, password, reqmsg);
            if (cert != null) {
                ret = cert.getEncoded();
            }
        } catch (IOException e) {
            log.error("Error receiving ScepMessage: ",e);
        } 
        log.debug("<getRequestMessage():" + (ret == null ? 0 : ret.length));
        return ret;
    }

}
