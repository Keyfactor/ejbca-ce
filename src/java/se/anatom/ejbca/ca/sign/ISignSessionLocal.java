
package se.anatom.ejbca.ca.sign;

import java.util.*;
import javax.ejb.ObjectNotFoundException;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.PublicKey;

import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.SignRequestException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;

/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown.
 *  Creates certificates.
 *
 * @version $Id: ISignSessionLocal.java,v 1.1 2002-05-26 13:28:53 anatom Exp $
 * @see se.anatom.ejbca.ca.sign.ISignSession
 */
public interface ISignSessionLocal extends javax.ejb.EJBLocalObject {

    /**
     * @see se.anatom.ejbca.ca.sign.ISignSession
     */ 
    public Certificate[] getCertificateChain();
    /**
     * @see se.anatom.ejbca.ca.sign.ISignSession
     */ 
    public Certificate createCertificate(String username, String password, PublicKey pk) throws ObjectNotFoundException, AuthStatusException, AuthLoginException;
    /**
     * @see se.anatom.ejbca.ca.sign.ISignSession
     */ 
    public Certificate createCertificate(String username, String password, PublicKey pk, boolean[] keyusage) throws ObjectNotFoundException, AuthStatusException, AuthLoginException;
    /**
     * @see se.anatom.ejbca.ca.sign.ISignSession
     */ 
    public Certificate createCertificate(String username, String password, PublicKey pk, int keyusage) throws ObjectNotFoundException, AuthStatusException, AuthLoginException;
    /**
     * @see se.anatom.ejbca.ca.sign.ISignSession
     */ 
    public Certificate createCertificate(String username, String password, int certType, PublicKey pk) throws ObjectNotFoundException, AuthStatusException, AuthLoginException;
    /**
     * @see se.anatom.ejbca.ca.sign.ISignSession
     */ 
    public Certificate createCertificate(String username, String password, Certificate incert) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, SignRequestSignatureException;
    /**
     * @see se.anatom.ejbca.ca.sign.ISignSession
     */ 
    public Certificate createCertificate(String username, String password, byte[] pkcs10req) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, SignRequestException, SignRequestSignatureException;
    /**
     * @see se.anatom.ejbca.ca.sign.ISignSession
     */ 
    public Certificate createCertificate(String username, String password, byte[] pkcs10req, int keyUsage) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, SignRequestException, SignRequestSignatureException;
    /**
     * @see se.anatom.ejbca.ca.sign.ISignSession
     */ 
    public X509CRL createCRL(Vector certs);
}
