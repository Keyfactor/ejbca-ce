package se.anatom.ejbca.ca.sign;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.Vector;
import java.util.Collection;
import java.util.HashMap;

import javax.ejb.ObjectNotFoundException;

import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.IllegalKeyException;
import se.anatom.ejbca.ca.exception.SignRequestException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.protocol.IRequestMessage;
import se.anatom.ejbca.protocol.IResponseMessage;

/**
 * Local interface for EJB, unforturnately this must be a copy of the remote interface except that
 * RemoteException is not thrown. Creates certificates.
 *
 * @version $Id: ISignSessionLocal.java,v 1.14 2003-09-03 17:36:44 herrvendil Exp $
 *
 * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
 */
public interface ISignSessionLocal extends javax.ejb.EJBLocalObject {
    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public Collection getCertificateChain(Admin admin, int caid);
        
     /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public byte[] createPKCS7(Admin admin, Certificate cert)
        throws SignRequestSignatureException;


    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */

    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException;


    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        PublicKey pk, boolean[] keyusage)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException;


    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        PublicKey pk, int keyusage)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException;


    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        int certType, PublicKey pk)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException;

    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        Certificate incert)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, SignRequestSignatureException;


    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        IRequestMessage req)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, SignRequestException, SignRequestSignatureException;


    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        IRequestMessage req, int keyUsage)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, SignRequestException, SignRequestSignatureException;

    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public IResponseMessage createCertificate(Admin admin, IRequestMessage req, int keyUsage,
        Class responseClass)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, SignRequestException, SignRequestSignatureException;


    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public X509CRL createCRL(Admin admin, int caid, Vector certs);
    

    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */    
    public void publishCACertificate(Admin admin, Collection certificatechain, Collection publishers, boolean rootca);

    public HashMap getPublisherIdToNameMap(Admin admin);
}

