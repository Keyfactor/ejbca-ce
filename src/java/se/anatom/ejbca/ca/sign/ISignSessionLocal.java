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
 
package se.anatom.ejbca.ca.sign;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.Vector;
import java.util.Collection;
import java.util.HashMap;

import javax.ejb.ObjectNotFoundException;

import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceResponse;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.CADoesntExistsException;
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
 * @version $Id: ISignSessionLocal.java,v 1.22 2004-04-16 07:38:58 anatom Exp $
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
    public byte[] createPKCS7(Admin admin, Certificate cert) throws CADoesntExistsException, SignRequestSignatureException;

    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public byte[] createPKCS7(Admin admin, int caId) throws CADoesntExistsException;
    

    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException;


    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        PublicKey pk, boolean[] keyusage)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException;


    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        PublicKey pk, int keyusage)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException;


    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        int certType, PublicKey pk)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException;

    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        Certificate incert)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException, SignRequestSignatureException;

    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public IResponseMessage createCertificate(Admin admin, IRequestMessage req, Class responseClass)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException;

    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public IResponseMessage createCertificate(Admin admin, IRequestMessage req, int keyUsage,
        Class responseClass)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException;

    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public X509CRL createCRL(Admin admin, int caid, Vector certs);

	/**
	 * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
	 */
    
	public ExtendedCAServiceResponse extendedService(Admin admin, int caid, ExtendedCAServiceRequest request) 
	  throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, CADoesntExistsException;    
    
    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */    
    public void publishCACertificate(Admin admin, Collection certificatechain, Collection publishers, int certtype);

    public HashMap getPublisherIdToNameMap(Admin admin);
    
    
}

