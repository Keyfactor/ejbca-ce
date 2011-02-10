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
package org.ejbca.core.ejb.ra;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.ejb.CreateException;
import javax.ejb.ObjectNotFoundException;
import javax.persistence.PersistenceException;

import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;

/**
 * @version $Id$
 */
public interface CertificateRequestSession {

	/**
	 * Edits or adds a user and generates a certificate for that user in a single transaction.
     * 
	 * @param admin is the requesting administrator
	 * @param userdata contains information about the user that is about to get a certificate
	 * @param req is the certificate request, base64 encoded binary request, in the format specified in the reqType parameter
	 * @param reqType is one of SecConst.CERT_REQ_TYPE_..
	 * @param hardTokenSN is the hard token to associate this or null
	 * @param responseType is one of SecConst.CERT_RES_TYPE_...
     * @return a encoded certificate of the type specified in responseType 
	 */
    public byte[] processCertReq(Admin admin, UserDataVO userdata, String req, int reqType, String hardTokenSN, int responseType) throws CADoesntExistsException,
            AuthorizationDeniedException, NotFoundException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
            SignatureException, IOException, ObjectNotFoundException, CreateException, CertificateException, UserDoesntFullfillEndEntityProfile,
            ApprovalException, EjbcaException;

	/**
	 * Edits or adds a user and generates a certificate for that user in a single transaction.
     * Username and password in userdata and req message must match.
     * 
	 * @param admin is the requesting administrator
	 * @param userdata contains information about the user that is about to get a certificate
	 * @param req is the certificate request, base64 encoded binary request, in the format specified in the reqType parameter
	 * @param reqType is one of SecConst.CERT_REQ_TYPE_..
	 * @param hardTokenSN is the hard token to associate this or null
	 * @param responseType is one of SecConst.CERT_RES_TYPE_...
     * @return a encoded certificate of the type specified in responseType 
	 */
    public IResponseMessage processCertReq(Admin admin, UserDataVO userdata, IRequestMessage req, Class responseClass) throws PersistenceException,
            AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException;

	/**
	 * Edits or adds a user and generates a keystore for that user in a single transaction.
     * Used from EjbcaWS.
     * 
	 * @param admin is the requesting administrator
	 * @param userdata contains information about the user that is about to get a keystore
	 * @param hardTokenSN is the hard token to associate this or null
     * @param keyspec name of ECDSA key or length of RSA and DSA keys  
     * @param keyalg AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmConstants.KEYALGORITHM_DSA or AlgorithmConstants.KEYALGORITHM_ECDSA
     * @param createJKS true to create a JKS, false to create a PKCS12
     * @return an encoded keystore of the type specified in responseType 
     */
    public byte[] processSoftTokenReq(Admin admin, UserDataVO userdata, String hardTokenSN, String keyspec, String keyalg, boolean createJKS) throws CADoesntExistsException,
            AuthorizationDeniedException, NotFoundException, InvalidKeyException, InvalidKeySpecException, NoSuchProviderException, SignatureException, IOException,
            ObjectNotFoundException, CreateException, CertificateException, UserDoesntFullfillEndEntityProfile, ApprovalException, EjbcaException,
            KeyStoreException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, PersistenceException;
}
