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

import javax.ejb.Remote;

/**
 * Remote interface for CertificateRequestSession.
 */
@Remote
public interface CertificateRequestSessionRemote {
    /**
     * Edits or adds a user and generates a certificate for that user in a
     * single transaction.
     * 
     * @param admin
     *            is the requesting administrator
     * @param userdata
     *            contains information about the user that is about to get a
     *            certificate
     * @param req
     *            is the certificate request, base64 encoded binary request, in
     *            the format specified in the reqType parameter
     * @param reqType
     *            is one of SecConst.CERT_REQ_TYPE_..
     * @param hardTokenSN
     *            is the hard token to associate this or null
     * @param responseType
     *            is one of SecConst.CERT_RES_TYPE_...
     * @return a encoded certificate of the type specified in responseType
     */
    public byte[] processCertReq(org.ejbca.core.model.log.Admin admin, org.ejbca.core.model.ra.UserDataVO userdata, java.lang.String req, int reqType,
            java.lang.String hardTokenSN, int responseType) throws org.ejbca.core.model.ca.caadmin.CADoesntExistsException,
            org.ejbca.core.model.authorization.AuthorizationDeniedException, org.ejbca.core.model.ra.NotFoundException, java.security.InvalidKeyException,
            java.security.NoSuchAlgorithmException, java.security.spec.InvalidKeySpecException, java.security.NoSuchProviderException,
            java.security.SignatureException, java.io.IOException, javax.ejb.ObjectNotFoundException, javax.ejb.CreateException,
            java.security.cert.CertificateException, org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile,
            org.ejbca.core.model.approval.ApprovalException, org.ejbca.core.EjbcaException, java.rmi.RemoteException;

    /**
     * Edits or adds a user and generates a certificate for that user in a
     * single transaction.
     * 
     * @param admin
     *            is the requesting administrator
     * @param userdata
     *            contains information about the user that is about to get a
     *            certificate
     * @param req
     *            is the certificate request, base64 encoded binary request, in
     *            the format specified in the reqType parameter
     * @param reqType
     *            is one of SecConst.CERT_REQ_TYPE_..
     * @param hardTokenSN
     *            is the hard token to associate this or null
     * @param responseType
     *            is one of SecConst.CERT_RES_TYPE_...
     * @return a encoded certificate of the type specified in responseType
     * @throws EjbcaException
     * @throws UserDoesntFullfillEndEntityProfile
     * @throws AuthorizationDeniedException
     * @throws DuplicateKeyException
     * @throws EjbcaException
     */
    public org.ejbca.core.protocol.IResponseMessage processCertReq(org.ejbca.core.model.log.Admin admin, org.ejbca.core.model.ra.UserDataVO userdata,
            org.ejbca.core.protocol.IRequestMessage req, java.lang.Class responseClass) throws javax.ejb.DuplicateKeyException,
            org.ejbca.core.model.authorization.AuthorizationDeniedException, org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile,
            org.ejbca.core.EjbcaException, java.rmi.RemoteException;

    /**
     * Edits or adds a user and generates a keystore for that user in a single
     * transaction. Used from EjbcaWS.
     * 
     * @param admin
     *            is the requesting administrator
     * @param userdata
     *            contains information about the user that is about to get a
     *            keystore
     * @param hardTokenSN
     *            is the hard token to associate this or null
     * @param keyspec
     *            name of ECDSA key or length of RSA and DSA keys
     * @param keyalg
     *            AlgorithmConstants.KEYALGORITHM_RSA,
     *            AlgorithmConstants.KEYALGORITHM_DSA or
     *            AlgorithmConstants.KEYALGORITHM_ECDSA
     * @param createJKS
     *            true to create a JKS, false to create a PKCS12
     * @return an encoded keystore of the type specified in responseType
     */
    public byte[] processSoftTokenReq(org.ejbca.core.model.log.Admin admin, org.ejbca.core.model.ra.UserDataVO userdata, java.lang.String hardTokenSN,
            java.lang.String keyspec, java.lang.String keyalg, boolean createJKS) throws org.ejbca.core.model.ca.caadmin.CADoesntExistsException,
            org.ejbca.core.model.authorization.AuthorizationDeniedException, org.ejbca.core.model.ra.NotFoundException, java.security.InvalidKeyException,
            java.security.spec.InvalidKeySpecException, java.security.NoSuchProviderException, java.security.SignatureException, java.io.IOException,
            javax.ejb.ObjectNotFoundException, javax.ejb.CreateException, java.security.cert.CertificateException,
            org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile, org.ejbca.core.model.approval.ApprovalException, org.ejbca.core.EjbcaException,
            java.security.KeyStoreException, java.security.NoSuchAlgorithmException, java.security.InvalidAlgorithmParameterException, java.rmi.RemoteException;

}
