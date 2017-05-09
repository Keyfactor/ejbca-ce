/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.CertificateSignatureException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

/**
 * 
 * @version $Id$
 *
 */
public interface KeyStoreCreateSession {
    
    /**
     * This method generates a new pkcs12 or jks token for a user, and key recovers the token, if the user is configured for that in EJBCA.
     * 
     * @param administrator administrator performing the action
     * @param username username in ejbca
     * @param password password for user
     * @param caid caid of the CA the user is registered for
     * @param keyspec name of ECDSA key or length of RSA and DSA keys (endEntityInformation.extendedInformation.keyStoreAlgorithmSubType has priority over this value) 
     * @param keyalg AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmConstants.KEYALGORITHM_DSA or AlgorithmConstants.KEYALGORITHM_ECDSA (endEntityInformation.extendedInformation.keyStoreAlgorithmType has priority over this value)
     * @param createJKS true to create a JKS, false to create a PKCS12
     * @param loadkeys true if keys should be recovered
     * @param savekeys true if generated keys should be stored for keyrecovery
     * @param reusecertificate true if the old certificate should be reused for a recovered key
     * @param endEntityProfileId the end entity profile the user is registered for
     * 
     * @return a keystore
     * 
     * @throws AuthorizationDeniedException if the authentication token was not allowed access to the EEP or CA of the end entity, to recover keys,
     * to issue certificates
     * @throws KeyStoreException if keys were set to be recovered, but no key recovery data was found
     * @throws InvalidAlgorithmParameterException  if the given parameters (keyspec, keyalg) are inappropriate for this key pair generator.
     * @throws CADoesntExistsException if the CA defined by caid does not exist
     * @throws AuthLoginException If the password was incorrect.
     * @throws AuthStatusException If the end entity's status is incorrect.
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either
     *             missing unique index in database, or certificate profile does not allow it
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CAOfflineException if the CA was offline
     * @throws IllegalValidityException if the validity defined by notBefore and notAfter was invalid
     * @throws CryptoTokenOfflineException if the crypto token for the CA wasn't found 
     * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA. 
     * @throws CertificateRevokeException (rollback) if certificate was meant to be issued revoked, but could not. 
     * @throws IllegalNameException if the certificate request contained an illegal name 
     * @throws CertificateCreateException (rollback) if certificate couldn't be created. 
     * @throws IllegalKeyException if the public key didn't conform to the constrains of the CA's certificate profile. 
     * @throws NoSuchEndEntityException if the end entity was not found
     * @throws EndEntityProfileValidationException if the password doesn't fulfill the demands set by the EE profile
     * @throws CertificateSignatureException if verification of the CA certificate failed
     * @throws InvalidKeySpecException if the key specification defined in keys couldn't be found
     * @throws NoSuchAlgorithmException if the algorithm defined in the keys couldn't be found
     * @throws CertificateException if there was a problem with the certificate
     * @throws CertificateEncodingException if there was a problem with the certificate
     */
    KeyStore generateOrKeyRecoverToken(AuthenticationToken administrator, String username, String password, int caid, String keyspec, String keyalg,
            boolean createJKS, boolean loadkeys, boolean savekeys, boolean reusecertificate, int endEntityProfileId)
            throws AuthorizationDeniedException, KeyStoreException, InvalidAlgorithmParameterException, CADoesntExistsException, IllegalKeyException,
            CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException, AuthStatusException, AuthLoginException, EndEntityProfileValidationException,
            NoSuchEndEntityException, CertificateSignatureException, CertificateEncodingException, CertificateException, NoSuchAlgorithmException,
            InvalidKeySpecException;

}
