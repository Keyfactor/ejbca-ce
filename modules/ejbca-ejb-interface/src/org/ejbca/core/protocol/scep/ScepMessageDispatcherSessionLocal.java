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

package org.ejbca.core.protocol.scep;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.protocol.NoSuchAliasException;
import org.ejbca.ui.web.protocol.CertificateRenewalException;

@Local
public interface ScepMessageDispatcherSessionLocal extends ScepMessageDispatcherSession {

    /**
     * TODO Docs
     * @param authenticationToken
     * @param pkiMessageBytes
     * @param cmpConfigurationAlias
     * @return
     * @throws NoSuchAliasException 
     * @throws CertificateEncodingException 
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException 
     * @throws CertificateRenewalException 
     * @throws CertificateExtensionException 
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     * @throws CertificateException 
     * @throws SignatureException 
     * @throws InvalidAlgorithmException 
     * @throws CAOfflineException 
     * @throws IllegalValidityException 
     * @throws CertificateSerialNumberException 
     * @throws CertificateRevokeException 
     * @throws CertificateCreateException 
     * @throws IllegalNameException 
     * @throws AuthLoginException 
     * @throws AuthStatusException 
     * @throws SignRequestSignatureException 
     * @throws SignRequestException 
     * @throws IllegalKeyException 
     * @throws CryptoTokenOfflineException 
     * @throws CustomCertificateSerialNumberException 
     * @throws NoSuchEndEntityException 
     * @throws InvalidKeyException 
     */
    byte[] dispatchRequest(AuthenticationToken authenticationToken, String operation, String message, String scepConfigurationAlias) throws NoSuchAliasException, 
        CertificateEncodingException, CADoesntExistsException, AuthorizationDeniedException, InvalidKeyException, NoSuchEndEntityException, CustomCertificateSerialNumberException, 
        CryptoTokenOfflineException, IllegalKeyException, SignRequestException, SignRequestSignatureException, AuthStatusException, AuthLoginException, IllegalNameException, 
        CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, 
        SignatureException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, CertificateExtensionException, CertificateRenewalException;
}
