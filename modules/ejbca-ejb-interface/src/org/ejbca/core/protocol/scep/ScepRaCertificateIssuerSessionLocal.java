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

import java.security.cert.X509Certificate;

import org.cesecore.authentication.tokens.AuthenticationToken;

import jakarta.ejb.Local;

/**
 * I generate certificates to encrypt/sign SCEP messages.
 */
@Local
public interface ScepRaCertificateIssuerSessionLocal {

    /**
     * Creates a SCEP encryption certificate using an internal certificate profile
     * 
     * @param authenticationToken an authentication token  
     * @param caName the name of the CA
     * @param cryptoTokenId the id of the crypto token to use
     * @param keyAlias the alias of the encryption key
     * @return the encryption certificate
     * @throws ScepEncryptionCertificateIssuanceException if any error happened during issuance
     */
    X509Certificate issueEncryptionCertificate(AuthenticationToken authenticationToken, String caName, int cryptoTokenId,
            String keyAlias) throws ScepEncryptionCertificateIssuanceException;
    

    /**
     * Creates a SCEP signing certificate using an internal certificate profile
     * 
     * @param authenticationToken an authentication token  
     * @param caName the name of the CA
     * @param cryptoTokenId the id of the crypto token to use
     * @param keyAlias the alias of the signing key
     * @return the signing certificate
     * @throws ScepEncryptionCertificateIssuanceException if any error happened during issuance
     */
    X509Certificate issueSigningCertificate(AuthenticationToken authenticationToken, String caName, int cryptoTokenId,
            String keyAlias) throws ScepEncryptionCertificateIssuanceException;

}
