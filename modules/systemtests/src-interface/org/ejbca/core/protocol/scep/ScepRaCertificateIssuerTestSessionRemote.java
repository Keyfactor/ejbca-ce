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

import jakarta.ejb.Remote;

/**
 * Allows testing of ScepRaCertificateIssuerSession
 */

@Remote
public interface ScepRaCertificateIssuerTestSessionRemote {
    
    X509Certificate issueEncryptionCertificate(AuthenticationToken authenticationToken, String caName, int cryptoTokenId,
            String keyAlias) throws ScepEncryptionCertificateIssuanceException;
    
    X509Certificate issueSigningCertificate(AuthenticationToken authenticationToken, String caName, int cryptoTokenId,
            String keyAlias) throws ScepEncryptionCertificateIssuanceException;

}
