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
package org.ejbca.core.protocol.msae;

import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.ejbca.core.ejb.config.ClearCacheSessionBean;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

public interface KecCache {

    /**
     * Gets a valid KEC certificate from the cache, or calls for a valid one to be generated and cached.
     * @param admin
     * @param cAId
     * @param cPId
     * @return
     * @throws CertificateEncodingException
     * @throws InvalidAlgorithmException
     * @throws CryptoTokenOfflineException
     * @throws CertificateCreateException
     * @throws CAOfflineException
     * @throws IllegalValidityException
     * @throws SignatureException
     * @throws IllegalKeyException
     * @throws OperatorCreationException
     * @throws IllegalNameException
     * @throws AuthorizationDeniedException
     * @throws CertificateExtensionException
     * @throws KeyArchivalException
     */
    default Certificate getCachedKEC(final AuthenticationToken admin, final int cAId, final int cPId)
            throws CertificateEncodingException, InvalidAlgorithmException, CryptoTokenOfflineException, CertificateCreateException,
            CAOfflineException, IllegalValidityException, SignatureException, IllegalKeyException, OperatorCreationException, IllegalNameException,
            AuthorizationDeniedException, CertificateExtensionException, KeyArchivalException {
        throw new UnsupportedOperationException("KEC cache methods are only supported in EJBCA Enterprise");
    }

    /**
     * Clears the cache, called from {@link ClearCacheSessionBean}
     */
    default void flushKecCache() {
        throw new UnsupportedOperationException("KEC cache methods are only supported in EJBCA Enterprise");
    }
}
