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
package org.ejbca.core.ejb.ocsp.standalone;

import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;

import javax.ejb.Local;

import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;

/**
 * @version $Id$
 *
 */
@Local
public interface OcspKeyRenewalSessionLocal {

    static final String RENEW_ALL_KEYS = "all";
    
    /**
     * This method causes the standalone OCSP responder to renew its keystores. 
     * 
     * This method will use the password stored in configuration, and is mainly used for automatic key renewal. 
     * 
     * @param signerSubjectDN subject DN of the signing key to be renewed. The string "all" (as represented by the constant 
     * TokenAndChainCache.RENEW_ALL_KEYS) will result 
     * @throws KeyStoreException if p11 key store hasn't been activated
     * @throws CryptoTokenOfflineException 
     * @throws InvalidKeyException if the public key can not be used to verify a string signed by the private key, because the key is wrong or the 
     * signature operation fails for other reasons such as a NoSuchAlgorithmException or SignatureException.
     * 
     */
    void renewKeyStores(String signerSubjectDN) throws KeyStoreException, CryptoTokenOfflineException, InvalidKeyException;
    
    /**
     * This method causes the standalone OCSP responder to renew its keystores. 
     * 
     * @param signerSubjectDN signerSubjectDN subject DN of the signing key to be renewed. The string "all" (as represented by the constant 
     * TokenAndChainCache.RENEW_ALL_KEYS) will result 
     * @param p11Password password to the p11 key store.
     * @throws KeyStoreException if p11 key store hasn't been activated
     * @throws CryptoTokenOfflineException 
     * @throws CertificateException if any error occurred while generating the certificate chain.
     * @throws InvalidKeyException if the public key can not be used to verify a string signed by the private key, because the key is wrong or the 
     * signature operation fails for other reasons such as a NoSuchAlgorithmException or SignatureException.
     */
    void renewKeyStores(String signerSubjectDN, String p11Password) throws KeyStoreException, CryptoTokenOfflineException, CertificateException, InvalidKeyException;
    

    void setEjbcaWs(EjbcaWS ejbcaWS);

}
