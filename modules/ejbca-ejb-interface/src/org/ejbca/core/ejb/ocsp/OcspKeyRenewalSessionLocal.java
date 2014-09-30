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
package org.ejbca.core.ejb.ocsp;

import java.security.InvalidKeyException;
import java.security.KeyStoreException;

import javax.ejb.Local;

import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * @version $Id$
 *
 */
@Local
public interface OcspKeyRenewalSessionLocal {

     final String RENEW_ALL_KEYS = "all";
    
    /**
     * This method causes the standalone OCSP responder to renew its keystores. 
     * 
     * This method will use the password stored in configuration, and is mainly used for automatic key renewal. Will throw
     * an exception if passwords can't be set in memory.
     * 
     * @param signerSubjectDN subject DN of the signing key to be renewed. The string OcspKeyRenewalSessionLocal.RENEW_ALL_KEYS will result 
     * @throws KeyStoreException if p11 key store hasn't been activated
     * @throws CryptoTokenOfflineException if Crypto Token is not available or connected, or key with alias does not exist.
     * @throws InvalidKeyException if the public key can not be used to verify a string signed by the private key, because the key is wrong or the 
     * signature operation fails for other reasons such as a NoSuchAlgorithmException or SignatureException.
     * 
     */
    void renewKeyStores(String signerSubjectDN) throws KeyStoreException, CryptoTokenOfflineException, InvalidKeyException; 
    
    /**
     * Cancels all running timers and starts the initial timer. This method should be called from a servlet and be used to start the rekeying 
     * timer at startup.
     */
    void startTimer();

}
