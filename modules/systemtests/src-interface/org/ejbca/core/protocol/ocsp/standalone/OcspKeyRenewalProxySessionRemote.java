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
package org.ejbca.core.protocol.ocsp.standalone;

import java.security.InvalidKeyException;
import java.security.KeyStoreException;

import javax.ejb.Remote;

import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * @version $Id$
 *
 */
@Remote
public interface OcspKeyRenewalProxySessionRemote {
    
    /**
     * This method causes the standalone OCSP responder to renew its keystores. 
     * 
     * @param signerSubjectDN subject DN of the signing key to be renewed. The string "all" will result 
     * @throws KeyStoreException 
     * @throws CryptoTokenOfflineException 
     * @throws InvalidKeyException 
     * 
     */
    void renewKeyStores(String signerSubjectDN) throws KeyStoreException, CryptoTokenOfflineException, InvalidKeyException;
    
    /**
     * Commands the key renewal timer to fire in 1 second, waits for that time, then resets. 
     * @throws InterruptedException 
     */
    void setTimerToFireInOneSecond() throws InterruptedException;

}
