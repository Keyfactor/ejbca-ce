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
package org.ejbca.core.protocol.certificatestore;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.ejbca.core.ejb.ca.store.CertificateStoreSessionLocal;

/**
 * Factory for creating a {@link CertificateCache} object to be used by the OCSP responder of the CA.
 * 
 * @author primelars
 * @version $Id$
 * 
 */
public class CertificateCacheFactory {
    private static ICertificateCache instance = null;
    private static final Lock lock = new ReentrantLock();
    /**
     * @return  {@link CertificateCache} for the CA.
     */
    public static ICertificateCache getInstance(CertificateStoreSessionLocal certificateStoreSession) {
        if (instance != null) {
        	return instance;
        }
        lock.lock();
        try {
        	if ( instance==null ) {
        		instance = new CertificateCache(certificateStoreSession);
        	}
    		return instance;
        } finally {
        	lock.unlock();
        }
    }
}
