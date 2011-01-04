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

import java.security.cert.Certificate;
import java.util.Collection;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Factory for creating a {@link CertificateCache} object to be used by the OCSP responder of the CA.
 * This is class is just used for system testing.
 * 
 * @author primelars
 * @version $Id$
 * 
 */
public class CertificateCacheTstFactory {
    private static ICertificateCache instance = null;
    private static final Lock lock = new ReentrantLock();
    /**
     * @return  {@link CertificateCache} for the CA.
     */
    public static ICertificateCache getInstance(Collection<Certificate> testcerts) {
        if (instance != null) {
        	return instance;
        }
        lock.lock();
        try {
        	if ( instance==null ) {
        		instance = new CertificateCache(testcerts);
        	}
    		return instance;
        } finally {
        	lock.unlock();
        }
    }
}
