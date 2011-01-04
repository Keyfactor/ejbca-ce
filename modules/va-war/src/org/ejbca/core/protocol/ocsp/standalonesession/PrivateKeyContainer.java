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

package org.ejbca.core.protocol.ocsp.standalonesession;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * An object of this class is used to handle an OCSP signing key.
 * Please note that {@link #getKey()} is blocking during re-keying but {@link #getCertificate()} is not.
 * This means that {@link #getCertificate()} must always be called after {@link #getKey()}.
 * 
 * @author primelars
 * @version  $Id$
 */
interface PrivateKeyContainer {

    /**
     * Initiates the container. Start to wait to renew key.
     * @param chain the certificate chain for the key
     * @param caid the EJBCA id of the key.
     */
    public abstract void init(List<X509Certificate> chain, int caid);

    /**
     * Gets the OCSP signing key. The method is blocking while re-keying.
     * If a the certificate of the key is needed you must call {@link #getCertificate()} after this method.
     * @return the key
     * @throws Exception
     */
    public abstract PrivateKey getKey() throws Exception;

    /**
     * Must always be called after key fetched with {@link #getKey()} has been used.
     */
    public abstract void releaseKey();

    /**
     * Sets the keystore to be used.
     * @param keyStore
     * @throws Exception
     */
    public abstract void set(KeyStore keyStore) throws Exception;

    /**
     * removes key
     */
    public abstract void clear();

    /**
     * Checks if key is OK to use
     * @return true if OK
     */
    public abstract boolean isOK();

    /**
     * You got to call {@link #getKey()} before this method in order to always get the certificate of the key.
     * @return the certificate of the key
     */
    public abstract X509Certificate getCertificate();

    /**
     * Destroys the container. Waiting to renew keys stopped.
     */
    public abstract void destroy();

}