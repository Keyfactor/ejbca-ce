/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.keys.util.KeyPairWrapper;

/**
 * Helper methods for EJB calls, currently only wrapping and unwrapping certificates in a way such that they can always be deserialized.
 * 
 * @see CertificateWrapper
 * @see KeyPairWrapper
 * 
 * @version $Id$
 */
public final class EJBTools {

    /** May not be instantiated */
    private EJBTools() { }
    
    /**
     * Wraps a Certificate object in a CertificateWrapper, which can be sent over Remote EJB even if it's supported only by the BC provider.
     * @param cert Certificate or null.
     * @return Wrapped object, or null if cert was null.
     */
    public static CertificateWrapper wrap(final Certificate cert) {
        if (cert == null) {
            return null;
        } else {
            return new CertificateSerializableWrapper(cert);
        }
    }
    
    /**
     * Unwraps a Certificate from a CertificateWrapper.
     * @param certWrapper Wrapped certificate or null.
     * @return Certificate object, or null if certWrapper was null.
     */
    public static Certificate unwrap(final CertificateWrapper certWrapper) {
        if (certWrapper == null) {
            return null;
        } else {
            return certWrapper.getCertificate();
        }
    }
    
    /**
     * Wraps certificate objects in a collection.
     * @param certs List of certificates or null. The list may contain null values, which will simply be copied as null values.
     * @return List of wrapped certificates, or null if certs was null.
     * @see EJBTools#wrap
     */
    public static List<CertificateWrapper> wrapCertCollection(final Collection<Certificate> certs) {
        if (certs == null) {
            return null;
        } else {
            final List<CertificateWrapper> list = new ArrayList<>(certs.size());
            for (final Certificate cert : certs) {
                list.add(wrap(cert));
            }
            return list;
        }
    }
    
    /**
     * Unwraps wrapped certificates in a collection.
     * @param wrappedCerts List of wrapped certificates or null. The list may contain null values, which will simply be copied as null values.
     * @return List of certificate objects, or null if certs was null.
     * @see EJBTools#unwrap
     */
    public static List<Certificate> unwrapCertCollection(final Collection<CertificateWrapper> wrappedCerts) {
        if (wrappedCerts == null) {
            return null;
        } else {
            final List<Certificate> list = new ArrayList<>(wrappedCerts.size());
            for (final CertificateWrapper wrapped : wrappedCerts) {
                list.add(unwrap(wrapped));
            }
            return list;
        }
    }
    
    /**
     * Wraps a KeyPair object in a KeyPairWrapper, which can be sent over Remote EJB even if it's supported only by the BC provider.
     * @param keyPair KeyPair or null.
     * @return Wrapped object, or null if cert was null.
     */
    public static KeyPairWrapper wrap(final KeyPair keyPair) {
        if (keyPair == null) {
            return null;
        } else {
            return new KeyPairWrapper(keyPair);
        }
    }
    
    /**
     * Unwraps a KeyPair from a KeyPairWrapper.
     * @param keyPairWrapper Wrapped KeyPair or null.
     * @return KeyPair object, or null if keyPairWrapper was null.
     */
    public static KeyPair unwrap(final KeyPairWrapper keyPairWrapper) {
        if (keyPairWrapper == null) {
            return null;
        } else {
            return keyPairWrapper.getKeyPair();
        }
    }
}
