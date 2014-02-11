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
package org.cesecore.certificates.certificatetransparency;

/**
 * Loads and holds an instance of the Certificate Transparency implementation, if available.
 * 
 * @version $Id$
 */
public enum CertificateTransparencyFactory {

    SINGLETON;

    private static final String IMPLEMENTATION_CLASSNAME = "org.cesecore.certificates.certificatetransparency.CertificateTransparencyImpl";


    private final CertificateTransparency ct;
    
    private CertificateTransparencyFactory() {
        CertificateTransparency instance;
        try {
            // No lock is used since the CertificateTransparencyImpl class has no state
            // so it's OK with multiple instances.
            instance = (CertificateTransparency)Class.forName(IMPLEMENTATION_CLASSNAME).newInstance();
        } catch (Exception e) { // NOPMD not a good idea to throw an exception in a enum constructor
            instance = null;
        }
        ct = instance;
    }
    
    /**
     * Returns the implementation of the CertificateTransparency interface, or null if not available.
     * No exceptions can ever be thrown by this method, so it's safe to call from static-blocks and initializers.
     */
    public static CertificateTransparency getInstance() {
        return SINGLETON.ct;
    }
    
    /**
     * Returns true if the implementation class is available. No exceptions can be thrown by this method. 
     */
    public static boolean isCTAvailable() {
        return getInstance() != null;
    }

}
