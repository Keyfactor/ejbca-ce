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
public final class CertificateTransparencyFactory {

    private static final String IMPLEMENTATION_CLASSNAME = "org.cesecore.certificates.certificatetransparency.CertificateTransparencyImpl";
    
    private static CertificateTransparency ct;
    private static boolean triedToLoad;
    
    static {
        // getInstance might have been called by static code before we get here 
        if (ct == null) {
            loadImplClass();
        }
    }
    
    // This class can't be instantiated
    private CertificateTransparencyFactory() { }
    
    private static void loadImplClass() {
        try {
            // No lock is used since the CertificateTransparencyImpl class has no state
            // so it's OK with multiple instances.
            ct = (CertificateTransparency)Class.forName(IMPLEMENTATION_CLASSNAME).newInstance();
        } catch (Exception e) { // NOPMD must catch everything since it can be called from static-blocks and initializers
        }
        triedToLoad = true;
    }

    /**
     * Returns the implementation of the CertificateTransparency interface, or null if not available.
     * No exceptions can ever be thrown by this method, so it's safe to call from static-blocks and initializers.
     */
    public static CertificateTransparency getInstance() {
        if (!triedToLoad) {
            loadImplClass();
        }
        return ct;
    }
    
    /**
     * Returns true if the implementation class is available. No exceptions can be thrown by this method. 
     */
    public static boolean isCTAvailable() {
        return getInstance() != null;
    }

}
