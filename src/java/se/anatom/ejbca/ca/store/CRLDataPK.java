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
 
package se.anatom.ejbca.ca.store;

/**
 * The primary key of the CRL is the SHA1 fingerprint which should be unique.
 */
public class CRLDataPK implements java.io.Serializable {
    public String fingerprint;

    /**
     * Creates a new CRLDataPK object.
     *
     * @param fingerprint DOCUMENT ME!
     */
    public CRLDataPK(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    /**
     * Creates a new CRLDataPK object.
     */
    public CRLDataPK() {
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int hashCode() {
        return fingerprint.hashCode();
    }

    /**
     * DOCUMENT ME!
     *
     * @param obj DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean equals(Object obj) {
        return ((CRLDataPK) obj).fingerprint.equals(fingerprint);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String toString() {
        return fingerprint.toString();
    }
}
