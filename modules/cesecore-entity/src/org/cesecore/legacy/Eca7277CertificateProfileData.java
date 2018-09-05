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

package org.cesecore.legacy;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfileData;

/**
 * CertificateProfileData was one of the old classes that used serialized binary data in a blob in the database.
 * In order for CertificateProfileData.getProtectString to produce a String, the object was read in and then the
 * getData() method returned a LinkedHashMap. StringBuilder.build() called toString() on the LinkedHashMap, which
 * in turn called toString() on the objects in it. One of the objects was an ApprovalRequestType. In ECA-6518 the
 * toString() method was overridden in this enum, causing the string representation to be different. This caused
 * rowProtection signature verification to fail when you upgraded from a version <=6.11 to a version >=6.12.
 *
 * The aim of Eca7277CertificateProfileData is to fix this problem. Eca7277CertificateProfileData behaves exactly
 * like CertificateProfileData, but replaces any faulty substrings found in the protect string returned by
 * getProtectString() before returning it to the caller.
 *
 * This class and all references to it can be safely removed when we drop support for EJBCA 6.14.
 *
 * @version $Id$
 */
@SuppressWarnings("serial")
@Deprecated
public class Eca7277CertificateProfileData extends CertificateProfileData {
    private final static Logger log = Logger.getLogger(Eca7277CertificateProfileData.class);

    public Eca7277CertificateProfileData(final CertificateProfileData data) {
        super(data.getId(), data.getCertificateProfileName(), data.getCertificateProfile());
        this.setRowVersion(data.getRowVersion());
        this.setRowProtection(data.getRowProtection());
    }

    @Override
    protected String getProtectString(final int rowversion) {
        if (log.isDebugEnabled()) {
            log.debug("Verification of row protected data for Certificate Profile " + getCertificateProfileName()
                    + " failed. Trying to fix the protect string now.");
        }
        // Signature was computer over "Add or Edit End Entity" ect. in EJBCA 6.11-6.14
        return super.getProtectString(rowversion)
            .replace("ADDEDITENDENTITY=", "Add or Edit End Entity=")
            .replace("KEYRECOVER=", "Key Recovery=")
            .replace("REVOCATION=", "Revocation=")
            .replace("ACTIVATECA=", "CA Activation=");
    }
}