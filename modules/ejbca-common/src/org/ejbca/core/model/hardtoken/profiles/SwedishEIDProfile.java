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

package org.ejbca.core.model.hardtoken.profiles;

import java.util.ArrayList;

import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.ejbca.core.model.hardtoken.HardTokenConstants;

/**
 * Hard token profile with a goal to fulfill Swedish EID standard.
 * 
 * @version $Id$
 */
public class SwedishEIDProfile extends EIDProfile {

    private static final long serialVersionUID = -4972472165710748612L;

    // Public Constants
    public static final int TYPE_SWEDISHEID = HardTokenConstants.TOKENTYPE_SWEDISHEID;

    public static final float LATEST_VERSION = 4;

    public static final int CERTUSAGE_SIGN = 0;
    public static final int CERTUSAGE_AUTHENC = 1;

    public static final int PINTYPE_AUTHENC_SAME_AS_SIGN = 100;

    // Protected Constants
    protected static final int NUMBEROFCERTIFICATES = 2;

    // Private Constants
    public static final int[] AVAILABLEMINIMUMKEYLENGTHS = { 1024, 2048 };

    // Protected Fields

    private String[][] SUPPORTEDTOKENS = { { "TODO" } };

    // Default Values
    public SwedishEIDProfile() {
        super();
        init();

    }

    private void init() {
        data.put(TYPE, Integer.valueOf(TYPE_SWEDISHEID));

        ArrayList<Integer> certprofileids = new ArrayList<Integer>(NUMBEROFCERTIFICATES);
        certprofileids.add(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENSIGN));
        certprofileids.add(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTHENC));
        data.put(CERTIFICATEPROFILEID, certprofileids);

        ArrayList<Boolean> certWritable = new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
        certWritable.add(Boolean.FALSE);
        certWritable.add(Boolean.FALSE);
        data.put(CERTWRITABLE, certWritable);

        ArrayList<Integer> caids = new ArrayList<Integer>(NUMBEROFCERTIFICATES);
        caids.add(Integer.valueOf(CAID_USEUSERDEFINED));
        caids.add(Integer.valueOf(CAID_USEUSERDEFINED));
        data.put(CAID, caids);

        ArrayList<Integer> pintypes = new ArrayList<Integer>(NUMBEROFCERTIFICATES);
        pintypes.add(Integer.valueOf(PINTYPE_ASCII_NUMERIC));
        pintypes.add(Integer.valueOf(PINTYPE_ASCII_NUMERIC));
        data.put(PINTYPE, pintypes);

        ArrayList<Integer> minpinlength = new ArrayList<Integer>(NUMBEROFCERTIFICATES);
        minpinlength.add(Integer.valueOf(4));
        minpinlength.add(Integer.valueOf(4));
        data.put(MINIMUMPINLENGTH, minpinlength);

        ArrayList<Boolean> iskeyrecoverable = new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
        iskeyrecoverable.add(Boolean.FALSE);
        iskeyrecoverable.add(Boolean.FALSE);
        data.put(ISKEYRECOVERABLE, iskeyrecoverable);

        ArrayList<Boolean> reuseoldcertificate = new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
        reuseoldcertificate.add(Boolean.FALSE);
        reuseoldcertificate.add(Boolean.FALSE);
        data.put(REUSEOLDCERTIFICATE, reuseoldcertificate);

        ArrayList<Integer> minimumkeylength = new ArrayList<Integer>(NUMBEROFCERTIFICATES);
        minimumkeylength.add(Integer.valueOf(1024));
        minimumkeylength.add(Integer.valueOf(1024));
        data.put(MINIMUMKEYLENGTH, minimumkeylength);

        ArrayList<String> keytypes = new ArrayList<String>(NUMBEROFCERTIFICATES);
        keytypes.add(KEYTYPE_RSA);
        keytypes.add(KEYTYPE_RSA);
        data.put(KEYTYPES, keytypes);
    }

    public int[] getAvailableMinimumKeyLengths() {
        return AVAILABLEMINIMUMKEYLENGTHS;
    }

    /**
     * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.HardTokenProfile#isTokenSupported(java.lang.String)
     */
    public boolean isTokenSupported(String tokenidentificationstring) {
        return this.isTokenSupported(SUPPORTEDTOKENS, tokenidentificationstring);
    }

    /* 
     * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.HardTokenProfile#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        SwedishEIDProfile clone = new SwedishEIDProfile();
        super.clone(clone);

        return clone;
    }

    /* 
     * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.HardTokenProfile#getLatestVersion()
     */
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    public void upgrade() {
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            // New version of the class, upgrade
            super.upgrade();

            if (data.get(MINIMUMPINLENGTH) == null) {
                ArrayList<Integer> minpinlength = new ArrayList<Integer>(NUMBEROFCERTIFICATES);
                minpinlength.add(Integer.valueOf(4));
                minpinlength.add(Integer.valueOf(4));
                data.put(MINIMUMPINLENGTH, minpinlength);
            }

            if (data.get(REUSEOLDCERTIFICATE) == null) {
                ArrayList<Boolean> reuseoldcertificate = new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
                reuseoldcertificate.add(Boolean.FALSE);
                reuseoldcertificate.add(Boolean.FALSE);
                data.put(REUSEOLDCERTIFICATE, reuseoldcertificate);
            }

            if (data.get(CERTWRITABLE) == null) {
                ArrayList<Boolean> certWritable = new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
                certWritable.add(Boolean.FALSE);
                certWritable.add(Boolean.FALSE);
                data.put(CERTWRITABLE, certWritable);
            }

            data.put(VERSION, new Float(LATEST_VERSION));
        }
    }

    /**
     * @Override
     */
    public void reInit() {
        init();
    }
}
