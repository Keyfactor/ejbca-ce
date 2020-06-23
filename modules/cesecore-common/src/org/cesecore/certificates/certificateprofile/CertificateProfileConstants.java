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

package org.cesecore.certificates.certificateprofile;

/**
 * Constants for users and certificates. Constants for Type of user: Type is constructed as a mask
 * since one user can be of several types. To test a user type:
 * <pre>
 * if (((type & USER_ENDUSER) == USER_ENDUSER) && ((type & USER_CAADMIN) == USER_ADMINISTOR) || ...
 *    ...
 * </pre>
 * Bit usage: bits 0-7   (1:st byte):  user types bits 8-15  (2:nd byte):  unused bits 16-23 (3:rd
 * byte):  unused bits 24-30 (4:th byte):  unused Constants for certificates are simple integer
 * types. Constants for Token Types Token type is constructed of integer constants since only one
 * token type can be generated.
 *
 * Based on EJBCA (SecConst) version: SecConst.java 9321 2010-06-30 12:49:32Z jeklund
 *
 * @version $Id$
 */
public final class CertificateProfileConstants {
    /**
     * The id of a non-existing certificate profile.
     */
    public static final int NO_CERTIFICATE_PROFILE = 0;

    // Certificate profiles.

    /** Used when no certificate profile id value is available */
    public static final int CERTPROFILE_NO_PROFILE            = 0;
    public static final int CERTPROFILE_FIXED_ENDUSER         = 1;
    public static final int CERTPROFILE_FIXED_SUBCA           = 2;
    public static final int CERTPROFILE_FIXED_ROOTCA          = 3;
	public static final int CERTPROFILE_FIXED_OCSPSIGNER      = 4;
	public static final int CERTPROFILE_FIXED_SSH             = 5;
	public static final int CERTPROFILE_FIXED_SERVER          = 9;

    /**
     * Constants defining range of id's reserved for fixed certificate types. Observe fixed
     * certificates cannot have value 0.
     */
    public static final int FIXED_CERTIFICATEPROFILE_BOUNDRY = 1000;

    /**
     * @return true is certificate profile identified by profileId is fixed
     */
    public static boolean isFixedCertificateProfile(final int profileId) {
    	return profileId == CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER ||
    			profileId == CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA ||
    			profileId == CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA ||
    			profileId == CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER ||
    			profileId == CertificateProfileConstants.CERTPROFILE_FIXED_SERVER;
    }

    /**
     * Default key lengths. Users are allowed to choose from these key lengths when
     * lookup of available bit lengths fails.
     * @see org.ejbca.ui.web.pub.ApplyBean
     */
    public static final int[] DEFAULT_KEY_LENGTHS = new int[] {512, 1024, 2048};
    
    /** QC ETSI Type OID: Electronic Signature */
    public static final String QC_ETSI_TYPE_ESIGN = "0.4.0.1862.1.6.1";
    /** QC ETSI Type OID: Electronic Seal */
    public static final String QC_ETSI_TYPE_ESEAL = "0.4.0.1862.1.6.2";
    /** QC ETSI Type OID: Website Authentication */
    public static final String QC_ETSI_TYPE_WEBAUTH = "0.4.0.1862.1.6.3";

    /**
     * Prevents creation of new class
     */
    private CertificateProfileConstants() {
    }

}