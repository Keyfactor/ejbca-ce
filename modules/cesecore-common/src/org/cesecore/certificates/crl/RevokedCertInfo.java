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
package org.cesecore.certificates.crl;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Date;

/**
 * Holds information about a revoked certificate. The information kept here is the
 * information that goes into a CRLEntry.
 *
 * @version $Id$
 * 
 **/
public class RevokedCertInfo implements Serializable {

	/** Version number for serialization */
	private static final long serialVersionUID = 1L;

	/** Constants defining different revocation reasons. */
    public static final int NOT_REVOKED                            = RevocationReasons.NOT_REVOKED.getDatabaseValue();
    public static final int REVOCATION_REASON_UNSPECIFIED          = RevocationReasons.UNSPECIFIED.getDatabaseValue();
    public static final int REVOCATION_REASON_KEYCOMPROMISE        = RevocationReasons.KEYCOMPROMISE.getDatabaseValue();
    public static final int REVOCATION_REASON_CACOMPROMISE         = RevocationReasons.CACOMPROMISE.getDatabaseValue();
    public static final int REVOCATION_REASON_AFFILIATIONCHANGED   = RevocationReasons.AFFILIATIONCHANGED.getDatabaseValue();
    public static final int REVOCATION_REASON_SUPERSEDED           = RevocationReasons.SUPERSEDED.getDatabaseValue();
    public static final int REVOCATION_REASON_CESSATIONOFOPERATION = RevocationReasons.CESSATIONOFOPERATION.getDatabaseValue();
    public static final int REVOCATION_REASON_CERTIFICATEHOLD      = RevocationReasons.CERTIFICATEHOLD.getDatabaseValue();
    // Value 7 is not used, see RFC5280
    public static final int REVOCATION_REASON_REMOVEFROMCRL        = RevocationReasons.REMOVEFROMCRL.getDatabaseValue();
    public static final int REVOCATION_REASON_PRIVILEGESWITHDRAWN  = RevocationReasons.PRIVILEGESWITHDRAWN.getDatabaseValue();
    public static final int REVOCATION_REASON_AACOMPROMISE         = RevocationReasons.AACOMPROMISE.getDatabaseValue();
    
    /** BigInteger (serialNumber) in byte format, BigInteger.toByteArray() */
    private byte[]      userCertificate;
    private long        revocationDate;
    private long        expireDate;
    private int         reason;
    /** Fingerprint in byte format, String.getBytes() */    
    private byte[] 		fingerprint;

    /**
     * A default constructor is needed to instantiate
     * RevokedCertInfo objects using &lt;jsp:useBean&gt; by Tomcat 5. 
     */
    public RevokedCertInfo() {
    	fingerprint = null;
    	userCertificate = null;
    	revocationDate = 0;
    	expireDate = 0;
    	reason = REVOCATION_REASON_UNSPECIFIED;
    }

    /**
     * Constructor filling in the whole object.
     * 
     * @param reason {@link RevokedCertInfo#REVOCATION_REASON_UNSPECIFIED}
     *
     **/
    public RevokedCertInfo(final byte[] fingerprint, final byte[] sernoBigIntegerArray, final long revdate, final int reason, final long expdate) {
        this.fingerprint = fingerprint;
        this.userCertificate = sernoBigIntegerArray;
        this.revocationDate = revdate;
        this.reason = reason;
        this.expireDate = expdate;
    }

    /**
     * Certificate fingerprint
     **/
    public String getCertificateFingerprint() {
        return fingerprint == null ? null : new String(fingerprint);
    }

    /**
     * Certificate fingerprint
     **/
    public void setCertificateFingerprint(final String fp) {
        this.fingerprint = fp == null ? null : fp.getBytes();
    }
    
    /**
     * Certificate serial number
     **/
    public BigInteger getUserCertificate() {
        return userCertificate == null ? null : new BigInteger(userCertificate);
    }

    /**
     * Certificate serial number
     **/
    public void setUserCertificate(final BigInteger serno) {
        this.userCertificate = serno==null ? null : serno.toByteArray();
    }

    /**
     * Date when the certificate was revoked.
     **/
    public Date getRevocationDate() {
        return revocationDate == 0 ? null : new Date(revocationDate);
    }

    /**
     * Date when the certificate was revoked.
     **/
    public void setRevocationDate(final Date date) {
        this.revocationDate = date == null ? 0 : date.getTime();
    }

    /**
     * Date when the certificate expires.
     **/
    public Date getExpireDate() {
        return expireDate == 0 ? null : new Date(expireDate);
    }

    /**
     * Date when the certificate expires.
     **/
    public void setExpireDate(final Date date) {
        this.expireDate = date==null ? 0 : date.getTime();
    }

    /**
     * The reason the certificate was revoked.
     * <pre>
     * ReasonFlags ::= BIT STRING {
     *    unspecified(0),
     *    keyCompromise(1),
     *    cACompromise(2),
     *    affiliationChanged(3),
     *    superseded(4),
     *    cessationOfOperation(5),
     *    certficateHold(6)
     *    removeFromCRL(8)
     *    privilegeWithdrawn(9)
     *    aACompromise(10)
     * }
     * </pre>
     * @see {@link RevokedCertInfo#REVOCATION_REASON_UNSPECIFIED}
     **/
    public int getReason() {
        return this.reason;
    }

    /**
     * The reason the certificate was revoked.
     * @param reason {@link RevokedCertInfo#REVOCATION_REASON_UNSPECIFIED}
     **/
    public void setReason(final int reason) {
        this.reason = reason;
    }

    public String toString() {
        return this.userCertificate == null ? "null" : new BigInteger(userCertificate).toString();
    }
    
    /**
     * A quick way to tell if the certificate has been revoked. 
     * @return true if the certificate has been revoked, otherwise false.
     */
    public boolean isRevoked() {
    	return this.reason != NOT_REVOKED;
    }
    
    /**
     * This method returns the revocation reason as a text string that is understandable.
     * TODO: The strings in the enum should be easier for users to change, used from "publicweb/retrieve/check_status_result.jsp"
     * 
     * @return A string describing the reason for revocation.
     */
    public String getHumanReadableReason() {
        RevocationReasons revocationReason = RevocationReasons.getFromDatabaseValue(reason);
        if (revocationReason != null) {
            return revocationReason.getHumanReadable();

        } else {
            return "unknown";
        }
    }
}
