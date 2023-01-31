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
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.log4j.Logger;
import org.cesecore.util.CompressedCollection;

/**
 * Holds information about a revoked certificate. The information kept here is the
 * information that goes into a CRLEntry.
 **/
public class RevokedCertInfo implements Serializable {

	/** Version number for serialization */
	private static final long serialVersionUID = 1L;
	
	private static final Logger log = Logger.getLogger(RevokedCertInfo.class);

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
    
    public static final List<Integer> ALLOWED_OLD_REVOCATION_REASONS = Stream.of(REVOCATION_REASON_UNSPECIFIED,
                                                                        REVOCATION_REASON_KEYCOMPROMISE,
                                                                        REVOCATION_REASON_PRIVILEGESWITHDRAWN,
                                                                        REVOCATION_REASON_CESSATIONOFOPERATION,
                                                                        REVOCATION_REASON_AFFILIATIONCHANGED,
                                                                        REVOCATION_REASON_SUPERSEDED)
                                                                    .collect(Collectors.toList());

    /** BigInteger (serialNumber) in byte format, BigInteger.toByteArray() */
    private byte[]      userCertificate;
    private Long        invalidityDate;
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
    	invalidityDate = null;
    	revocationDate = 0;
    	expireDate = 0;
    	reason = REVOCATION_REASON_UNSPECIFIED;
    }

    /**
     * Constructor which doesn't fill in invalidityDate.
     * 
     * @param reason {@link RevokedCertInfo#REVOCATION_REASON_UNSPECIFIED}
     *
     **/
    public RevokedCertInfo(final byte[] fingerprint, final byte[] sernoBigIntegerArray, final long revdate, final int reason, final long expdate) {
        this.fingerprint = fingerprint;
        this.userCertificate = sernoBigIntegerArray;
        this.invalidityDate = null;
        this.revocationDate = revdate;
        this.reason = reason;
        this.expireDate = expdate;
    }
    
    /**
     * Constructor filling in the whole object.
     * 
     * @param reason {@link RevokedCertInfo#REVOCATION_REASON_UNSPECIFIED}
     *
     **/
    public RevokedCertInfo(final byte[] fingerprint, final byte[] sernoBigIntegerArray, final Long invalidityDate, final long revdate, final int reason, final long expdate) {
        this.fingerprint = fingerprint;
        this.userCertificate = sernoBigIntegerArray;
        this.invalidityDate = invalidityDate;
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
     * @return true is there is a invalidityDate set (getInvalidityDate() != null), false otherwise
     */
    public boolean isInvalidityDateSet() {
        return invalidityDate != null;
    }

    /**
     * Date on which the private key of the certificate became compromised or the certificate became invalid.
     **/
    public Date getInvalidityDate() {
        return invalidityDate == null ? null : new Date(invalidityDate);
    }

    /**
     * Date on which the private key of the certificate became compromised or the certificate became invalid.
     **/
    public void setInvalidityDate(final Date date) {
        this.invalidityDate = date.getTime();
    }
    
    /** 
     * @return true is there is a revocationDate set (getRevocationDate() != null), false otherwise
     */
    public boolean isRevocationDateSet() {
        return revocationDate != 0;
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
     * @see #REVOCATION_REASON_UNSPECIFIED
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

    @Override
    public String toString() {
        return String.format("(serial = %s, reason = %s)", 
                userCertificate == null ? "null" : new BigInteger(userCertificate).toString(),
                getReason());
    }
    
    /**
     * A quick way to tell if the certificate has been revoked. 
     * @return true if the certificate has been revoked, otherwise false.
     */
    public boolean isRevoked() {
    	return isRevoked(reason);
    }
    
    /**
     * Returns true if the certificate is permanently revoked (i.e. revoked and not just "on hold")
     */
    public boolean isPermanentlyRevoked() {
        return isPermanentlyRevoked(reason);
    }
    
    public static boolean isRevoked(int revocationReason) {
        return revocationReason != NOT_REVOKED && revocationReason != REVOCATION_REASON_REMOVEFROMCRL;
    }

    /**
     * Check if the revocation reason can be changed.
     *
     * @param newReason         new revocation reason must Key Compromise
     * @param newDate           new date can only be a backdate
     * @param currentReason     current reason can be one of the 5 revocation reasons
     * @param currentDate       current revocation date
     * @param allowedOnCa       changing revocation reason must be allowed on CA level.
     *
     * @return  true if all the requirements are met.
     */
    public static boolean canRevocationReasonBeChanged(final int newReason, final Date newDate, final int currentReason, final long currentDate, final boolean allowedOnCa, final boolean isX509) {
        final boolean dateIsOk = isDateOk(newDate, currentDate);
        return isX509 && allowedOnCa && newReason == REVOCATION_REASON_KEYCOMPROMISE && ALLOWED_OLD_REVOCATION_REASONS.contains(currentReason) && dateIsOk;
    }

    /**
     * Helper function to check if new date for updated revocation is ok.
     * @param newDate the new revocation date
     * @param currentDate the current revocation date
     * @return true if newDate is null or newDate is before currentDate
     */
    public static boolean isDateOk(final Date newDate, final long currentDate) {
        return newDate == null || newDate.getTime() <= currentDate;
    }
    
    public static boolean isPermanentlyRevoked(int revocationReason) {
        return isRevoked(revocationReason) && revocationReason != REVOCATION_REASON_CERTIFICATEHOLD;
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
    
    /**
     * Merges two collections of RevokedCertInfo. Note that the parameters are slightly different. Duplicates are removed according to these rules:
     * <ul>
     * <li>Older permanent status changes win over newer ones
     * <li>Permanent status changes always win over temporary ones ("on hold" / "re-activate")
     * <li>More recent temporary status changes win over older ones
     * </ul>
     * 
     * @param a First collection of RevokedCertInfo. May <b>not</b> contain duplicates for the same serial number.
     * @param b Second collection of RevokedCertInfo. May contain duplicates
     * @param lastBaseCrlDate Entries in unrevoked state will only be included if they are more recent than this date. (<= 0 means never include them)
     * @return CompressionCollection of certificates. May simply be a reference to <code>a</code> if <code>b</code> is empty, or a new merged CompressedCollection with any duplicates removed.
     */
    public static Collection<RevokedCertInfo> mergeByDateAndStatus(final Collection<RevokedCertInfo> a, final Collection<RevokedCertInfo> b, final long lastBaseCrlDate) {
        // We can optimize this case, but not the reverse, since b can contain duplicates that should be filtered.
        if (b.isEmpty()) {
            return a;
        }
        // Merge revocation information
        final Map<BigInteger,RevokedCertInfo> permRevoked = new HashMap<>();
        final Map<BigInteger,RevokedCertInfo> tempRevoked = new HashMap<>();
        for (final RevokedCertInfo revoked : a) {
            final BigInteger serial = revoked.getUserCertificate();
            if (revoked.isPermanentlyRevoked()) {
                permRevoked.put(serial, revoked);
            } else {
                tempRevoked.put(serial, revoked);
            }
        }
        for (final RevokedCertInfo revoked : b) {
            final BigInteger serial = revoked.getUserCertificate();
            final Date revdate = revoked.getRevocationDate();
            final RevokedCertInfo permDate = permRevoked.get(serial);
            if (permDate != null) {
                // Older permanent status changes win over newer ones
                if (permDate.getRevocationDate().after(revdate) && revoked.isPermanentlyRevoked()) {
                    permRevoked.put(serial, revoked);
                    tempRevoked.remove(serial);
                }
                continue;
            }
            if (revoked.isPermanentlyRevoked()) {
                // Permanently revoked wins over temporary revoked/re-activated
                permRevoked.put(serial, revoked);
                tempRevoked.remove(serial);
                continue;
            }
            final RevokedCertInfo tempDate = tempRevoked.get(serial);
            // More recent temporary status changes win over older ones 
            if (tempDate == null || tempDate.getRevocationDate().before(revdate)) {
                tempRevoked.put(serial, revoked);
            }
        }
        final CompressedCollection<RevokedCertInfo> mergedRevokedData = new CompressedCollection<>(RevokedCertInfo.class);
        mergedRevokedData.addAll(permRevoked.values()); // Permanently revoked entries are always added
        for (final RevokedCertInfo revoked : tempRevoked.values()) {
            if (!revoked.isRevoked() && (lastBaseCrlDate <= 0 || revoked.getRevocationDate().getTime() <= lastBaseCrlDate)) {
                continue; // REMOVEFROMCRL entries are not added in Base CRLs (lastBaseCrlDate=0) or if already removed from the latest Base CRL
            }
            mergedRevokedData.add(revoked);
        }
        mergedRevokedData.closeForWrite();
        if (log.isDebugEnabled()) {
            log.debug("mergeByDateAndStatus: Merged to " + mergedRevokedData.size() + " entries");
        }
        return mergedRevokedData;
    }
}
