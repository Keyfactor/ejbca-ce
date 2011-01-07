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
 
package org.ejbca.core.model.ca.crl;

import java.math.BigInteger;
import java.util.Date;

/**
 * Holds information about a revoked certificate. The information kept here is the
 * information that goes into a CRLEntry.
 *
 * @version $Id$
 **/
public class RevokedCertInfo implements java.io.Serializable {

	/** Version number for serialization */
	private static final long serialVersionUID = 1L;

	/** Constants defining different revocation reasons. */
    public static final int NOT_REVOKED                            = -1;
    public static final int REVOCATION_REASON_UNSPECIFIED          = 0;
    public static final int REVOCATION_REASON_KEYCOMPROMISE        = 1;
    public static final int REVOCATION_REASON_CACOMPROMISE         = 2;
    public static final int REVOCATION_REASON_AFFILIATIONCHANGED   = 3;
    public static final int REVOCATION_REASON_SUPERSEDED           = 4;
    public static final int REVOCATION_REASON_CESSATIONOFOPERATION = 5;
    public static final int REVOCATION_REASON_CERTIFICATEHOLD      = 6;
    public static final int REVOCATION_REASON_REMOVEFROMCRL        = 8;
    public static final int REVOCATION_REASON_PRIVILEGESWITHDRAWN  = 9;
    public static final int REVOCATION_REASON_AACOMPROMISE         = 10;
    

    private BigInteger  userCertificate;
    private Date        revocationDate;
    private Date        expireDate;
    private int         reason;
    private String 		fingerprint;

    /**
     * A default constructor is needed to instantiate
     * RevokedCertInfo objects using &lt;jsp:useBean&gt; by Tomcat 5. 
     */
    public RevokedCertInfo() {
    	fingerprint = null;
    	userCertificate = null;
    	revocationDate = null;
    	expireDate = null;
    	reason = REVOCATION_REASON_UNSPECIFIED;
    }

    /**
     * Constructor filling in the whole object.
     *
     **/
    public RevokedCertInfo(final String fingerprint, final BigInteger serno, final Date revdate, final int reason, final Date expdate)
    {
    	this.fingerprint = fingerprint;
        this.userCertificate = serno;
        this.revocationDate = revdate;
        this.reason = reason;
        this.expireDate = expdate;
    }

    /**
     * Certificate fingerprint
     **/
    public String getCertificateFingerprint() {
        return this.fingerprint;
    }

    /**
     * Certificate fingerprint
     **/
    public void setCertificateFingerprint(final String fp) {
        this.fingerprint = fp;
    }
    
    /**
     * Certificate serial number
     **/
    public BigInteger getUserCertificate() {
        return this.userCertificate;
    }

    /**
     * Certificate serial number
     **/
    public void setUserCertificate(final BigInteger serno) {
        this.userCertificate = serno;
    }

    /**
     * Date when the certificate was revoked.
     **/
    public Date getRevocationDate() {
        return this.revocationDate;
    }

    /**
     * Date when the certificate was revoked.
     **/
    public void setRevocationDate(final Date date) {
        this.revocationDate = date;
    }

    /**
     * Date when the certificate expires.
     **/
    public Date getExpireDate() {
        return this.expireDate;
    }

    /**
     * Date when the certificate expires.
     **/
    public void setExpireDate(final Date date) {
        this.expireDate = date;
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
     **/
    public int getReason() {
        return this.reason;
    }

    /**
     * The reason the certificate was revoked.
     **/
    public void setReason(final int reason) {
        this.reason = reason;
    }

    public String toString() {
        return this.userCertificate == null ? "null" : this.userCertificate.toString();
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
     * TODO: The strings in this method should be easier for users to change, used from "publicweb/retrieve/check_status_result.jsp"
     * 
     * @return A string describing the reason for revocation.
     */
    public String getHumanReadableReason() {
    	switch (reason) {
    	case NOT_REVOKED:
    		return "the certificate is not revoked";
    	case REVOCATION_REASON_UNSPECIFIED:
    		return "unspecified";
    	case REVOCATION_REASON_KEYCOMPROMISE:
    		return "key compromise";
    	case REVOCATION_REASON_CACOMPROMISE:
    		return "CA compromise";
    	case REVOCATION_REASON_AFFILIATIONCHANGED:
    		return "affiliation changed";
    	case REVOCATION_REASON_SUPERSEDED:
    		return "superseded";
    	case REVOCATION_REASON_CESSATIONOFOPERATION:
    		return "cessation of operation";
    	case REVOCATION_REASON_CERTIFICATEHOLD:
    		return "certificate hold";
    	case REVOCATION_REASON_REMOVEFROMCRL:
    		return "remove from CRL";
    	case REVOCATION_REASON_PRIVILEGESWITHDRAWN:
    		return "privileges withdrawn";
    	case REVOCATION_REASON_AACOMPROMISE:
    		return "AA compromise";
    	default:
    		return "unknown";
         	}
    }
}
