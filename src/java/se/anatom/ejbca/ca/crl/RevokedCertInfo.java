package se.anatom.ejbca.ca.crl;

import java.math.BigInteger;
import java.util.Date;

/**
 * Holds information about a revoked certificate. The information kept here is the
 * information that goes into a CRLEntry.
 *
 * @version $Id: RevokedCertInfo.java,v 1.5 2003-09-03 15:47:16 herrvendil Exp $
 **/
public class RevokedCertInfo extends java.lang.Object implements java.io.Serializable {
    
    /** Constants defining different revokation reasons. */
    public final static int REVOKATION_REASON_UNSPECIFIED          = 0;
    public final static int REVOKATION_REASON_KEYCOMPROMISE        = 1;
    public final static int REVOKATION_REASON_CACOMPROMISE         = 2;
    public final static int REVOKATION_REASON_AFFILIATIONCHANGED   = 3;
    public final static int REVOKATION_REASON_SUPERSEDED           = 4;
    public final static int REVOKATION_REASON_CESSATIONOFOPERATION = 5;
    public final static int REVOKATION_REASON_CERTIFICATEHOLD      = 6;      
    public final static int REVOKATION_REASON_REMOVEFROMCRL        = 8;
    public final static int REVOKATION_REASON_PRIVILEGESWITHDRAWN  = 9;
    public final static int REVOKATION_REASON_AACOMPROMISE         = 10;
    

    private BigInteger  userCertificate;
    private Date        revocationDate;
    private int         reason;

    /**
     * Constuctor filling in the whole object.
     *
     **/
    public RevokedCertInfo(BigInteger serno, Date date, int reason)
    {
        this.userCertificate = serno;
        this.revocationDate = date;
        this.reason = reason;
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
    public void setUserCertificate( BigInteger serno ) {
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
    public void setRevocationDate( Date date ) {
        this.revocationDate = date;
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
    public void setReason( int reason ) {
        this.reason = reason;
    }

    public String toString() {
        return this.userCertificate == null ? "null" : this.userCertificate.toString();
    }
}
