
package se.anatom.ejbca.ca.crl;

import java.math.BigInteger;
import java.util.Date;

/**
 * Holds information about a revoked certificate. The information kept here is the
 * information that goes into a CRLEntry.
 *
 * @version $Id: RevokedCertInfo.java,v 1.1.1.1 2001-11-15 14:58:14 anatom Exp $
 **/
public class RevokedCertInfo extends java.lang.Object implements java.io.Serializable {

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
     *    unused(0),
     *    keyCompromise(1),
     *    cACompromise(2),
     *    affiliationChanged(3),
     *    superseded(4),
     *    cessationOfOperation(5),
     *    certficateHold(6)
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
