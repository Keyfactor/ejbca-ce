/*
 * RevokedInfoView.java
 *
 * Created on den 1 maj 2002, 07:55
 */
package se.anatom.ejbca.webdist.rainterface;

import java.math.BigInteger;
import java.util.Date;
import java.util.Vector;

import se.anatom.ejbca.ca.crl.RevokedCertInfo;


/**
 * DOCUMENT ME!
 *
 * @author Philip Vendil
 */
public class RevokedInfoView {
    // Public constants.

    /**
     * Creates a new instance of RevokedInfoView
     *
     * @param revokedcertinfo DOCUMENT ME!
     */
    public RevokedInfoView(RevokedCertInfo revokedcertinfo) {
        this.revokedcertinfo = revokedcertinfo;
    }

    // Public methods.
    public String getCertificateSerialNumberAsString() {
        return this.revokedcertinfo.getUserCertificate().toString(16);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public BigInteger getCertificateSerialNumber() {
        return this.revokedcertinfo.getUserCertificate();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getRevocationDate() {
        return this.revokedcertinfo.getRevocationDate();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String[] getRevokationReasons() {
        String[] dummy = { "" };
        Vector reasons = new Vector();
        int reason = this.revokedcertinfo.getReason();

        if ((reason >= 0) && (reason < HIGN_REASON_BOUNDRARY)) {
            // Add this reason.
            reasons.addElement(reasontexts[reason]);
        }

        return (String[]) reasons.toArray(dummy);
    }

    // Private constants.
    public static final String[] reasontexts = {
        "UNSPECIFIED", "KEYCOMPROMISE", "CACOMPROMISE", "AFFILIATIONCHANGED", "SUPERSEDED",
        "CESSATIONOFOPERATION", "CERTIFICATEHOLD", "UNUSED", "REMOVEFROMCRL", "PRIVILEGESWITHDRAWN",
        "AACOMPROMISE"
    };
    public static final int HIGN_REASON_BOUNDRARY = 11;

    // Private fields.
    private RevokedCertInfo revokedcertinfo;
}
