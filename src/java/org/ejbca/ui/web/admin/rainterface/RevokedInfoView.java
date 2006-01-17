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
 
/*
 * RevokedInfoView.java
 *
 * Created on den 1 maj 2002, 07:55
 */
package org.ejbca.ui.web.admin.rainterface;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;

import org.ejbca.core.model.ca.crl.RevokedCertInfo;




/**
 * DOCUMENT ME!
 *
 * @author Philip Vendil
 */
public class RevokedInfoView implements Serializable {
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
        ArrayList reasons = new ArrayList();
        int reason = this.revokedcertinfo.getReason();

        if ((reason >= 0) && (reason < HIGN_REASON_BOUNDRARY)) {
            // Add this reason.
            reasons.add(reasontexts[reason]);
        }

        return (String[]) reasons.toArray(dummy);
    }

    public boolean isRevoked(){
    	return this.revokedcertinfo.getReason() != RevokedCertInfo.NOT_REVOKED;
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
