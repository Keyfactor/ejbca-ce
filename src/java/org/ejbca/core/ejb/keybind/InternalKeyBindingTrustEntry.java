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
package org.ejbca.core.ejb.keybind;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * (JavaBean-) XML Serializable representation of a trust anchor (CA Id) or trusted certificate (CA Id and certificate serialnumber)
 * 
 * An undefined (null) serialnumber means ANY serialnumber.
 * 
 * @version $Id$
 */
public class InternalKeyBindingTrustEntry implements Serializable {

    private static final long serialVersionUID = 1L;

    private int caId = 0;
    private String certificateSerialNumberDecimal = null;
    
    public InternalKeyBindingTrustEntry() {}
    
    public InternalKeyBindingTrustEntry(int caId, BigInteger certificateSerialNumber) {
        setCaId(caId);
        setCertificateSerialNumber(certificateSerialNumber);
    }

    public int getCaId() { return caId; }
    public void setCaId(int caId) { this.caId = caId; }
    public String getCertificateSerialNumberDecimal() { return certificateSerialNumberDecimal; }
    public void setCertificateSerialNumberDecimal(String certificateSerialNumberDecimal) { this.certificateSerialNumberDecimal = certificateSerialNumberDecimal; }

    public BigInteger getCertificateSerialNumber() {
        if (certificateSerialNumberDecimal == null) {
            return null;
        } else {
            return new BigInteger(certificateSerialNumberDecimal);
        }
    }

    public void setCertificateSerialNumber(BigInteger certificateSerialNumber) {
        if (certificateSerialNumber == null) {
            this.certificateSerialNumberDecimal = null;
        } else {
            this.certificateSerialNumberDecimal = certificateSerialNumber.toString();
        }
    }
    
    @Override
    public String toString() {
        final BigInteger certificateSerialNumber = getCertificateSerialNumber();
        if (certificateSerialNumber==null) {
            return Integer.valueOf(caId).toString();
        } else {
            return Integer.valueOf(caId).toString() + ";" + certificateSerialNumber.toString(16);
        }
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof InternalKeyBindingTrustEntry)) {
            return false;
        }
        final InternalKeyBindingTrustEntry other = (InternalKeyBindingTrustEntry) object;
        if (caId != other.caId) {
            return false;
        }
        if (certificateSerialNumberDecimal==null && other.certificateSerialNumberDecimal==null) {
            return true;
        }
        return certificateSerialNumberDecimal!=null && certificateSerialNumberDecimal.equals(other.certificateSerialNumberDecimal);
    }
}
