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
package org.cesecore.keybind;

import java.io.Serializable;
import java.math.BigInteger;

import org.apache.commons.lang.StringUtils;

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
    private String trustEntryDescription = null;
    
    public InternalKeyBindingTrustEntry() {}
    
    public InternalKeyBindingTrustEntry(int caId, BigInteger certificateSerialNumber) {
        setCaId(caId);
        putCertificateSerialNumber(certificateSerialNumber);
    }

    public InternalKeyBindingTrustEntry(int caId, BigInteger certificateSerialNumber, String description) {
        setCaId(caId);
        putCertificateSerialNumber(certificateSerialNumber);
        // We don't want to put empty Strings. Use null instead
        if (!StringUtils.isEmpty(description)) {
            this.trustEntryDescription = description;
        }
    }
    
    public int getCaId() { return caId; }
    public void setCaId(int caId) { this.caId = caId; }
    public String getCertificateSerialNumberDecimal() { return certificateSerialNumberDecimal; }
    public void setCertificateSerialNumberDecimal(String certificateSerialNumberDecimal) { this.certificateSerialNumberDecimal = certificateSerialNumberDecimal; }
    public String getTrustEntryDescription() {return trustEntryDescription;}
    public void setTrustEntryDescription(String description) {this.trustEntryDescription = description;}

    /* NOTE: The getter and setter for a BigInteger must not comply with the JavaBean spec for this to work with java.beans.XMLEncoder 
     * NO_NOT_RENAME_TO get */
    public BigInteger fetchCertificateSerialNumber() {
        if (certificateSerialNumberDecimal == null) {
            return null;
        } else {
            return new BigInteger(certificateSerialNumberDecimal);
        }
    }

    /* NOTE: The getter and setter for a BigInteger must not comply with the JavaBean spec for this to work with java.beans.XMLEncoder 
     * NO_NOT_RENAME_TO set */
    public void putCertificateSerialNumber(BigInteger certificateSerialNumber) {
        if (certificateSerialNumber == null) {
            this.certificateSerialNumberDecimal = null;
        } else {
            this.certificateSerialNumberDecimal = certificateSerialNumber.toString();
        }
    }
    
    @Override
    public String toString() {
        final BigInteger certificateSerialNumber = fetchCertificateSerialNumber();
        if (certificateSerialNumber==null) {
            return String.valueOf(caId);
        } else {
            return String.valueOf(caId) + ";" + certificateSerialNumber.toString(16);
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
    
    @Override
    public int hashCode() {
        int hash = caId;
        if (certificateSerialNumberDecimal != null) {
            hash += 13*certificateSerialNumberDecimal.hashCode(); // add prime number product (common practice in Java, see String.hashCode for example) 
        }
        return hash;
    }
}
