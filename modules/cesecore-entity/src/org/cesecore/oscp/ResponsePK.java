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
package org.cesecore.oscp;

import java.io.Serializable;

/**
 * Primary key class used by OcspResponseData class.
 * 
 * @version $Id$
 *
 */
public class ResponsePK implements Serializable {

    private static final long serialVersionUID = 1L;
    protected Integer caId;
    protected String serialNumber;
    
    public Integer getCaId() {
        return caId;
    }

    public void setCaId(final Integer cAId) {
        this.caId = cAId;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(final String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public ResponsePK() {
    }

    public ResponsePK(final Integer caId, final String serialNumber) {
        this.caId = caId;
        this.serialNumber = serialNumber;
    }

    public int hashCode() {
        int hashCode = 0;
        if (caId != null) {
            hashCode += caId.hashCode();
        }
        if (serialNumber != null) {
            hashCode += serialNumber.hashCode();
        }
        return hashCode;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof ResponsePK)) {
            return false;
        }
        ResponsePK pk = (ResponsePK) obj;
        if (caId == null || !caId.equals(pk.caId)) {
            return false;
        }
        if (serialNumber == null || !serialNumber.equals(pk.serialNumber)) {
            return false;
        }
        return true;
    }
}