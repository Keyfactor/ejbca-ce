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

package org.ejbca.ui.web.rest.api.types;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Revocation result type holder. Used to produce JSON.
 *
 * @version $Id$
 */
public class RevocationResultType {

    public static final String STATUS_REVOKED              = "Revoked";

    private BigInteger serialNumber;
    private Date revocationDate;
    private String status;
    private String message;
    
    public RevocationResultType(BigInteger serialNumber, Date revocationDate, String status, String message) {
        this.serialNumber = serialNumber;
        this.revocationDate = revocationDate;
        this.status = status;
        this.message = message;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getDate() {
        // "2018-02-10T17:06:15+00:00"
        final SimpleDateFormat dateFormater = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
        return revocationDate != null ? dateFormater.format(revocationDate) : null;
    }

    public void setDate(Date date) {
        this.revocationDate = date;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}