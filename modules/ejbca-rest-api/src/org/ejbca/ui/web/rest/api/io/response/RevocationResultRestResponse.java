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
package org.ejbca.ui.web.rest.api.io.response;

import java.math.BigInteger;
import java.util.Date;

/**
 * Revocation result type holder. Used to produce JSON.
 *
 * @version $Id$
 */
public class RevocationResultRestResponse {

    public static final String STATUS_REVOKED              = "Revoked";

    private BigInteger serialNumber;
    private Date revocationDate;
    private String status;
    private String message;

    public RevocationResultRestResponse() {
    }

    private RevocationResultRestResponse(final BigInteger serialNumber, final Date revocationDate, final String status, final String message) {
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

    public Date getRevocationDate() {
        return revocationDate;
    }

    public void setRevocationDate(Date date) {
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

    /**
    * Return a builder instance for this class.
    *
    * @return builder instance for this class.
    */
    public static RevocationResultRestResponseBuilder builder() {
        return new RevocationResultRestResponseBuilder();
    }

    /**
     * Builder of this class.
     */
    public static class RevocationResultRestResponseBuilder {

        private BigInteger serialNumber;
        private Date revocationDate;
        private String status;
        private String message;

        RevocationResultRestResponseBuilder() {
        }

        /**
         * Sets a serial number in this builder.
         *
         * @param serialNumber serial number.
         *
         * @return instance of this builder.
         */
        public RevocationResultRestResponseBuilder serialNumber(final BigInteger serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        /**
         * Sets a revocation date in this builder.
         *
         * @param revocationDate error message.
         *
         * @return instance of this builder.
         */
        public RevocationResultRestResponseBuilder revocationDate(final Date revocationDate) {
            this.revocationDate = revocationDate;
            return this;
        }

        /**
         * Sets a status in this builder.
         *
         * @param status status.
         *
         * @return instance of this builder.
         */
        public RevocationResultRestResponseBuilder status(final String status) {
            this.status = status;
            return this;
        }

        /**
         * Sets a message in this builder.
         *
         * @param message message.
         *
         * @return instance of this builder.
         */
        public RevocationResultRestResponseBuilder message(final String message) {
            this.message = message;
            return this;
        }

        /**
         * Builds an instance of RevocationResultRestResponse using this builder.
         *
         * @return instance of RevocationResultRestResponse using this builder.
         */
        public RevocationResultRestResponse build() {
            return new RevocationResultRestResponse(serialNumber, revocationDate, status, message);
        }
    }

}