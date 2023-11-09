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
package org.ejbca.ra.dto;

/**
 * DTO containing information about the inspected Certificate/CSR for use on the inspect.xhtml page.
 */
public class InspectedObject {

    private final InspectType type;
    private final String content;
    private final String serialNumberHex;
    private String serialNumberDecimal;
    private String fingerprintSha1;
    private String fingerprintSha256;
    private String filename;

    private InspectedObject(Builder builder) {
        this.type = builder.type;
        this.content = builder.content;
        this.serialNumberHex = builder.serialNumberHex;
        this.serialNumberDecimal = builder.serialNumberDecimal;
        this.fingerprintSha1 = builder.fingerprintSha1;
        this.fingerprintSha256 = builder.fingerprintSha256;
        this.filename = builder.filename;
    }

    public InspectType getType() {
        return type;
    }

    public String getContent() {
        return content;
    }

    public String getSerialNumberHex() {
        return serialNumberHex;
    }

    public String getSerialNumberDecimal() {
        return serialNumberDecimal;
    }


    public void setSerialNumberDecimal(final String serialNumberDecimal) {
        this.serialNumberDecimal = serialNumberDecimal;
    }

    public String getFingerprintSha1() {
        return fingerprintSha1;
    }

    public void setFingerprintSha1(final String fingerprintSha1) {
        this.fingerprintSha1 = fingerprintSha1;
    }

    public String getFingerprintSha256() {
        return fingerprintSha256;
    }

    public void setFingerprintSha256(final String fingerprintSha256) {
        this.fingerprintSha256 = fingerprintSha256;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(final String filename) {
        this.filename = filename;
    }

    public static class Builder {
        private InspectType type;
        private String content;
        private String serialNumberHex;
        private String serialNumberDecimal;
        private String fingerprintSha1;
        private String fingerprintSha256;
        private String filename;

        public Builder type(final InspectType type) {
            this.type = type;
            return this;
        }

        public Builder content(final String content) {
            this.content = content;
            return this;
        }

        public Builder serialNumberHex(final String serialNumberHex) {
            this.serialNumberHex = serialNumberHex;
            return this;
        }

        public Builder serialNumberDecimal(final String serialNumberDecimal) {
            this.serialNumberDecimal = serialNumberDecimal;
            return this;
        }

        public Builder fingerprintSha1(final String fingerprintSha1) {
            this.fingerprintSha1 = fingerprintSha1;
            return this;
        }

        public Builder fingerprintSha256(final String fingerprintSha256) {
            this.fingerprintSha256 = fingerprintSha256;
            return this;
        }

        public Builder filename(final String filename) {
            this.filename = filename;
            return this;
        }

        public InspectedObject build() {
            return new InspectedObject(this);
        }
    }

    public static Builder builder() {
        return new Builder();
    }

}
