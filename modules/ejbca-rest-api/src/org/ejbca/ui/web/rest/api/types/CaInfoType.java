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

import java.util.Date;

/**
 * A class representing general information about CA certificate.
 *
 * @version $Id: CaInfoType.java 28909 2018-05-10 12:16:53Z andrey_s_helmes $
 */
public class CaInfoType {

    private Integer id;
    private String name;
    private String subjectDn;
    private String issuerDn;
    private Date expirationDate;

    /**
     * Simple constructor.
     */
    public CaInfoType() {
    }

    // Private
    private CaInfoType(final Integer id, final String name, final String subjectDn, final String issuerDn, final Date expirationDate) {
        this.id = id;
        this.name = name;
        this.subjectDn = subjectDn;
        this.issuerDn = issuerDn;
        this.expirationDate = expirationDate;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static CaInfoTypeBuilder builder() {
        return new CaInfoTypeBuilder();
    }

    /**
     * Return the identifier.
     *
     * @return identifier.
     */
    public int getId() {
        return id;
    }

    /**
     * Return the name.
     *
     * @return name.
     */
    public String getName() {
        return name;
    }

    /**
     * Returns the Subject DN.
     *
     * @return Subject DN.
     */
    public String getSubjectDn() {
        return subjectDn;
    }

    /**
     * Returns the Issuer DN.
     *
     * @return Issuer DN.
     */
    public String getIssuerDn() {
        return issuerDn;
    }

    /**
     * Returns the expiration date.
     *
     * @return expiration date.
     */
    public Date getExpirationDate() {
        return expirationDate;
    }

    /**
     * Sets an identifier.
     *
     * @param id identifier.
     */
    public void setId(Integer id) {
        this.id = id;
    }

    /**
     * Sets a name.
     *
     * @param name name.
     */
    public void setName(final String name) {
        this.name = name;
    }

    /**
     * Sets a Subject DN.
     *
     * @param subjectDn Subject DN.
     */
    public void setSubjectDn(String subjectDn) {
        this.subjectDn = subjectDn;
    }

    /**
     * Sets an Issuer DN.
     *
     * @param issuerDn Issuer DN.
     */
    public void setIssuerDn(String issuerDn) {
        this.issuerDn = issuerDn;
    }

    /**
     * Sets an expiration date.
     *
     * @param expirationDate expiration date.
     */
    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
    }

    /**
     * Builder of this class.
     */
    public static class CaInfoTypeBuilder {

        private Integer id;
        private String name;
        private String subjectDn;
        private String issuerDn;
        private Date expirationDate;

        CaInfoTypeBuilder() {
        }

        /**
         * Sets an identifier in this builder.
         *
         * @param id identifier.
         *
         * @return instance of this builder.
         */
        public CaInfoTypeBuilder id(final Integer id) {
            this.id = id;
            return this;
        }

        /**
         * Sets a name in this builder.
         *
         * @param name name.
         *
         * @return instance of this builder.
         */
        public CaInfoTypeBuilder name(final String name) {
            this.name = name;
            return this;
        }

        /**
         * Sets a Subject DN in this builder.
         *
         * @param subjectDn Subject DN.
         *
         * @return instance of this builder.
         */
        public CaInfoTypeBuilder subjectDn(final String subjectDn) {
            this.subjectDn = subjectDn;
            return this;
        }

        /**
         * Sets an Issuer DN in this builder.
         *
         * @param issuerDn Issuer DN.
         *
         * @return instance of this builder.
         */
        public CaInfoTypeBuilder issuerDn(final String issuerDn) {
            this.issuerDn = issuerDn;
            return this;
        }

        /**
         * Sets an expiration date in this builder.
         *
         * @param expirationDate expiration date.
         *
         * @return instance of this builder.
         */
        public CaInfoTypeBuilder expirationDate(final Date expirationDate) {
            this.expirationDate = expirationDate;
            return this;
        }

        /**
         * Builds an instance of CaInfoType using this builder.
         *
         * @return instance of CaInfoType using this builder.
         */
        public CaInfoType build() {
            return new CaInfoType(
                    id,
                    name,
                    subjectDn,
                    issuerDn,
                    expirationDate
            );
        }
    }
}
