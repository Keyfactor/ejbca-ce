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

// TODO Javadoc
/**
 * A class representing general information about CA certificate.
 *
 * @version $Id: CaInfoType.java 28909 2018-05-10 12:16:53Z aminkh $
 */
public class CaInfoType {

    private Integer id;
    private String name;
    private String subjectDn;
    private String issuerDn;
    private Date expirationDate;

    public CaInfoType() {
    }

    CaInfoType(final Integer id, final String name, final String subjectDn, final String issuerDn, final Date expirationDate) {
        this.id = id;
        this.name = name;
        this.subjectDn = subjectDn;
        this.issuerDn = issuerDn;
        this.expirationDate = expirationDate;
    }

    public static CaInfoTypeBuilder builder() {
        return new CaInfoTypeBuilder();
    }

    public int getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getSubjectDn() {
        return subjectDn;
    }

    public String getIssuerDn() {
        return issuerDn;
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public void setSubjectDn(String subjectDn) {
        this.subjectDn = subjectDn;
    }

    public void setIssuerDn(String issuerDn) {
        this.issuerDn = issuerDn;
    }

    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
    }

    public static class CaInfoTypeBuilder {

        private Integer id;
        private String name;
        private String subjectDn;
        private String issuerDn;
        private Date expirationDate;

        CaInfoTypeBuilder() {
        }

        public CaInfoTypeBuilder id(final Integer id) {
            this.id = id;
            return this;
        }

        public CaInfoTypeBuilder name(final String name) {
            this.name = name;
            return this;
        }

        public CaInfoTypeBuilder subjectDn(final String subjectDn) {
            this.subjectDn = subjectDn;
            return this;
        }

        public CaInfoTypeBuilder issuerDn(final String issuerDn) {
            this.issuerDn = issuerDn;
            return this;
        }

        public CaInfoTypeBuilder expirationDate(final Date expirationDate) {
            this.expirationDate = expirationDate;
            return this;
        }

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
