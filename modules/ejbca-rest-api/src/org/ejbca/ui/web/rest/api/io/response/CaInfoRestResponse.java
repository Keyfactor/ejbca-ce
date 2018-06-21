/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.response;

import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;

import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.util.CertTools;

/**
 * A class representing general information about CA certificate.
 *
 * @version $Id: CaInfoRestResponse.java 28909 2018-05-22 12:16:53Z andrey_s_helmes $
 */
public class CaInfoRestResponse {

    private Integer id;
    private String name;
    private String subjectDn;
    private String issuerDn;
    private Date expirationDate;

    /**
     * Simple constructor.
     */
    public CaInfoRestResponse() {
    }

    private CaInfoRestResponse(final Integer id, final String name, final String subjectDn, final String issuerDn, final Date expirationDate) {
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
    public static CaInfoRestResponseBuilder builder() {
        return new CaInfoRestResponseBuilder();
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
    public static class CaInfoRestResponseBuilder {

        private Integer id;
        private String name;
        private String subjectDn;
        private String issuerDn;
        private Date expirationDate;

        CaInfoRestResponseBuilder() {
        }

        /**
         * Sets an identifier in this builder.
         *
         * @param id identifier.
         *
         * @return instance of this builder.
         */
        public CaInfoRestResponseBuilder id(final Integer id) {
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
        public CaInfoRestResponseBuilder name(final String name) {
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
        public CaInfoRestResponseBuilder subjectDn(final String subjectDn) {
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
        public CaInfoRestResponseBuilder issuerDn(final String issuerDn) {
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
        public CaInfoRestResponseBuilder expirationDate(final Date expirationDate) {
            this.expirationDate = expirationDate;
            return this;
        }

        /**
         * Builds an instance of CaInfoRestResponse using this builder.
         *
         * @return instance of CaInfoRestResponse using this builder.
         */
        public CaInfoRestResponse build() {
            return new CaInfoRestResponse(
                    id,
                    name,
                    subjectDn,
                    issuerDn,
                    expirationDate
            );
        }
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static CaInfoRestResponseConverter converter() {
        return new CaInfoRestResponseConverter();
    }

    /**
     * Converter of this class.
     */
    public static class CaInfoRestResponseConverter {

        CaInfoRestResponseConverter() {
        }

        /**
         * Converts a non-null instance of CAInfo into CaInfoRestResponse.
         *
         * @param caInfo CAInfo.
         *
         * @return CaInfoRestResponse.
         */
        public CaInfoRestResponse toRestResponse(final CAInfo caInfo) throws CADoesntExistsException {
            return CaInfoRestResponse.builder()
                    .id(caInfo.getCAId())
                    .name(caInfo.getName())
                    .subjectDn(caInfo.getSubjectDN())
                    .issuerDn(extractIssuerDn(caInfo))
                    .expirationDate(caInfo.getExpireTime())
                    .build();
        }

        // Extracts the Issuer DN using certificate chain
        private String extractIssuerDn(final CAInfo caInfo) throws CADoesntExistsException {
            final List<Certificate> caInfoCertificateChain = caInfo.getCertificateChain();
            if(caInfoCertificateChain != null && !caInfoCertificateChain.isEmpty()) {
                // Get last it should be RootCA
                final Certificate rootCa = caInfoCertificateChain.get(caInfoCertificateChain.size() - 1);
                return CertTools.getIssuerDN(rootCa);
            }
            throw new CADoesntExistsException("Cannot extract the Issuer DN for CA certificate with id " + caInfo.getCAId());
        }
    }
}
