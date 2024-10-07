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

import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;

import com.keyfactor.util.CertTools;

import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * A class representing general information about CA certificate.
 *
 */
public class CaInfoRestResponse {

    @Schema(description = "CA identifier", example = "12345678")
    private Integer id;
    @Schema(description = "Certificate Authority (CA) name", example = "ExampleCA")
    private String name;
    @Schema(description = "Subject Distinguished Name", example = "CN=ExampleCA,O=Sample,C=SE")
    private String subjectDn;
    @Schema(description = "Issuer Distinguished Name", example = "CN=ExampleCA,O=Sample,C=SE")
    private String issuerDn;
    @Schema(description = "Expiration date", example = "2038-01-19T03:14:07Z")
    private Date expirationDate;
    @Schema(description = "Is external (whether CA certificate was imported)", example = "true")
    private boolean external;

    /**
     * Simple constructor.
     */
    public CaInfoRestResponse() {
    }

    private CaInfoRestResponse(final Integer id, final String name, final String subjectDn, final String issuerDn, final Date expirationDate, final boolean external) {
        this.id = id;
        this.name = name;
        this.subjectDn = subjectDn;
        this.issuerDn = issuerDn;
        this.expirationDate = expirationDate;
        this.external = external;
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
     * Gets an indication if this is an external CA Certificate, i.e. an imported CA Certificate.
     *
     * @return <code>True</code> is it is external, <code>false</code> otherwise.
     */
    public boolean isExternal() {
        return external;
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
     * Sets indication if this is an external CA Certificate, i.e. an imported CA Certificate.
     *
     * @param external Whether the CA Certificate is external.
     */
    public void setExternal(boolean external) {
        this.external = external;
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
        private boolean external;

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
         * Sets an external boolean in this builder.
         *
         * @param external external boolean.
         *
         * @return instance of this builder.
         */
        public CaInfoRestResponseBuilder external(final boolean external) {
            this.external = external;
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
                    expirationDate,
                    external
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
                    .external(caInfo.getStatus() == CAConstants.CA_EXTERNAL)
                    .build();
        }

        // Extracts the Issuer DN using certificate chain
        private String extractIssuerDn(final CAInfo caInfo) throws CADoesntExistsException {
            final List<Certificate> caInfoCertificateChain = caInfo.getCertificateChain();
            if(caInfoCertificateChain != null && !caInfoCertificateChain.isEmpty()) {
                // Get first certificate, it's this CAs issuer wr're looking for
                final Certificate ca = caInfoCertificateChain.get(0);
                return CertTools.getIssuerDN(ca);
            }
            throw new CADoesntExistsException("Cannot extract the Issuer DN for CA certificate with id " + caInfo.getCAId());
        }
    }
}
