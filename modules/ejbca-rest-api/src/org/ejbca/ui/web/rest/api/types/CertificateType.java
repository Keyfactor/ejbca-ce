package org.ejbca.ui.web.rest.api.types;

import java.math.BigInteger;

/**
 * A class representing general information about certificate.
 *
 *
 */
public class CertificateType {

    private byte[] certificate;
    private BigInteger serialNumber;

    private CertificateType(byte[] certificate, BigInteger serialNumber) {
        this.certificate = certificate;
        this.serialNumber = serialNumber;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static CertificateTypeBuilder builder() {
        return new CertificateTypeBuilder();
    }

    public byte[] getCertificate() {
        return certificate;
    }

    public void setCertificate(byte[] certificate) {
        this.certificate = certificate;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }



    public static class CertificateTypeBuilder {
        private byte[] certificate;
        private BigInteger serialNumber;

        private CertificateTypeBuilder() {
        }

        public CertificateTypeBuilder setCertificate(byte[] certificate) {
            this.certificate = certificate;
            return this;
        }

        public CertificateTypeBuilder setSerialNumber(BigInteger serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        public CertificateType build() {
            return new CertificateType(certificate, serialNumber);
        }
    }
}
