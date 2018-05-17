package org.ejbca.ui.web.rest.api.types;

import java.math.BigInteger;

public class EnrollCertificateResponseType {
        
    private byte[] certificate;
    BigInteger serialNumber;
    
    public EnrollCertificateResponseType(byte[] certificate, BigInteger serialNumber) {
        super();
        this.certificate = certificate;
        this.serialNumber = serialNumber;
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
}