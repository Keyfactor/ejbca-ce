package org.ejbca.ui.web.rest.api.converters;

import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.ui.web.rest.api.types.CertificateResponse;


import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * A class to make a conversion between Entity and its corresponding REST Type.
 * 
 * @version $Id: CertificateConverter.java 28909 2018-05-10 12:16:53Z tarmo_r_helmes $
 */
public class CertificateConverter {

    public List<CertificateResponse> toTypes(final List<Certificate> certificateList) throws CertificateEncodingException {
        final List<CertificateResponse> certificateTypes = new ArrayList<>();
        if (certificateList != null && !certificateList.isEmpty()) {
            for (final Certificate certificate : certificateList) {
                certificateTypes.add(toType(certificate));
            }
        }
        return certificateTypes;
    }

    private CertificateResponse toType(Certificate certificate) throws CertificateEncodingException {
        certificate.getType();
        return CertificateResponse.builder()
                .setCertificate(Base64.encode(certificate.getEncoded()))
                .setSerialNumber(CertTools.getSerialNumber(certificate))
                .build();
    }

    public CertificateResponse toType(X509Certificate certificate) throws CertificateEncodingException {
        certificate.getType();
        return CertificateResponse.builder()
                .setCertificate(certificate.getEncoded())
                .setSerialNumber(certificate.getSerialNumber())
                .build();
    }


}
