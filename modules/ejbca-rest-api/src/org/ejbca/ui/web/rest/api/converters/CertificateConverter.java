package org.ejbca.ui.web.rest.api.converters;

import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.ui.web.rest.api.types.CertificateType;


import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

/**
 * A class to make a conversion between Entity and its corresponding REST Type.
 */
public class CertificateConverter {

    public List<CertificateType> toTypes(final List<Certificate> certificateList) throws CertificateEncodingException {
        final List<CertificateType> certificateTypes = new ArrayList<>();
        if (certificateList != null && !certificateList.isEmpty()) {
            for (final Certificate certificate : certificateList) {
                certificateTypes.add(toType(certificate));
            }
        }
        return certificateTypes;
    }

    private CertificateType toType(Certificate certificate) throws CertificateEncodingException {
        certificate.getType();
        return CertificateType.builder()
                .setCertificate(Base64.encode(certificate.getEncoded()))
                .setSerialNumber(CertTools.getSerialNumber(certificate))
                .build();
    }


}
