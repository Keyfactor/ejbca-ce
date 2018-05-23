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
        if (certificateList != null) {
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
