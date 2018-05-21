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

import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.util.CertTools;
import org.ejbca.ui.web.rest.api.types.CaInfoType;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * A class to make a conversion between Entity and its corresponding REST Type.
 *
 * @version $Id: CaInfoConverter.java 28909 2018-05-10 12:16:53Z andrey_s_helmes $
 */
public class CaInfoConverter {

    /**
     * Converts a list of CAData into list of CaInfoType. Null-safe.
     *
     * @param caDataList input list of CAData.
     *
     * @return list of CaInfoType.
     */
    public List<CaInfoType> toTypes(final List<CAData> caDataList) {
        final List<CaInfoType> caInfoTypes = new ArrayList<>();
        if(caDataList != null && !caDataList.isEmpty()) {
            for(final CAData caData : caDataList) {
                caInfoTypes.add(toType(caData));
            }
        }
        return caInfoTypes;
    }

    /**
     * Converts a non-null instance of CAData into CaInfoType.
     *
     * @param caData non-null CAData.
     *
     * @return CaInfoType.
     */
    public CaInfoType toType(final CAData caData) {
        return CaInfoType.builder()
                .id(caData.getCaId())
                .name(caData.getName())
                .subjectDn(caData.getSubjectDN())
                .issuerDn(extractIssuerDn(caData))
                .expirationDate(new Date(caData.getExpireTime()))
                .build();
    }

    // Extracts the Issuer DN using certificate data
    private String extractIssuerDn(final CAData caData) {
        final CA ca = caData.getCA();
        if(ca != null && ca.getCACertificate() != null) {
            return CertTools.getIssuerDN(caData.getCA().getCACertificate());
        }
        return "unknown";
    }
}
