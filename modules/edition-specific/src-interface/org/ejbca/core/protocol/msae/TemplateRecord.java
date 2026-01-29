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
package org.ejbca.core.protocol.msae;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * A DTO representing an AD Certificate Template entry
 * with only the attributes required by CEPService and CESService.
 */
public record TemplateRecord(
        String cn,
        String oid,
        Long schemaVersion,
        Long validityPeriodSeconds,
        Long renewalPeriodSeconds,
        Long minimalKeySize,
        Long defaultKeySpec,
        List<String> defaultCsps,
        Long minorRevision,
        Long majorRevision,
        List<String> supersededTemplateCNs,
        Long privateKeyFlags,
        Long subjectNameFlags,
        Long enrollmentFlags,
        Long generalFlags,
        List<String> criticalExtensions,
        List<String> extendedKeyUsages,
        String[] keyUsages,
        String raApplicationPolicies,
        byte[] securityDescriptor,
        boolean autoEnrollAllowed,
        boolean enrollAllowed
) implements Serializable {
    private static final long serialVersionUID = 1L;

    // Canonical constructor to enforce defensive copies and defaults
    public TemplateRecord {
        defaultCsps = defaultCsps == null ? Collections.emptyList() : List.copyOf(defaultCsps);
        supersededTemplateCNs = supersededTemplateCNs == null ? Collections.emptyList() : List.copyOf(supersededTemplateCNs);
        criticalExtensions = criticalExtensions == null ? Collections.emptyList() : List.copyOf(criticalExtensions);
        extendedKeyUsages = extendedKeyUsages == null ? Collections.emptyList() : List.copyOf(extendedKeyUsages);
        keyUsages = keyUsages == null ? new String[0] : Arrays.copyOf(keyUsages, keyUsages.length);
        securityDescriptor = securityDescriptor == null ? null : Arrays.copyOf(securityDescriptor, securityDescriptor.length);
    }
}
