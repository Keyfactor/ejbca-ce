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

package org.ejbca.issuechecker.issues;

import java.util.AbstractMap;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.log4j.Level;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.util.AlgorithmTools;
import org.ejbca.issuechecker.Issue;
import org.ejbca.issuechecker.Ticket;

/**
 * Warn whenever a certificate profile uses an ECC-based signature scheme, and has the key usage
 * 'keyEncipherment' enabled.  Section 3 of RFC 5480 defines the keyUsage bits allowed with
 * Elliptic Curve Cryptography Subject Public Key Information. Key Encipherment is not on the list.
 *
 * @version $Id$
 */
public class EccWithKeyEncipherment extends Issue {
    private final CertificateProfileSessionLocal certificateProfileSession;

    public EccWithKeyEncipherment(final CertificateProfileSessionLocal certificateProfileSession) {
        this.certificateProfileSession = certificateProfileSession;
    }

    @Override
    public List<Ticket> getTickets() {
        return certificateProfileSession.getCertificateProfileIdToNameMap()
                .entrySet()
                .stream()
                /* Ignore built-in certificate profiles such as SERVER and ENDUSER */
                .filter(idToName -> !CertificateProfileConstants.isFixedCertificateProfile(idToName.getKey()))
                .map(idToName -> new AbstractMap.SimpleEntry<String, CertificateProfile>(idToName.getValue(), certificateProfileSession.getCertificateProfile(idToName.getKey())))
                .filter(entry -> AlgorithmTools.isEccCapable(entry.getValue()))
                .filter(entry -> entry.getValue().getKeyUsage(CertificateConstants.KEYENCIPHERMENT))
                .map(entry -> new Ticket(this, "ECC_WITH_KEY_ENCIPHERMENT_TICKET_DESCRIPTION", entry.getKey()))
                .collect(Collectors.toList());
    }

    @Override
    public Level getLevel() {
        return Level.WARN;
    }

    @Override
    public String getDescriptionLanguageKey() {
        return "ECC_WITH_KEY_ENCIPHERMENT_ISSUE_DESCRIPTION";
    }

    @Override
    public String getDatabaseValue() {
        return "EccWithKeyEncipherment";
    }
}
