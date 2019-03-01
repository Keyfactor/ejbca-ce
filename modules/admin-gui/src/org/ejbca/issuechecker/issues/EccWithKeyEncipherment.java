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

import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.log4j.Level;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.util.AlgorithmTools;
import org.ejbca.issuechecker.ConfigurationIssue;
import org.ejbca.issuechecker.Ticket;
import org.ejbca.issuechecker.TicketDescription;

/**
 * Warn whenever a certificate profile uses an ECC-based signature scheme, and has the key usage
 * 'keyEncipherment' enabled.  Section 3 of RFC 5480 defines the keyUsage bits allowed with
 * Elliptic Curve Cryptography Subject Public Key Information. Key Encipherment is not on the list.
 *
 * <p>Ticket created by this issue can be viewed by anyone who has view access to the certificate
 * profile specified as target.
 *
 * @version $Id$
 */
public class EccWithKeyEncipherment extends ConfigurationIssue {
    private final CertificateProfileSessionLocal certificateProfileSession;

    /**
     * Wrapper class used to increase the readability of the code.
     */
    private final class CertificateProfileEntry {
        private final CertificateProfile certificateProfile;
        private final int certificateProfileId;
        private final String certificateProfileName;

        public CertificateProfileEntry(final Map.Entry<Integer, String> mapEntry) {
            this.certificateProfile = certificateProfileSession.getCertificateProfile(mapEntry.getKey());
            this.certificateProfileId = mapEntry.getKey();
            this.certificateProfileName = mapEntry.getValue();
        }
    }

    public EccWithKeyEncipherment(final CertificateProfileSessionLocal certificateProfileSession) {
        this.certificateProfileSession = certificateProfileSession;
    }

    @Override
    public List<Ticket> getTickets() {
        return certificateProfileSession.getCertificateProfileIdToNameMap()
                .entrySet()
                .stream()
                .map(mapEntry -> new CertificateProfileEntry(mapEntry))
                .filter(entry -> isCertificateProfileCreatedByUser(entry.certificateProfileId))
                .filter(entry -> AlgorithmTools.isEccCapable(entry.certificateProfile))
                .filter(entry -> entry.certificateProfile.getKeyUsage(CertificateConstants.KEYENCIPHERMENT))
                .map(entry -> Ticket
                        .builder(this, TicketDescription.fromResource("ECC_WITH_KEY_ENCIPHERMENT_TICKET_DESCRIPTION", entry.certificateProfileName))
                        .withAccessControl(createAccessControlRule(entry.certificateProfile))
                        .build())
                .collect(Collectors.toList());
    }

    /**
     * Determine if the certificate profile is created by the user, i.e. not one of the fixed certificate
     * profiles built into EJBCA, e.g. ROOTCA, SERVER or ENDUSER.
     *
     * @param certificateProfileId the ID of the certificate profile to check
     * @return true if the certificate profile is created by the user, false otherwise.
     */
    private boolean isCertificateProfileCreatedByUser(final int certificateProfileId) {
        return !CertificateProfileConstants.isFixedCertificateProfile(certificateProfileId);
    }

    private Predicate<AuthenticationToken> createAccessControlRule(final CertificateProfile certificateProfile) {
        return authenticationToken -> certificateProfileSession.authorizedToProfileWithResource(authenticationToken,
                certificateProfile, /* logging */ false, StandardRules.CERTIFICATEPROFILEVIEW.resource());
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
