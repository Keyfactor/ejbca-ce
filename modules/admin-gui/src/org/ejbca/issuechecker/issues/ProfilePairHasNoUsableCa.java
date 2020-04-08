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

import org.apache.log4j.Level;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.issuechecker.ConfigurationIssue;
import org.ejbca.issuechecker.Ticket;
import org.ejbca.issuechecker.TicketDescription;

import java.util.*;

/**
 * Produce an error for each certificate/end entity profile pair without CAs in common.
 *
 * <p>This could happen if none of the available CAs in the end entity profile is allowed by the certificate profile.
 *
 * <p>Tickets created by this issue can be viewed by anyone who has read access to the end entity profile.
 *
 * @version $Id$
 */
public class ProfilePairHasNoUsableCa extends ConfigurationIssue {
    private final EndEntityProfileSession endEntityProfileSession;
    private final CertificateProfileSession certificateProfileSession;
    private final CaSessionLocal caSession;

    public ProfilePairHasNoUsableCa(final EndEntityProfileSession endEntityProfileSession,
                                    final CertificateProfileSession certificateProfileSession,
                                    final CaSessionLocal caSession) {
        this.endEntityProfileSession = endEntityProfileSession;
        this.certificateProfileSession = certificateProfileSession;
        this.caSession = caSession;
    }

    @Override
    public Level getLevel() {
        return Level.ERROR;
    }

    @Override
    public String getDescriptionLanguageKey() {
        return "PROFILE_PAIR_HAS_NO_USABLE_CA_ISSUE_DESCRIPTION";
    }

    @Override
    public String getDatabaseValue() {
        return "ProfilePairHasNoUsableCa";
    }

    @Override
    public List<Ticket> getTickets() {
        final List<Ticket> tickets = new ArrayList<>();
        for (final int endEntityProfileId : endEntityProfileSession.getEndEntityProfileIdToNameMap().keySet()) {
            if (endEntityProfileId == EndEntityConstants.EMPTY_END_ENTITY_PROFILE) {
                continue;
            }
            final EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(endEntityProfileId);
            for (final int certificateProfileId : endEntityProfile.getAvailableCertificateProfileIds()) {
                final CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(certificateProfileId);
                if (hasNoCaInCommon(endEntityProfile, certificateProfile)) {
                    tickets.add(Ticket.builder(this, TicketDescription.fromResource(
                            "PROFILE_PAIR_HAS_NO_USABLE_CA_TICKET_DESCRIPTION",
                            endEntityProfileSession.getEndEntityProfileIdToNameMap().get(endEntityProfileId),
                            certificateProfileSession.getCertificateProfileIdToNameMap().get(certificateProfileId)
                        ))
                        .withAccessControl(authenticationToken -> endEntityProfileSession.isAuthorizedToView(authenticationToken, endEntityProfileId))
                        .build());
                }
            }
        }
        return tickets;
    }

    private boolean hasNoCaInCommon(final EndEntityProfile endEntityProfile, final CertificateProfile certificateProfile) {
        final Set<Integer> endEntityProfileCas = endEntityProfile.getAvailableCAs().contains(CAConstants.ALLCAS)
                ? caSession.getCAIdToNameMap().keySet()
                : new HashSet<>(endEntityProfile.getAvailableCAs());
        final Set<Integer> certificateProfileCas = certificateProfile.getAvailableCAs().contains(CertificateProfile.ANYCA)
                ? caSession.getCAIdToNameMap().keySet()
                : new HashSet<>(certificateProfile.getAvailableCAs());

        return intersect(endEntityProfileCas, certificateProfileCas).isEmpty();
    }

    private Set<Integer> intersect(final Set<Integer> endEntityProfileCas, final Set<Integer> certificateProfileCas) {
        final Set<Integer> intersection = new HashSet<>();
        for (final int caId : endEntityProfileCas) {
            if (certificateProfileCas.contains(caId)) {
                intersection.add(caId);
            }
        }
        return intersection;
    }
}
