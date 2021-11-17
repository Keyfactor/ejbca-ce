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

import java.util.Arrays;
import java.util.List;

import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.util.MapTools;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.issuechecker.Ticket;
import org.junit.Test;

import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.mock;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

/**
 * Unit tests for {@link ProfilePairHasNoUsableCa}.
 * 
 * @version $Id$
 */
public class ProfilePairHasNoUsableCaTest {

    @Test
    public void noTicketsForProfilesWithAnyCa() {
        final EndEntityProfileSession endEntityProfileSession = mock(EndEntityProfileSession.class);
        final CertificateProfileSession certificateProfileSession = mock(CertificateProfileSession.class);
        final CaSessionLocal caSession = mock(CaSessionLocal.class);
        final EndEntityProfile endEntityProfile = mock(EndEntityProfile.class);
        final CertificateProfile certificateProfile = mock(CertificateProfile.class);
        expect(certificateProfile.getAvailableCAs())
                .andReturn(Arrays.asList(CertificateProfile.ANYCA))
                .anyTimes();
        expect(endEntityProfile.getAvailableCAs())
                .andReturn(Arrays.asList(CAConstants.ALLCAS))
                .anyTimes();
        expect(endEntityProfile.getAvailableCertificateProfileIds())
                .andReturn(Arrays.asList(1))
                .anyTimes();
        expect(endEntityProfileSession.getEndEntityProfileIdToNameMap())
                .andReturn(MapTools.unmodifiableMap(
                1, "EMPTY",
                2, "End Entity Profile"))
                .anyTimes();
        expect(endEntityProfileSession.getEndEntityProfile(eq(2)))
                .andReturn(endEntityProfile)
                .once();
        expect(certificateProfileSession.getCertificateProfileIdToNameMap())
                .andReturn(MapTools.unmodifiableMap(
                1, "Certificate Profile"
                ))
                .anyTimes();
        expect(certificateProfileSession.getCertificateProfile(eq(1)))
                .andReturn(certificateProfile)
                .anyTimes();
        expect(caSession.getCAIdToNameMap())
                .andReturn(MapTools.unmodifiableMap(1, "CA 1"))
                .anyTimes();
        replay(endEntityProfileSession,
                certificateProfileSession,
                caSession,
                endEntityProfile,
                certificateProfile);
        final ProfilePairHasNoUsableCa profilePairHasNoUsableCa = new ProfilePairHasNoUsableCa(
                endEntityProfileSession,
                certificateProfileSession,
                caSession
        );
        final List<Ticket> tickets = profilePairHasNoUsableCa.getTickets();
        verify(endEntityProfileSession,
                certificateProfileSession,
                caSession,
                endEntityProfile,
                certificateProfile);
        assertEquals(0, tickets.size());
    }

    @Test
    public void noTicketsForProfilesWithCaInCommon() {
        final EndEntityProfileSession endEntityProfileSession = mock(EndEntityProfileSession.class);
        final CertificateProfileSession certificateProfileSession = mock(CertificateProfileSession.class);
        final CaSessionLocal caSession = mock(CaSessionLocal.class);
        final EndEntityProfile endEntityProfile = mock(EndEntityProfile.class);
        final CertificateProfile certificateProfile = mock(CertificateProfile.class);
        expect(certificateProfile.getAvailableCAs())
                .andReturn(Arrays.asList(1))
                .anyTimes();
        expect(endEntityProfile.getAvailableCAs())
                .andReturn(Arrays.asList(1))
                .anyTimes();
        expect(endEntityProfile.getAvailableCertificateProfileIds())
                .andReturn(Arrays.asList(1))
                .anyTimes();
        expect(endEntityProfileSession.getEndEntityProfileIdToNameMap())
                .andReturn(MapTools.unmodifiableMap(
                        1, "EMPTY",
                        2, "End Entity Profile"))
                .anyTimes();
        expect(endEntityProfileSession.getEndEntityProfile(eq(2)))
                .andReturn(endEntityProfile)
                .once();
        expect(certificateProfileSession.getCertificateProfileIdToNameMap())
                .andReturn(MapTools.unmodifiableMap(
                        1, "Certificate Profile"
                ))
                .anyTimes();
        expect(certificateProfileSession.getCertificateProfile(eq(1)))
                .andReturn(certificateProfile)
                .anyTimes();
        expect(caSession.getCAIdToNameMap())
                .andReturn(MapTools.unmodifiableMap(1, "CA 1"))
                .anyTimes();
        replay(endEntityProfileSession,
                certificateProfileSession,
                caSession,
                endEntityProfile,
                certificateProfile);
        final ProfilePairHasNoUsableCa profilePairHasNoUsableCa = new ProfilePairHasNoUsableCa(
                endEntityProfileSession,
                certificateProfileSession,
                caSession
        );
        final List<Ticket> tickets = profilePairHasNoUsableCa.getTickets();
        verify(endEntityProfileSession,
                certificateProfileSession,
                caSession,
                endEntityProfile,
                certificateProfile);
        assertEquals(0, tickets.size());
    }

    @Test
    public void get1TicketForProfilesWithoutACaInCommon() {
        final EndEntityProfileSession endEntityProfileSession = mock(EndEntityProfileSession.class);
        final CertificateProfileSession certificateProfileSession = mock(CertificateProfileSession.class);
        final CaSessionLocal caSession = mock(CaSessionLocal.class);
        final EndEntityProfile endEntityProfile = mock(EndEntityProfile.class);
        final CertificateProfile certificateProfile = mock(CertificateProfile.class);
        expect(certificateProfile.getAvailableCAs())
                .andReturn(Arrays.asList(1))
                .anyTimes();
        expect(endEntityProfile.getAvailableCAs())
                .andReturn(Arrays.asList(2))
                .anyTimes();
        expect(endEntityProfile.getAvailableCertificateProfileIds())
                .andReturn(Arrays.asList(1))
                .anyTimes();
        expect(endEntityProfileSession.getEndEntityProfileIdToNameMap())
                .andReturn(MapTools.unmodifiableMap(
                        1, "EMPTY",
                        2, "End Entity Profile"))
                .anyTimes();
        expect(endEntityProfileSession.getEndEntityProfile(eq(2)))
                .andReturn(endEntityProfile)
                .once();
        expect(certificateProfileSession.getCertificateProfileIdToNameMap())
                .andReturn(MapTools.unmodifiableMap(
                        1, "Certificate Profile"
                ))
                .anyTimes();
        expect(certificateProfileSession.getCertificateProfile(eq(1)))
                .andReturn(certificateProfile)
                .anyTimes();
        expect(caSession.getCAIdToNameMap())
                .andReturn(MapTools.unmodifiableMap(
                        1, "CA 1",
                        2, "CA 2"))
                .anyTimes();
        replay(endEntityProfileSession,
                certificateProfileSession,
                caSession,
                endEntityProfile,
                certificateProfile);
        final ProfilePairHasNoUsableCa profilePairHasNoUsableCa = new ProfilePairHasNoUsableCa(
                endEntityProfileSession,
                certificateProfileSession,
                caSession
        );
        final List<Ticket> tickets = profilePairHasNoUsableCa.getTickets();
        verify(endEntityProfileSession,
                certificateProfileSession,
                caSession,
                endEntityProfile,
                certificateProfile);
        assertEquals(1, tickets.size());
        assertEquals(
                "(PROFILE_PAIR_HAS_NO_USABLE_CA_TICKET_DESCRIPTION, End Entity Profile, Certificate Profile)",
                tickets.get(0).getTicketDescription().toString()
        );
    }

    @Test
    public void databaseValue() {
        assertEquals("The database value is not allowed to change.", "ProfilePairHasNoUsableCa",
                new ProfilePairHasNoUsableCa(null, null, null).getDatabaseValue());
    }
}
