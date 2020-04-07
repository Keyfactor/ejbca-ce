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

import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.util.MapTools;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.issuechecker.Ticket;
import org.junit.Test;

import java.util.*;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

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
        final CAInfo caInfo = mock(CAInfo.class);
        expect(caInfo.getStatus())
                .andReturn(CAConstants.CA_ACTIVE);
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
        expect(caSession.getCAInfoInternal(eq(1)))
                .andReturn(caInfo)
                .anyTimes();
        replay(endEntityProfileSession,
                certificateProfileSession,
                caSession,
                endEntityProfile,
                certificateProfile,
                caInfo);
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
                certificateProfile,
                caInfo);
        assertEquals(0, tickets.size());
    }

    @Test
    public void noTicketsForProfilesWithCaInCommon() {
        final EndEntityProfileSession endEntityProfileSession = mock(EndEntityProfileSession.class);
        final CertificateProfileSession certificateProfileSession = mock(CertificateProfileSession.class);
        final CaSessionLocal caSession = mock(CaSessionLocal.class);
        final EndEntityProfile endEntityProfile = mock(EndEntityProfile.class);
        final CertificateProfile certificateProfile = mock(CertificateProfile.class);
        final CAInfo caInfo = mock(CAInfo.class);
        expect(caInfo.getStatus())
                .andReturn(CAConstants.CA_ACTIVE);
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
        expect(caSession.getCAInfoInternal(eq(1)))
                .andReturn(caInfo)
                .anyTimes();
        replay(endEntityProfileSession,
                certificateProfileSession,
                caSession,
                endEntityProfile,
                certificateProfile,
                caInfo);
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
                certificateProfile,
                caInfo);
        assertEquals(0, tickets.size());
    }

    @Test
    public void get1TicketForProfilesWithoutACaInCommon() {
        final EndEntityProfileSession endEntityProfileSession = mock(EndEntityProfileSession.class);
        final CertificateProfileSession certificateProfileSession = mock(CertificateProfileSession.class);
        final CaSessionLocal caSession = mock(CaSessionLocal.class);
        final EndEntityProfile endEntityProfile = mock(EndEntityProfile.class);
        final CertificateProfile certificateProfile = mock(CertificateProfile.class);
        final CAInfo caInfo1 = mock(CAInfo.class);
        final CAInfo caInfo2 = mock(CAInfo.class);
        expect(caInfo1.getStatus())
                .andReturn(CAConstants.CA_ACTIVE)
                .anyTimes();
        expect(caInfo2.getStatus())
                .andReturn(CAConstants.CA_ACTIVE)
                .anyTimes();
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
        expect(caSession.getCAInfoInternal(eq(1)))
                .andReturn(caInfo1)
                .anyTimes();
        expect(caSession.getCAInfoInternal(eq(2)))
                .andReturn(caInfo2)
                .anyTimes();
        replay(endEntityProfileSession,
                certificateProfileSession,
                caSession,
                endEntityProfile,
                certificateProfile,
                caInfo1,
                caInfo2);
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
                certificateProfile,
                caInfo1,
                caInfo2);
        assertEquals(1, tickets.size());
        assertEquals(
                "(PROFILE_PAIR_HAS_NO_USABLE_CA_TICKET_DESCRIPTION, End Entity Profile, Certificate Profile)",
                tickets.get(0).getTicketDescription().toString()
        );
    }

    @Test
    public void get1TicketForExpiredCa() {
        final EndEntityProfileSession endEntityProfileSession = mock(EndEntityProfileSession.class);
        final CertificateProfileSession certificateProfileSession = mock(CertificateProfileSession.class);
        final CaSessionLocal caSession = mock(CaSessionLocal.class);
        final EndEntityProfile endEntityProfile = mock(EndEntityProfile.class);
        final CertificateProfile certificateProfile = mock(CertificateProfile.class);
        final CAInfo caInfo = mock(CAInfo.class);
        expect(caInfo.getStatus())
                .andReturn(CAConstants.CA_EXPIRED)
                .anyTimes();
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
        expect(caSession.getCAInfoInternal(eq(1)))
                .andReturn(caInfo)
                .anyTimes();
        replay(endEntityProfileSession,
                certificateProfileSession,
                caSession,
                endEntityProfile,
                certificateProfile,
                caInfo);
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
                certificateProfile,
                caInfo);
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
