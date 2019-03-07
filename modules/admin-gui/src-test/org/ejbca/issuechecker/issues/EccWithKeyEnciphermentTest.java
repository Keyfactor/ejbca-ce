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

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

import java.util.List;
import java.util.stream.Collectors;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.junit.Test;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

/**
 * Unit tests for {@link EccWithKeyEncipherment}.
 * 
 * @version $Id$
 */
public class EccWithKeyEnciphermentTest {

    @Test
    public void getTickets() {
        final CertificateProfile eccButNoKeyEncipherment = createMock(CertificateProfile.class);
        expect(eccButNoKeyEncipherment.getAvailableKeyAlgorithmsAsList())
                .andReturn(ImmutableList.of("ECDSA"))
                .anyTimes();
        expect(eccButNoKeyEncipherment.getKeyUsage(eq(CertificateConstants.KEYENCIPHERMENT)))
                .andReturn(false);
        final CertificateProfile keyEnciphermentButNoEcc = createMock(CertificateProfile.class);
        expect(keyEnciphermentButNoEcc.getAvailableKeyAlgorithmsAsList())
                .andReturn(ImmutableList.of("RSA"))
                .anyTimes();
        expect(keyEnciphermentButNoEcc.getKeyUsage(eq(CertificateConstants.KEYENCIPHERMENT)))
                .andReturn(true);
        final CertificateProfile eccAndKeyEncipherment1 = createMock(CertificateProfile.class);
        expect(eccAndKeyEncipherment1.getAvailableKeyAlgorithmsAsList())
                .andReturn(ImmutableList.of("ECDSA"))
                .anyTimes();
        expect(eccAndKeyEncipherment1.getKeyUsage(eq(CertificateConstants.KEYENCIPHERMENT)))
                .andReturn(true);
        final CertificateProfile eccAndKeyEncipherment2 = createMock(CertificateProfile.class);
        expect(eccAndKeyEncipherment2.getAvailableKeyAlgorithmsAsList())
                .andReturn(ImmutableList.of("ECGOST3410", "RSA", "DSTU4145"))
                .anyTimes();
        expect(eccAndKeyEncipherment2.getKeyUsage(eq(CertificateConstants.KEYENCIPHERMENT)))
                .andReturn(true);
        final CertificateProfileSessionLocal certificateProfileSession = createMock(CertificateProfileSessionLocal.class);
        expect(certificateProfileSession.getCertificateProfileIdToNameMap())
            .andReturn(new ImmutableMap.Builder<Integer, String>()
                .put(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, "ENDUSER")
                .put(10, "eccButNoKeyEncipherment")
                .put(11, "keyEnciphermentButNoEcc")
                .put(12, "eccAndKeyEncipherment1")
                .put(13, "eccAndKeyEncipherment2")
                .build())
            .atLeastOnce();
        expect(certificateProfileSession.getCertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER))
                .andReturn(new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER))
                .atLeastOnce();
        expect(certificateProfileSession.getCertificateProfile(10))
            .andReturn(eccButNoKeyEncipherment)
            .atLeastOnce();
        expect(certificateProfileSession.getCertificateProfile(11))
            .andReturn(keyEnciphermentButNoEcc)
            .atLeastOnce();
        expect(certificateProfileSession.getCertificateProfile(12))
            .andReturn(eccAndKeyEncipherment1)
            .atLeastOnce();
        expect(certificateProfileSession.getCertificateProfile(13))
            .andReturn(eccAndKeyEncipherment2)
            .atLeastOnce();
        expect(certificateProfileSession.authorizedToProfileWithResource(
                anyObject(AuthenticationToken.class), 
                anyObject(CertificateProfile.class),
                eq(false),
                eq(StandardRules.CERTIFICATEPROFILEVIEW.resource())))
            .andReturn(true)
            .anyTimes();
        replay(eccButNoKeyEncipherment);
        replay(keyEnciphermentButNoEcc);
        replay(eccAndKeyEncipherment1);
        replay(eccAndKeyEncipherment2);
        replay(certificateProfileSession);
        final List<String> ticketDescriptions = new EccWithKeyEncipherment(certificateProfileSession)
                .getTickets()
                .stream()
                .map(ticket -> ticket.getTicketDescription().toString())
                .sorted()
                .collect(Collectors.toList());
        verify(certificateProfileSession);
        assertEquals(2, ticketDescriptions.size());
        assertEquals("(ECC_WITH_KEY_ENCIPHERMENT_TICKET_DESCRIPTION, eccAndKeyEncipherment1)", ticketDescriptions.get(0));
        assertEquals("(ECC_WITH_KEY_ENCIPHERMENT_TICKET_DESCRIPTION, eccAndKeyEncipherment2)", ticketDescriptions.get(1));
    }

    @Test
    public void databaseValue() {
        assertEquals("The database value is not allowed to change since.", "EccWithKeyEncipherment",
                new EccWithKeyEncipherment(null).getDatabaseValue());
    }
}
