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

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.junit.Test;

/**
 * Unit tests for {@link BasicConstraintsViolation}.
 * 
 * @version $Id$
 */
public class BasicConstraintsViolationTest {

    @Test
    public void getTickets() {
        final X509Certificate root = createMock(X509Certificate.class);
        final X509Certificate issuingCa = createMock(X509Certificate.class);
        expect(root.getBasicConstraints()).andReturn(0).anyTimes();
        expect(issuingCa.getBasicConstraints()).andReturn(37).anyTimes();
        replay(root);
        replay(issuingCa);
        final List<Certificate> certificateChain = new ArrayList<>();
        certificateChain.add(issuingCa);
        certificateChain.add(root);

        final CAInfo caInfo1 = createMock(CAInfo.class);
        final CAInfo caInfo2 = createMock(CAInfo.class);
        final CAInfo caInfo3 = createMock(CAInfo.class);
        expect(caInfo1.getCAType()).andReturn(CAInfo.CATYPE_CVC);
        expect(caInfo2.getCAType()).andReturn(CAInfo.CATYPE_X509);
        expect(caInfo3.getCAType()).andReturn(CAInfo.CATYPE_X509);
        expect(caInfo1.getCAId()).andReturn(1).anyTimes();
        expect(caInfo2.getCAId()).andReturn(2).anyTimes();
        expect(caInfo3.getCAId()).andReturn(3).anyTimes();
        expect(caInfo2.getCertificateChain()).andReturn(certificateChain).anyTimes();
        expect(caInfo3.getCertificateChain()).andReturn(null).anyTimes();
        replay(caInfo1);
        replay(caInfo2);
        replay(caInfo3);
        
        final CaSessionLocal caSession = createMock(CaSessionLocal.class);
        final Map<Integer, String> idToName = new HashMap<>();
        idToName.put(1, "CVC");
        idToName.put(2, "Initialized X509");
        idToName.put(3, "Uninitialized X509");
        expect(caSession.getCAIdToNameMap()).andReturn(idToName);
        expect(caSession.getCAInfoInternal(1)).andReturn(caInfo1);
        expect(caSession.getCAInfoInternal(2)).andReturn(caInfo2);
        expect(caSession.getCAInfoInternal(3)).andReturn(caInfo3);
        replay(caSession);
        
        final List<String> ticketDescriptions = new BasicConstraintsViolation(caSession)
                .getTickets()
                .stream()
                .map(ticket -> ticket.getTicketDescription().toString())
                .sorted()
                .collect(Collectors.toList());
        verify(caSession);
        verify(caInfo1);
        verify(caInfo2);
        assertEquals(1, ticketDescriptions.size());
        assertEquals("(BASIC_CONSTRAINTS_VIOLATION_TICKET_DESCRIPTION, Initialized X509)", ticketDescriptions.get(0));
    }

    @Test
    public void databaseValue() {
        assertEquals("The database value is not allowed to change.", "BasicConstraintsViolation",
                new BasicConstraintsViolation(null).getDatabaseValue());
    }

    /**
     * Test path length constraint (X) -> (0) -> (X)
     */
    @Test
    public void isViolatingBaseConstraint1() {
        final X509Certificate root = createMock(X509Certificate.class);
        final X509Certificate intermediateCa = createMock(X509Certificate.class);
        final X509Certificate issuingCa = createMock(X509Certificate.class);
        expect(root.getBasicConstraints()).andReturn(Integer.MAX_VALUE).anyTimes();
        expect(intermediateCa.getBasicConstraints()).andReturn(0).anyTimes();
        expect(issuingCa.getBasicConstraints()).andReturn(Integer.MAX_VALUE).anyTimes();
        replay(root);
        replay(intermediateCa);
        replay(issuingCa);
        final List<X509Certificate> certificateChain = new ArrayList<>();
        certificateChain.add(issuingCa);
        certificateChain.add(intermediateCa);
        certificateChain.add(root);
        final BasicConstraintsViolation basicConstraintsViolation = new BasicConstraintsViolation(null);
        assertTrue(basicConstraintsViolation.isViolatingBasicConstraint(certificateChain));
    }

    /**
     * Test path length constraint (X) -> (3) -> (0) -> (1)
     */
    @Test
    public void isViolatingBaseConstraint2() {
        final X509Certificate root = createMock(X509Certificate.class);
        final X509Certificate intermediateCa = createMock(X509Certificate.class);
        final X509Certificate issuingCa1 = createMock(X509Certificate.class);
        final X509Certificate issuingCa2 = createMock(X509Certificate.class);
        expect(root.getBasicConstraints()).andReturn(Integer.MAX_VALUE).anyTimes();
        expect(intermediateCa.getBasicConstraints()).andReturn(3).anyTimes();
        expect(issuingCa1.getBasicConstraints()).andReturn(1).anyTimes();
        expect(issuingCa2.getBasicConstraints()).andReturn(0).anyTimes();
        replay(root);
        replay(intermediateCa);
        replay(issuingCa1);
        replay(issuingCa2);
        final List<X509Certificate> certificateChain = new ArrayList<>();
        certificateChain.add(issuingCa1);
        certificateChain.add(issuingCa2);
        certificateChain.add(intermediateCa);
        certificateChain.add(root);
        final BasicConstraintsViolation basicConstraintsViolation = new BasicConstraintsViolation(null);
        assertTrue(basicConstraintsViolation.isViolatingBasicConstraint(certificateChain));
    }

    /**
     * Test path length constraint (0) -> (0)
     */
    @Test
    public void isViolatingBaseConstraint3() {
        final X509Certificate root = createMock(X509Certificate.class);
        final X509Certificate issuingCa = createMock(X509Certificate.class);
        expect(root.getBasicConstraints()).andReturn(0).anyTimes();
        expect(issuingCa.getBasicConstraints()).andReturn(0).anyTimes();
        replay(root);
        replay(issuingCa);
        final List<X509Certificate> certificateChain = new ArrayList<>();
        certificateChain.add(issuingCa);
        certificateChain.add(root);
        final BasicConstraintsViolation basicConstraintsViolation = new BasicConstraintsViolation(null);
        assertTrue(basicConstraintsViolation.isViolatingBasicConstraint(certificateChain));
    }

    /**
     * Test path length constraints (X) -> 1 -> 0.
     */
    @Test
    public void isNotViolatingBaseConstraint1() {
        final X509Certificate root = createMock(X509Certificate.class);
        final X509Certificate intermediateCa = createMock(X509Certificate.class);
        final X509Certificate issuingCa = createMock(X509Certificate.class);
        expect(root.getBasicConstraints()).andReturn(Integer.MAX_VALUE).anyTimes();
        expect(intermediateCa.getBasicConstraints()).andReturn(1).anyTimes();
        expect(issuingCa.getBasicConstraints()).andReturn(0).anyTimes();
        replay(root);
        replay(intermediateCa);
        replay(issuingCa);
        final List<X509Certificate> certificateChain = new ArrayList<>();
        certificateChain.add(issuingCa);
        certificateChain.add(intermediateCa);
        certificateChain.add(root);
        final BasicConstraintsViolation basicConstraintsViolation = new BasicConstraintsViolation(null);
        assertFalse(basicConstraintsViolation.isViolatingBasicConstraint(certificateChain));
    }

    /**
     * Test path length constraints 2 -> 1 -> 0.
     */
    @Test
    public void isNotViolatingBaseConstraint2() {
        final X509Certificate root = createMock(X509Certificate.class);
        final X509Certificate intermediateCa = createMock(X509Certificate.class);
        final X509Certificate issuingCa = createMock(X509Certificate.class);
        expect(root.getBasicConstraints()).andReturn(2).anyTimes();
        expect(intermediateCa.getBasicConstraints()).andReturn(1).anyTimes();
        expect(issuingCa.getBasicConstraints()).andReturn(0).anyTimes();
        replay(root);
        replay(intermediateCa);
        replay(issuingCa);
        final List<X509Certificate> certificateChain = new ArrayList<>();
        certificateChain.add(issuingCa);
        certificateChain.add(intermediateCa);
        certificateChain.add(root);
        final BasicConstraintsViolation basicConstraintsViolation = new BasicConstraintsViolation(null);
        assertFalse(basicConstraintsViolation.isViolatingBasicConstraint(certificateChain));
    }

    /**
     * Test path length constraints (X) -> (X) -> 0.
     */
    @Test
    public void isNotViolatingBaseConstraint3() {
        final X509Certificate root = createMock(X509Certificate.class);
        final X509Certificate intermediateCa = createMock(X509Certificate.class);
        final X509Certificate issuingCa = createMock(X509Certificate.class);
        expect(root.getBasicConstraints()).andReturn(Integer.MAX_VALUE).anyTimes();
        expect(intermediateCa.getBasicConstraints()).andReturn(Integer.MAX_VALUE).anyTimes();
        expect(issuingCa.getBasicConstraints()).andReturn(0).anyTimes();
        replay(root);
        replay(intermediateCa);
        replay(issuingCa);
        final List<X509Certificate> certificateChain = new ArrayList<>();
        certificateChain.add(issuingCa);
        certificateChain.add(intermediateCa);
        certificateChain.add(root);
        final BasicConstraintsViolation basicConstraintsViolation = new BasicConstraintsViolation(null);
        assertFalse(basicConstraintsViolation.isViolatingBasicConstraint(certificateChain));
    }

    /**
     * Test path length constraint (X) -> [-1] (the issuing CA is not a CA or lacks the basic constraints extension).
     */
    @Test
    public void isViolatingBaseConstraint4() {
        final X509Certificate root = createMock(X509Certificate.class);
        final X509Certificate issuingCa = createMock(X509Certificate.class);
        expect(root.getBasicConstraints()).andReturn(Integer.MAX_VALUE).anyTimes();
        expect(issuingCa.getBasicConstraints()).andReturn(-1).anyTimes();
        replay(root);
        replay(issuingCa);
        final List<X509Certificate> certificateChain = new ArrayList<>();
        certificateChain.add(issuingCa);
        certificateChain.add(root);
        final BasicConstraintsViolation basicConstraintsViolation = new BasicConstraintsViolation(null);
        assertTrue(basicConstraintsViolation.isViolatingBasicConstraint(certificateChain));
    }
}
