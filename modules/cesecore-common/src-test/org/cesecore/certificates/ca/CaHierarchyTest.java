/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.certificates.ca;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.function.BiPredicate;
import java.util.stream.Collectors;

import org.apache.commons.codec.binary.StringUtils;
import org.junit.Test;

/**
 * Unit tests for {@link CaHierarchy}.
 * 
 * @version $Id$
 */
public class CaHierarchyTest {

    /**
     * Try to create a single CA hierarchy with no CAs.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testSingleCaHierarchyWithNoCas() {
        CaHierarchy.singleCaHierarchyFrom(Collections.emptySet());
    }

    /**
     * Try to create multiple CA hierarchies with no CAs.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testMultipleCaHierarchyWithNoCas() {
        CaHierarchy.caHierarchiesFrom(Collections.emptySet());
    }

    /**
     * Try to create a CA hierarchy without a root.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCaHierarchyWithoutRoot() {
        final BiPredicate<String, String> isSignedBy = (ca1, ca2) -> {
            if (StringUtils.equals(ca1, "rootCa") && StringUtils.equals(ca2, "issuingCa")) {
                return true;
            }
            return false;
        };
        CaHierarchy.singleCaHierarchyFrom(new HashSet<String>(Arrays.asList("rootCa", "issuingCa")), isSignedBy).toList();
    }

    /**
     * Try to create a CA hierarchy with a loop.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCaHierarchyWithLoop() {
        final BiPredicate<String, String> isSignedBy = (ca1, ca2) -> {
            if (StringUtils.equals(ca1, "rootCa") && StringUtils.equals(ca2, "issuingCa1")) {
                return true;
            }
            if (StringUtils.equals(ca1, "issuingCa1") && StringUtils.equals(ca2, "issuingCa2")) {
                return true;
            }
            if (StringUtils.equals(ca1, "issuingCa2") && StringUtils.equals(ca2, "rootCa")) {
                return true;
            }
            return false;
        };
        CaHierarchy.singleCaHierarchyFrom(new HashSet<String>(Arrays.asList("rootCa", "issuingCa1", "issuingCa2")), isSignedBy).toList();
    }

    /**
     * Try to create a CA hierarchy with only a single root.
     */
    @Test
    public void testCaHierarchyWithOnlyRoot() throws Exception {
        final Certificate rootCaCertificate = createMock(Certificate.class);
        final PublicKey rootCaPublicKey = createMock(PublicKey.class);

        expect(rootCaCertificate.getPublicKey()).andReturn(rootCaPublicKey).anyTimes();
        rootCaCertificate.verify(rootCaPublicKey);
        expectLastCall().andVoid();

        replay(rootCaCertificate);
        replay(rootCaPublicKey);

        final CaHierarchy<Certificate> caHierarchy = CaHierarchy.singleCaHierarchyFrom(new HashSet<>(Arrays.asList(rootCaCertificate)));
        assertEquals(Arrays.asList(rootCaCertificate), caHierarchy.toList());

        verify(rootCaCertificate);
        verify(rootCaPublicKey);
    }

    @Test
    public void test2SmallCaHierarchies() throws Exception {
        final Certificate rootCa1Certificate = createMock(Certificate.class);
        final Certificate rootCa2Certificate = createMock(Certificate.class);
        final Certificate issuingCa2Certificate = createMock(Certificate.class);
        final PublicKey rootCa1PublicKey = createMock(PublicKey.class);
        final PublicKey rootCa2PublicKey = createMock(PublicKey.class);
        final PublicKey issuingCa2PublicKey = createMock(PublicKey.class);

        expect(rootCa1Certificate.getPublicKey()).andReturn(rootCa1PublicKey).anyTimes();
        expect(rootCa2Certificate.getPublicKey()).andReturn(rootCa2PublicKey).anyTimes();
        expect(issuingCa2Certificate.getPublicKey()).andReturn(issuingCa2PublicKey).anyTimes();

        rootCa1Certificate.verify(rootCa1PublicKey);
        expectLastCall().andVoid();
        rootCa1Certificate.verify(rootCa2PublicKey);
        expectLastCall().andThrow(new SignatureException());
        rootCa1Certificate.verify(issuingCa2PublicKey);
        expectLastCall().andThrow(new SignatureException());

        rootCa2Certificate.verify(rootCa2PublicKey);
        expectLastCall().andVoid();
        rootCa2Certificate.verify(rootCa1PublicKey);
        expectLastCall().andThrow(new SignatureException());
        rootCa2Certificate.verify(issuingCa2PublicKey);
        expectLastCall().andThrow(new SignatureException());

        issuingCa2Certificate.verify(rootCa1PublicKey);
        expectLastCall().andThrow(new SignatureException());
        issuingCa2Certificate.verify(rootCa2PublicKey);
        expectLastCall().andVoid();
        issuingCa2Certificate.verify(issuingCa2PublicKey);
        expectLastCall().andThrow(new SignatureException());

        replay(rootCa1Certificate);
        replay(rootCa1PublicKey);
        replay(rootCa2Certificate);
        replay(rootCa2PublicKey);
        replay(issuingCa2Certificate);
        replay(issuingCa2PublicKey);

        final List<CaHierarchy<Certificate>> caHierarchies = CaHierarchy
                .caHierarchiesFrom(new HashSet<>(Arrays.asList(rootCa1Certificate, rootCa2Certificate, issuingCa2Certificate)))
                .stream()
                .sorted()
                .collect(Collectors.toList());
        assertEquals("Two CA hierarchies should be created.", 2, caHierarchies.size());
        final List<Certificate> caHierarchy1Certificates = caHierarchies.get(0).toList();
        final List<Certificate> caHierarchy2Certificates = caHierarchies.get(1).toList();
        System.out.println(caHierarchy1Certificates);
        System.out.println(caHierarchy2Certificates);
        assertEquals("Wrong number of CAs in CA hierarchy.", 1, caHierarchy1Certificates.size());
        assertEquals("Wrong number of CAs in CA hierarchy.", 2, caHierarchy2Certificates.size());
        assertTrue("Root must appear before issuing CA.",
                caHierarchy2Certificates.indexOf(rootCa2Certificate) < caHierarchy2Certificates.indexOf(issuingCa2Certificate));

        verify(rootCa1Certificate);
        verify(rootCa1PublicKey);
        verify(rootCa2Certificate);
        verify(rootCa2PublicKey);
        verify(issuingCa2Certificate);
        verify(issuingCa2PublicKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSingleCaHierarchyWithMultipleCaHierarchies() throws Exception {
        final Certificate rootCa1Certificate = createMock(Certificate.class);
        final Certificate rootCa2Certificate = createMock(Certificate.class);
        final PublicKey rootCa1PublicKey = createMock(PublicKey.class);
        final PublicKey rootCa2PublicKey = createMock(PublicKey.class);

        expect(rootCa1Certificate.getPublicKey()).andReturn(rootCa1PublicKey).anyTimes();
        expect(rootCa2Certificate.getPublicKey()).andReturn(rootCa2PublicKey).anyTimes();

        rootCa1Certificate.verify(rootCa1PublicKey);
        expectLastCall().andVoid();
        rootCa1Certificate.verify(rootCa2PublicKey);
        expectLastCall().andThrow(new SignatureException());

        rootCa2Certificate.verify(rootCa2PublicKey);
        expectLastCall().andVoid();
        rootCa2Certificate.verify(rootCa1PublicKey);
        expectLastCall().andThrow(new SignatureException());

        replay(rootCa1Certificate);
        replay(rootCa1PublicKey);
        replay(rootCa2Certificate);
        replay(rootCa2PublicKey);

        CaHierarchy.singleCaHierarchyFrom(new HashSet<>(Arrays.asList(rootCa1Certificate, rootCa2Certificate)));
    }

    /**
     * Try to create a CA hierarchy with one root and two issuing CAs.
     */
    @Test
    public void testCaHierarchyWithOneRootAndTwoIssuingCas() throws Exception {
        final Certificate rootCaCertificate = createMock(Certificate.class);
        final Certificate issuingCa1Certificate = createMock(Certificate.class);
        final Certificate issuingCa2Certificate = createMock(Certificate.class);
        
        final PublicKey rootCaPublicKey = createMock(PublicKey.class);
        final PublicKey issuingCa1PublicKey = createMock(PublicKey.class);
        final PublicKey issuingCa2PublicKey = createMock(PublicKey.class);
        
        expect(rootCaCertificate.getPublicKey()).andReturn(rootCaPublicKey).anyTimes();
        expect(issuingCa1Certificate.getPublicKey()).andReturn(issuingCa1PublicKey).anyTimes();
        expect(issuingCa2Certificate.getPublicKey()).andReturn(issuingCa2PublicKey).anyTimes();

        rootCaCertificate.verify(rootCaPublicKey);
        expectLastCall().andVoid();
        rootCaCertificate.verify(issuingCa1PublicKey);
        expectLastCall().andThrow(new SignatureException());
        rootCaCertificate.verify(issuingCa2PublicKey);
        expectLastCall().andThrow(new SignatureException());

        issuingCa1Certificate.verify(rootCaPublicKey);
        expectLastCall().andVoid();
        issuingCa1Certificate.verify(issuingCa1PublicKey);
        expectLastCall().andThrow(new SignatureException());
        issuingCa1Certificate.verify(issuingCa2PublicKey);
        expectLastCall().andThrow(new SignatureException());

        issuingCa2Certificate.verify(rootCaPublicKey);
        expectLastCall().andVoid();
        issuingCa2Certificate.verify(issuingCa1PublicKey);
        expectLastCall().andThrow(new SignatureException());
        issuingCa2Certificate.verify(issuingCa2PublicKey);
        expectLastCall().andThrow(new SignatureException());

        replay(rootCaCertificate);
        replay(issuingCa1Certificate);
        replay(issuingCa2Certificate);
        replay(rootCaPublicKey);
        replay(issuingCa1PublicKey);
        replay(issuingCa2PublicKey);

        final CaHierarchy<Certificate> caHierarchy = CaHierarchy
                .singleCaHierarchyFrom(new HashSet<>(Arrays.asList(rootCaCertificate, issuingCa1Certificate, issuingCa2Certificate)));
        assertEquals("Three CAs expected in the CA hierarchy.", 3, caHierarchy.toList().size());
        assertEquals("Root CA certificate should be first.", rootCaCertificate, caHierarchy.toList().get(0));

        verify(rootCaCertificate);
        verify(issuingCa1Certificate);
        verify(issuingCa2Certificate);
        verify(rootCaPublicKey);
        verify(issuingCa1PublicKey);
        verify(issuingCa2PublicKey);
    }
    
    /**
     * Try to create a CA hierarchy with one root, two intermediaries and three issuing CAs.
     */
    @Test
    public void testTwoIntermediariesAndThreeIssuingCas() {
        final BiPredicate<String, String> isSignedBy = (ca1, ca2) -> {
            if (StringUtils.equals(ca1, "rootCa") && StringUtils.equals(ca2, "rootCa")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa") && StringUtils.equals(ca2, "intermediary1")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa") && StringUtils.equals(ca2, "intermediary2")) {
                return true;
            }
            if (StringUtils.equals(ca1, "intermediary1") && StringUtils.equals(ca2, "issuingCa1")) {
                return true;
            }
            if (StringUtils.equals(ca1, "intermediary2") && StringUtils.equals(ca2, "issuingCa2")) {
                return true;
            }
            if (StringUtils.equals(ca1, "intermediary2") && StringUtils.equals(ca2, "issuingCa3")) {
                return true;
            }
            return false;
        };

        final List<String> cas = CaHierarchy.singleCaHierarchyFrom(
                new HashSet<String>(Arrays.asList("rootCa", "intermediary1", "intermediary2", "issuingCa1", "issuingCa2", "issuingCa3")), isSignedBy).toList();
        assertEquals("Six CAs expected in the CA hierarchy.", 6, cas.size());
        assertEquals("Root CA must be first.", "rootCa", cas.get(0));
        assertTrue("Intermediary must come before issuing CA.", cas.indexOf("intermediary1") < cas.indexOf("issuingCa1"));
        assertTrue("Intermediary must come before issuing CA.", cas.indexOf("intermediary2") < cas.indexOf("issuingCa2"));
        assertTrue("Intermediary must come before issuing CA.", cas.indexOf("intermediary2") < cas.indexOf("issuingCa3"));
    }

    /**
     * Try to create a CA hierarchy where a root has cross-signed an issuing CA from another CA hierarchy.
     */
    @Test
    public void testCrossSignFromRootCa() {
        final BiPredicate<String, String> isSignedBy = (ca1, ca2) -> {
            if (StringUtils.equals(ca1, "rootCa1") && StringUtils.equals(ca2, "rootCa1")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa1") && StringUtils.equals(ca2, "issuingCa1")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa1") && StringUtils.equals(ca2, "issuingCa2")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa2") && StringUtils.equals(ca2, "rootCa2")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa2") && StringUtils.equals(ca2, "issuingCa2")) {
                return true;
            }
            return false;
        };

        final List<String> cas = CaHierarchy.singleCaHierarchyFrom(
                new HashSet<String>(Arrays.asList("rootCa1", "rootCa2", "issuingCa1", "issuingCa2")), isSignedBy)
                .toList();
        assertEquals("Four CAs expected in CA hierarchy.", 4, cas.size());
        assertTrue("Root CA 1 must come before issuing CA 1.", cas.indexOf("rootCa1") < cas.indexOf("issuingCa1"));
        assertTrue("Root CA 1 must come before issuing CA 2.", cas.indexOf("rootCa1") < cas.indexOf("issuingCa2"));
        assertTrue("Root CA 2 must come before issuing CA 2.", cas.indexOf("rootCa2") < cas.indexOf("issuingCa2"));
    }

    /**
     * Try to create a CA hierarchy where an issuing CA has cross-signed an issuing CA from another CA hierarchy.
     */
    @Test
    public void testCrossSignFromIssuingCa() {
        final BiPredicate<String, String> isSignedBy = (ca1, ca2) -> {
            if (StringUtils.equals(ca1, "rootCa1") && StringUtils.equals(ca2, "rootCa1")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa1") && StringUtils.equals(ca2, "issuingCa1")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa2") && StringUtils.equals(ca2, "rootCa2")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa2") && StringUtils.equals(ca2, "issuingCa2")) {
                return true;
            }
            if (StringUtils.equals(ca1, "issuingCa1") && StringUtils.equals(ca2, "issuingCa2")) {
                return true;
            }
            return false;
        };

        final List<String> cas = CaHierarchy
                .singleCaHierarchyFrom(new HashSet<String>(Arrays.asList("rootCa1", "rootCa2", "issuingCa1", "issuingCa2")), isSignedBy).toList();
        assertEquals("Four CAs expected in CA hierarchy.", 4, cas.size());
        assertTrue("Root CA 1 must come before issuing CA 1.", cas.indexOf("rootCa1") < cas.indexOf("issuingCa1"));
        assertTrue("Root CA 2 must come before issuing CA 2.", cas.indexOf("rootCa2") < cas.indexOf("issuingCa2"));
        assertTrue("Issuing CA 1 must come before issuing CA 2.", cas.indexOf("issuingCa1") < cas.indexOf("issuingCa2"));
    }

    /**
     * Try to create a CA hierarchy with many levels.
     */
    @Test
    public void testDeepCaHierarchy() {
        final BiPredicate<String, String> isSignedBy = (ca1, ca2) -> {
            if (StringUtils.equals(ca1, "rootCa") && StringUtils.equals(ca2, "rootCa")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa") && StringUtils.equals(ca2, "civilCa")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa") && StringUtils.equals(ca2, "govCa")) {
                return true;
            }
            if (StringUtils.equals(ca1, "govCa") && StringUtils.equals(ca2, "finCa")) {
                return true;
            }
            if (StringUtils.equals(ca1, "govCa") && StringUtils.equals(ca2, "secCa")) {
                return true;
            }
            if (StringUtils.equals(ca1, "govCa") && StringUtils.equals(ca2, "govSerCa")) {
                return true;
            }
            if (StringUtils.equals(ca1, "govSerCa") && StringUtils.equals(ca2, "issuingCa")) {
                return true;
            }
            if (StringUtils.equals(ca1, "govSerCa") && StringUtils.equals(ca2, "etsiIssuingCa")) {
                return true;
            }
            return false;
        };
        final List<String> cas = CaHierarchy.singleCaHierarchyFrom(
                new HashSet<String>(Arrays.asList("rootCa", "civilCa", "govCa", "govSerCa", "secCa", "finCa", "issuingCa", "etsiIssuingCa")),
                isSignedBy).toList();
        assertEquals("Eight CAs expected in CA hierarchy.", 8, cas.size());
        assertEquals("Root CA must be first.", "rootCa", cas.get(0));
        assertTrue(cas.indexOf("rootCa") < cas.indexOf("govCa"));
        assertTrue(cas.indexOf("rootCa") < cas.indexOf("civilCa"));
        assertTrue(cas.indexOf("govCa") < cas.indexOf("govSerCa"));
        assertTrue(cas.indexOf("govCa") < cas.indexOf("finCa"));
        assertTrue(cas.indexOf("govCa") < cas.indexOf("secCa"));
        assertTrue(cas.indexOf("govCa") < cas.indexOf("issuingCa"));
        assertTrue(cas.indexOf("govCa") < cas.indexOf("etsiIssuingCa"));
        assertTrue(cas.indexOf("govSerCa") < cas.indexOf("issuingCa"));
        assertTrue(cas.indexOf("govSerCa") < cas.indexOf("etsiIssuingCa"));
    }

    @Test
    public void testStarCaHierarchy() {
        final BiPredicate<String, String> isSignedBy = (ca1, ca2) -> {
            if (StringUtils.equals(ca1, "rootCa1") && StringUtils.equals(ca2, "rootCa1")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa1") && StringUtils.equals(ca2, "center")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa2") && StringUtils.equals(ca2, "rootCa2")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa2") && StringUtils.equals(ca2, "center")) {
                return true;
            }
            if (StringUtils.equals(ca1, "center") && StringUtils.equals(ca2, "bottom1")) {
                return true;
            }
            if (StringUtils.equals(ca1, "center") && StringUtils.equals(ca2, "bottom2")) {
                return true;
            }
            return false;
        };
        final List<String> cas = CaHierarchy
                .singleCaHierarchyFrom(new HashSet<String>(Arrays.asList("rootCa1", "rootCa2", "center", "bottom1", "bottom2")), isSignedBy).toList();
        assertEquals(5, cas.size());
        assertTrue(cas.indexOf("rootCa1") < cas.indexOf("center"));
        assertTrue(cas.indexOf("rootCa2") < cas.indexOf("center"));
        assertTrue(cas.indexOf("center") < cas.indexOf("bottom1"));
        assertTrue(cas.indexOf("center") < cas.indexOf("bottom2"));
    }

    @Test
    public void testIterator() {
        final BiPredicate<String, String> isSignedBy = (ca1, ca2) -> {
            if (StringUtils.equals(ca1, "rootCa") && StringUtils.equals(ca2, "rootCa")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa") && StringUtils.equals(ca2, "issuingCa")) {
                return true;
            }
            return false;
        };
        final CaHierarchy<String> caHierarchy = CaHierarchy.singleCaHierarchyFrom(new HashSet<String>(Arrays.asList("rootCa", "issuingCa")),
                isSignedBy);
        final List<String> cas = new ArrayList<>();
        for (final String ca : caHierarchy) {
            cas.add(ca);
        }
        assertEquals("rootCa", cas.get(0));
        assertEquals("issuingCa", cas.get(1));
    }
}
