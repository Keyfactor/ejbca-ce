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
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit tests for {@link CaHierarchy}.
 * 
 * @version $Id$
 */
public class CaHierarchyTest {

    @BeforeClass
    public static void enableTrace() {
        Logger.getRootLogger().setLevel(Level.TRACE);
    }

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
     * Try to create CA hierarchies from two root CA certificates, both representing the same CA.
     * 
     * <p>This could happen if the root CA has been renewed.
     * 
     * <p><b>Implementation note:</b> Creating a CA hierarchy with a renewed root is currently not supported. However,
     * technically it would be possibly to support this.
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testCaHierarchyWithRenewedRoot() throws Exception {
        final Certificate rootCa1Certificate = createMock(Certificate.class);
        final Certificate rootCa2Certificate = createMock(Certificate.class);
        final PublicKey rootCaPublicKey = createMock(PublicKey.class);

        expect(rootCa1Certificate.getPublicKey()).andReturn(rootCaPublicKey).anyTimes();
        expect(rootCa2Certificate.getPublicKey()).andReturn(rootCaPublicKey).anyTimes();

        rootCa1Certificate.verify(rootCaPublicKey);
        expectLastCall().andVoid().anyTimes();
        rootCa2Certificate.verify(rootCaPublicKey);
        expectLastCall().andVoid().anyTimes();

        replay(rootCa1Certificate);
        replay(rootCa2Certificate);
        replay(rootCaPublicKey);

        CaHierarchy.caHierarchiesFrom(new HashSet<>(Arrays.asList(rootCa1Certificate, rootCa2Certificate)));
    }

    /**
     * Try to construct a CA hierarchy with a very deep certificate chain.
     * 
     * <p><b>Implementation note:</b> This limitation is mostly here to guard against infinite recursion which
     * could happen if there is a bug in the implementation.
     */
    @Test(expected = IllegalStateException.class)
    public void testTooDeepCaHierarchy() {
        final Set<Integer> cas = IntStream.rangeClosed(1, 100).boxed().collect(Collectors.toSet());
        // 1 has signed 1, 1 has signed 2, 2 has signed 3 ect.
        final BiPredicate<Integer, Integer> isSignedBy = (a, b) -> {
            if (a == 1 && b == 1) {
                return true;
            }
            if (a + 1 == b) {
                return true;
            }
            return false;
        };
        CaHierarchy.singleCaHierarchyFrom(cas, isSignedBy);
    }

    /**
     * Ensure a CA hierarchy with a depth of 99 can be constructed (this is the maximum permitted depth of any CA hierarchy).
     */
    public void testMaxDepthCaHierarchy() {
        final Set<Integer> cas = IntStream.rangeClosed(1, 99).boxed().collect(Collectors.toSet());
        // 1 has signed 1, 1 has signed 2, 2 has signed 3 ect.
        final BiPredicate<Integer, Integer> isSignedBy = (a, b) -> {
            if (a == 1 && b == 1) {
                return true;
            }
            if (a + 1 == b) {
                return true;
            }
            return false;
        };
        CaHierarchy.singleCaHierarchyFrom(cas, isSignedBy);
    }

    /**
     * Try to create CA hierarchies from one root and two issuing CA certificates, 
     * where the issuing CA certificates both represent the same CA.
     * 
     * <p>This could happen if the issuing CA has been renewed.
     */
    @Test
    public void testCaHierarchyWithRenewedIssuingCa() throws Exception {
        final Certificate rootCaCertificate = createMock(Certificate.class);
        final Certificate issuingCa1Certificate = createMock(Certificate.class);
        final Certificate issuingCa2Certificate = createMock(Certificate.class);
        final PublicKey rootCaPublicKey = createMock(PublicKey.class);
        final PublicKey issuingCaPublicKey = createMock(PublicKey.class);

        expect(rootCaCertificate.getPublicKey()).andReturn(rootCaPublicKey).anyTimes();
        expect(issuingCa1Certificate.getPublicKey()).andReturn(issuingCaPublicKey).anyTimes();
        expect(issuingCa2Certificate.getPublicKey()).andReturn(issuingCaPublicKey).anyTimes();

        rootCaCertificate.verify(rootCaPublicKey);
        expectLastCall().andVoid().atLeastOnce();
        rootCaCertificate.verify(issuingCaPublicKey);
        expectLastCall().andThrow(new SignatureException()).atLeastOnce();

        issuingCa1Certificate.verify(rootCaPublicKey);
        expectLastCall().andVoid().atLeastOnce();
        issuingCa1Certificate.verify(issuingCaPublicKey);
        expectLastCall().andThrow(new SignatureException()).atLeastOnce();

        issuingCa2Certificate.verify(rootCaPublicKey);
        expectLastCall().andVoid().atLeastOnce();
        issuingCa2Certificate.verify(issuingCaPublicKey);
        expectLastCall().andThrow(new SignatureException()).atLeastOnce();

        replay(rootCaCertificate);
        replay(issuingCa1Certificate);
        replay(issuingCa2Certificate);
        replay(rootCaPublicKey);
        replay(issuingCaPublicKey);

        final CaHierarchy<Certificate> caHierarchy = CaHierarchy.singleCaHierarchyFrom(new HashSet<>(
                Arrays.asList(issuingCa1Certificate, issuingCa2Certificate, rootCaCertificate)));
        
        verify(rootCaCertificate);
        verify(issuingCa1Certificate);
        verify(issuingCa2Certificate);
        verify(issuingCaPublicKey);
        verify(rootCaPublicKey);
        
        assertEquals(3, caHierarchy.toList().size());
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
        final CaHierarchy<String> caHierarchy = CaHierarchy.singleCaHierarchyFrom(
                new HashSet<String>(Arrays.asList("rootCa", "civilCa", "govCa", "govSerCa", "secCa", "finCa", "issuingCa", "etsiIssuingCa")),
                isSignedBy);
        assertEquals(8, caHierarchy.getEdges().size());
        assertEquals("Eight CAs expected in CA hierarchy.", 8, caHierarchy.size());
        assertEquals("Root CA must be first.", "rootCa", caHierarchy.toList().get(0));
        assertTrue(caHierarchy.toList().indexOf("rootCa") < caHierarchy.toList().indexOf("govCa"));
        assertTrue(caHierarchy.toList().indexOf("rootCa") < caHierarchy.toList().indexOf("civilCa"));
        assertTrue(caHierarchy.toList().indexOf("govCa") < caHierarchy.toList().indexOf("govSerCa"));
        assertTrue(caHierarchy.toList().indexOf("govCa") < caHierarchy.toList().indexOf("finCa"));
        assertTrue(caHierarchy.toList().indexOf("govCa") < caHierarchy.toList().indexOf("secCa"));
        assertTrue(caHierarchy.toList().indexOf("govCa") < caHierarchy.toList().indexOf("issuingCa"));
        assertTrue(caHierarchy.toList().indexOf("govCa") < caHierarchy.toList().indexOf("etsiIssuingCa"));
        assertTrue(caHierarchy.toList().indexOf("govSerCa") < caHierarchy.toList().indexOf("issuingCa"));
        assertTrue(caHierarchy.toList().indexOf("govSerCa") < caHierarchy.toList().indexOf("etsiIssuingCa"));
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
        final CaHierarchy<String> caHierarchy = CaHierarchy
                .singleCaHierarchyFrom(new HashSet<String>(Arrays.asList("rootCa1", "rootCa2", "center", "bottom1", "bottom2")), isSignedBy);
        assertEquals(6, caHierarchy.getEdges().size());
        assertEquals(5, caHierarchy.size());
        assertTrue(caHierarchy.toList().indexOf("rootCa1") < caHierarchy.toList().indexOf("center"));
        assertTrue(caHierarchy.toList().indexOf("rootCa2") < caHierarchy.toList().indexOf("center"));
        assertTrue(caHierarchy.toList().indexOf("center") < caHierarchy.toList().indexOf("bottom1"));
        assertTrue(caHierarchy.toList().indexOf("center") < caHierarchy.toList().indexOf("bottom2"));
    }

    @Test
    public void testInvertedStarCaHierarchy() {
        final BiPredicate<String, String> isSignedBy = (ca1, ca2) -> {
            if (StringUtils.equals(ca1, "rootCa") && StringUtils.equals(ca2, "rootCa")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa") && StringUtils.equals(ca2, "intermediate1")) {
                return true;
            }
            if (StringUtils.equals(ca1, "rootCa") && StringUtils.equals(ca2, "intermediate2")) {
                return true;
            }
            if (StringUtils.equals(ca1, "intermediate1") && StringUtils.equals(ca2, "issuingCa")) {
                return true;
            }
            if (StringUtils.equals(ca1, "intermediate2") && StringUtils.equals(ca2, "issuingCa")) {
                return true;
            }
            return false;
        };
        final CaHierarchy<String> caHierarchy = CaHierarchy
                .singleCaHierarchyFrom(new HashSet<String>(Arrays.asList("rootCa", "intermediate1", "intermediate2", "issuingCa")), isSignedBy);
        assertEquals(5, caHierarchy.getEdges().size());
        assertEquals(4, caHierarchy.size());
        assertTrue(caHierarchy.toList().indexOf("rootCa") < caHierarchy.toList().indexOf("intermediate1"));
        assertTrue(caHierarchy.toList().indexOf("rootCa") < caHierarchy.toList().indexOf("intermediate2"));
        assertTrue(caHierarchy.toList().indexOf("intermediate1") < caHierarchy.toList().indexOf("issuingCa"));
        assertTrue(caHierarchy.toList().indexOf("intermediate2") < caHierarchy.toList().indexOf("issuingCa"));
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
