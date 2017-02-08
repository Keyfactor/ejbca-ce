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
package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * (see {@link https://tools.ietf.org/html/rfc4683}).
 * 
 * @version $Id$
 */
public class RFC4683ToolsTest {

    @BeforeClass
    public static void beforeClass() throws Exception {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testGetAllowedHashAlgorithms() {
        assertEquals(RFC4683Tools.getAllowedHashAlgorithms(), new ArrayList<ASN1ObjectIdentifier>(TSPAlgorithms.ALLOWED));
    }

    @Test
    public void testGetAllowedHashAlgorithmOidStrings() {
        final List<ASN1ObjectIdentifier> identifiers = RFC4683Tools.getAllowedHashAlgorithms();
        final List<String> oids = new ArrayList<String>(identifiers.size());
        for (ASN1ObjectIdentifier identifier : identifiers) {
            oids.add(identifier.getId());
        }
        assertEquals(RFC4683Tools.getAllowedHashAlgorithmOidStrings(), oids);
    }

    @Test
    public void testGenerateSimForInternalSanFormat() throws NoSuchAlgorithmException, NoSuchProviderException {
        // 1. Test SANs.
        // 1a. Test empty SAN -> nothing happens.
        String san = "";
        assertEquals(RFC4683Tools.generateSimForInternalSanFormat(san), san);
        // 1b. Test SAN without 'subjectIdentificationMethod' -> nothing happens.
        san = "DNSNAME=localhost";
        assertEquals(RFC4683Tools.generateSimForInternalSanFormat(san), san);
        // 1c. Test SAN with 'subjectIdentificationMethod' but without SIM parameters -> nothing happens.        
        san = "SUBJECTIDENTIFICATIONMETHOD=, DNSNAME=localhost";
        assertEquals(RFC4683Tools.generateSimForInternalSanFormat(san), san);
        // 1d: Test SAN with 'subjectIdentificationMethod' but with wrong number of SIM parameters.
        san = "SUBJECTIDENTIFICATIONMETHOD=2.16.840.1.101.3.4.2.1::MyStrongPassword::SsiType::abc::abc, DNSNAME=localhost";
        try {
            RFC4683Tools.generateSimForInternalSanFormat(san);
            fail("An illegal number SIM parameters should throw an IllegalArgumentException: " + san);
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().startsWith("Wrong SIM input string with "));
        }
        // SIM is calculated (4 tokens).
        san = "SUBJECTIDENTIFICATIONMETHOD=2.16.840.1.101.3.4.2.1::MyStrongPassword::SsiType::SsiValue, DNSNAME=localhost";
        RFC4683Tools.generateSimForInternalSanFormat(san);
        // Calculated SIM (3 tokens) -> nothing happens
        san = "SUBJECTIDENTIFICATIONMETHOD=2.16.840.1.101.3.4.2.1::CB3AE7FBFFFD9C85A3FB234E51FFFD2190B1F8F161C0A2873B998EFAC067B03A::6D9E6264DDBD0FC997B9B40524247C8BC319D02A583F4B499DD3ECAF06C786DF, DNSNAME=localhost";
        assertEquals(RFC4683Tools.generateSimForInternalSanFormat(san), san);
    }

    @Test
    public void testGenerateInternalSimString() {
        // 1. Use different illegal SIM parameters.
        String[] simParameters = new String[] { "2.16.840.1.101.3.4.2.1", "MyStrongPassword", "SsiType", "Sensitive identifier information" };
        // 2a. Use invalid hash algorithm OID (unknown | empty | null) -> IAE("Hash algorithm OID string must not be null or empty.")
        simParameters = new String[] { null, "MyStrongPassword", "SsiType", "Sensitive identifier information" };
        assertIAEForGenerateInternalSimString(simParameters, "Hash algorithm OID string must not be null or empty");
        simParameters = new String[] { "2.16.840.1.101a.A.B.C", "MyStrongPassword", "SsiType", "Sensitive identifier information" };
        assertIAEForGenerateInternalSimString(simParameters, "Hash algorithm with OID");
        // 2b. Use invalid password ( empty | null | ... ) -> FIPS 112 and FIPS 180-1 compliance is not tested -> IAE("The user chosen password must not be null or empty")
        simParameters = new String[] { "2.16.840.1.101.3.4.2.1", null, "SsiType", "Sensitive identifier information" };
        assertIAEForGenerateInternalSimString(simParameters, "The user chosen password must not be null or empty");
        // 2b. User chosen password must have at least 8 characters.
        simParameters = new String[] { "2.16.840.1.101.3.4.2.1", "weakPwd", "SsiType", "Sensitive identifier information" };
        assertIAEForGenerateInternalSimString(simParameters, "The user chosen password must not be null or empty");
        // 2c. Use invalid SSI type (empty | null) -> IAE expected
        simParameters = new String[] { "2.16.840.1.101.3.4.2.1", "MyStrongPassword", null, "Sensitive identifier information" };
        assertIAEForGenerateInternalSimString(simParameters, "The sensitve identification information type must not be null or empty");
        // 2d. Use invalid SSI (empty | null) -> IAE expected
        simParameters = new String[] { "2.16.840.1.101.3.4.2.1", "MyStrongPassword", "SsiType", null };
        assertIAEForGenerateInternalSimString(simParameters, "The sensitve identification information must not be null or empty");

    }

    private final void assertIAEForGenerateInternalSimString(final String[] parameters, final String message) {
        try {
            RFC4683Tools.generateInternalSimString(parameters[0], parameters[1], parameters[2], parameters[3]);
            fail("An IllegalArgumentException should have been thrown: " + message);
        } catch (IllegalArgumentException | NoSuchAlgorithmException | NoSuchProviderException e) {
            assertTrue(e.getMessage().startsWith(message));
        }
    }

    @Test
    public void testAsn1ReadWrite() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        final String[] simParameters = new String[] { "2.16.840.1.101.3.4.2.1", "MyStrongPassword", "SsiType", "Sensitive identifier information" };
        final String internalSimString = RFC4683Tools.generateInternalSimString(simParameters[0], simParameters[1], simParameters[2],
                simParameters[3]);
        final String[] simTokens = internalSimString.split("(::)");

        final ASN1Primitive generalName = testCreateSimGeneralName(simParameters, simTokens);
        testGetSimStringSequence(internalSimString, generalName);
    }

    private ASN1Primitive testCreateSimGeneralName(final String[] simParameters, final String[] simTokens)
            throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        final ASN1Primitive generalName = RFC4683Tools.createSimGeneralName(simTokens[0], simTokens[1], simTokens[2]);
        final DERSequence simSequence = ((DERSequence) ((DERTaggedObject) ((DERSequence) ((DERTaggedObject) generalName.toASN1Primitive())
                .getObjectParser(0, true)).getObjectAt(1)).getObjectParser(0, true));
        final String algorithmIdentifier = ((AlgorithmIdentifier) simSequence.getObjectAt(0)).getAlgorithm().getId();
        final DEROctetString authorityRandom = (DEROctetString) simSequence.getObjectAt(1);
        final DEROctetString sim = (DEROctetString) simSequence.getObjectAt(2);
        assertEquals("The SIM algorithm identifier must match.", simParameters[0], algorithmIdentifier);
        assertEquals("The SIM authority random must match.", simTokens[1], new String(authorityRandom.getOctets()));
        assertEquals("The SIM algorithm identifier must match.", simTokens[2], new String(sim.getOctets()));
        return generalName;
    }

    private void testGetSimStringSequence(String simString, ASN1Primitive generalName) {
        final ASN1Sequence otherName = ASN1Sequence.getInstance(((DERTaggedObject) generalName.toASN1Primitive()).getObject());
        final String simStringBySequence = RFC4683Tools.getSimStringSequence(otherName);
        assertEquals("The SIM string, extracted by its ASN.1 structure must match the original.", simString, simStringBySequence);
    }
}
