/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * See <a href="https://tools.ietf.org/html/rfc4683">RFC 4683</a>
 */
public class RFC4683ToolsTest {

    @BeforeClass
    public static void beforeClass() throws Exception {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetAllowedHashAlgorithms() {
        assertEquals(RFC4683Tools.getAllowedHashAlgorithms(), new ArrayList<>(TSPAlgorithms.ALLOWED));
    }

    @Test
    public void testGetAllowedHashAlgorithmOidStrings() {
        final List<ASN1ObjectIdentifier> identifiers = RFC4683Tools.getAllowedHashAlgorithms();
        final List<String> oids = new ArrayList<>(identifiers.size());
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
        san = "SUBJECTIDENTIFICATIONMETHOD=2.16.840.1.101.3.4.2.1::MyStrongPassword::1.2.410.200004.10.1.1.10.1::SsiValue, DNSNAME=localhost";
        san = RFC4683Tools.generateSimForInternalSanFormat(san);
        String[] simtokens = StringUtils.split(san, "::");
        assertEquals("There should be 3 SIM tokens", 3, simtokens.length);

        // SIM is calculated (4 tokens).
        san = "uniformResourceId=http://www.a.se/,upn=foo@a.se,uniformResourceId=urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6,upn=foo@b.se,"
                + "rfc822name=tomas@a.se,dNSName=www.a.se,dNSName=www.b.se,iPAddress=10.1.1.1,registeredID=1.1.1.2,xmppAddr=tomas@xmpp.domain.com,"
                + "srvName=_Service.Name,"
                + "subjectIdentificationMethod=2.16.840.1.101.3.4.2.1::MyStrongPassword::1.2.410.200004.10.1.1.10.1::SIIValue";
        san = RFC4683Tools.generateSimForInternalSanFormat(san);
        System.out.println(san);
        final String simsan = CertTools.getPartFromDN(san, RFC4683Tools.SUBJECTIDENTIFICATIONMETHOD);
        simtokens = StringUtils.split(simsan, "::");
        assertEquals("There should be 3 SIM tokens", 3, simtokens.length);

        // Calculated SIM (3 tokens) -> nothing happens
        san = "SUBJECTIDENTIFICATIONMETHOD=2.16.840.1.101.3.4.2.1::CB3AE7FBFFFD9C85A3FB234E51FFFD2190B1F8F161C0A2873B998EFAC067B03A::6D9E6264DDBD0FC997B9B40524247C8BC319D02A583F4B499DD3ECAF06C786DF, DNSNAME=localhost";
        assertEquals(RFC4683Tools.generateSimForInternalSanFormat(san), san);
    }

    @Test
    public void testAndVerifySim() throws IllegalArgumentException, NoSuchProviderException, NoSuchAlgorithmException, IOException {
        // See RFC4683, section 6, "Example Usage of SIM". 
        // We want to test nr 1
        
        // SIM is calculated (4 tokens), sha-256, SIIType RFC4683 section 4.1
        final String sIIType = "1.2.410.200004.10.1.1.10.1";
        String san = "SUBJECTIDENTIFICATIONMETHOD=2.16.840.1.101.3.4.2.1::MyStrongPassword::" + sIIType + "::SIIValue, DNSNAME=localhost";
        String simsan = RFC4683Tools.generateSimForInternalSanFormat(san);
        assertTrue("SIM should have the dnsName still", simsan.endsWith("DNSNAME=localhost"));
        String sim = CertTools.getPartFromDN(simsan, "SUBJECTIDENTIFICATIONMETHOD");
        System.out.println(sim);
        // We have a SIM, verify the values, i.e. calculate so we can compare
        // We have something like this now:
        // 2.16.840.1.101.3.4.2.1::4F06B0AC827E4261EFD85A1E0508B33D39E8D65D313D46B1F34419DA653EACD6::5881D5D71ADD0D4B6C4B406A8F00259C67B0E5D2037588F776B9ED5B29C6CC2D
        // We are a relying party, that has been given the SsiType, SsiValue and MyStringPassword by the user,
        // and we want to verify that the CA have done validation of the SsiType, SsiValue, binding it to the subject. 
        // We do that by acquiring R from the certificate (4F06B0AC827E4261EFD85A1E0508B33D39E8D65D313D46B1F34419DA653EACD6), and calculating 
        // the encrypted PEPSI ourselves, then comparing it to what we got in the certificate (5881D5D71ADD0D4B6C4B406A8F00259C67B0E5D2037588F776B9ED5B29C6CC2D)

        String[] simtokens = StringUtils.split(sim, "::");
        assertNotNull("SIM must be tokenized by ::", simtokens);
        assertEquals("There should be 3 SIM tokens", 3, simtokens.length);
        String hashalg = simtokens[0];
        String r = simtokens[1];
        String pepsifromsim = simtokens[2];
        String pepsi = RFC4683Tools.createPepsi(hashalg, "MyStrongPassword", sIIType, "SIIValue", r);
        assertEquals("Calculated PEPSI and PEPSI from SIM must be equal", pepsifromsim, pepsi);

        // Wrong password and it should not compare correct
        String pepsiwrong = RFC4683Tools.createPepsi(hashalg, "MyBadPassword", sIIType, "SIIValue", r);
        assertNotEquals("Calculated PEPSI from wrong password and PEPSI from SIM must not be equal", pepsifromsim, pepsiwrong);
    }

    @Test
    public void testGenerateInternalSimStringIllegalParameters() {
        // 1. Use different illegal SIM parameters.
        String[] simParameters = new String[] { "2.16.840.1.101.3.4.2.1", "MyStrongPassword", "1.2.410.200004.10.1.1.10.1", "Sensitive identifier information" };
        // 2a. Use invalid hash algorithm OID (unknown | empty | null) -> IAE("Hash algorithm OID string must not be null or empty.")
        simParameters = new String[] { null, "MyStrongPassword", "SsiType", "Sensitive identifier information" };
        assertIAEForGenerateInternalSimString(simParameters, "Hash algorithm OID string must not be null or empty");
        simParameters = new String[] { "2.16.840.1.101a.A.B.C", "MyStrongPassword", "SsiType", "Sensitive identifier information" };
        assertIAEForGenerateInternalSimString(simParameters, "Hash algorithm with OID");
        // 2b. Use invalid password ( empty | null | ... ) -> FIPS 112 and FIPS 180-1 compliance is not tested -> IAE("The user chosen password must not be null or empty")
        simParameters = new String[] { "2.16.840.1.101.3.4.2.1", null, "1.2.410.200004.10.1.1.10.1", "Sensitive identifier information" };
        assertIAEForGenerateInternalSimString(simParameters, "The password must not be null, empty or only whitespace, and must be at least 8 characters.");
        // 2b. User chosen password must have at least 8 characters.
        simParameters = new String[] { "2.16.840.1.101.3.4.2.1", "weakPwd", "1.2.410.200004.10.1.1.10.1", "Sensitive identifier information" };
        assertIAEForGenerateInternalSimString(simParameters, "The password must not be null, empty or only whitespace, and must be at least 8 characters.");
        // 2c. Use invalid SSI type (empty | null) -> IAE expected
        simParameters = new String[] { "2.16.840.1.101.3.4.2.1", "MyStrongPassword", null, "Sensitive identifier information" };
        assertIAEForGenerateInternalSimString(simParameters, "The sensitve identification information type must not be null or empty");
        // 2d. Use invalid SSI type (not an OID) -> IAE expected
        simParameters = new String[] { "2.16.840.1.101.3.4.2.1", "MyStrongPassword", "SsiType", "Sensitive identifier information" };
        assertIAEForGenerateInternalSimString(simParameters, "string SsiType not an OID");
        // 2e. Use invalid SSI (empty | null) -> IAE expected
        simParameters = new String[] { "2.16.840.1.101.3.4.2.1", "MyStrongPassword", "1.2.410.200004.10.1.1.10.1", null };
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
        final String[] simParameters = new String[] { "2.16.840.1.101.3.4.2.1", "MyStrongPassword", "1.2.410.200004.10.1.1.10.1", "Sensitive identifier information" };
        final String internalSimString = RFC4683Tools.generateInternalSimString(simParameters[0], simParameters[1], simParameters[2],
                simParameters[3]);
        final String[] simTokens = internalSimString.split("(::)");

        final ASN1Primitive generalName = testCreateSimGeneralName(simParameters, simTokens);
        testGetSimStringSequence(internalSimString, generalName);
    }

    private ASN1Primitive testCreateSimGeneralName(final String[] simParameters, final String[] simTokens) throws IOException {
        // Create the value (OtherName altName extension)
        final ASN1Primitive generalName = RFC4683Tools.createSimGeneralName(simTokens[0], simTokens[1], simTokens[2]);
        // Parse the value and check that it's ok
        final GeneralName gn = GeneralName.getInstance(generalName);
        final OtherName on = OtherName.getInstance(gn.getName());
        final ASN1Sequence simSequence = ASN1Sequence.getInstance(on.getValue());
        final String algorithmIdentifier = (AlgorithmIdentifier.getInstance(simSequence.getObjectAt(0)).getAlgorithm().getId());
        final ASN1OctetString authorityRandom = ASN1OctetString.getInstance(simSequence.getObjectAt(1));
        final ASN1OctetString sim = ASN1OctetString.getInstance(simSequence.getObjectAt(2));
        assertEquals("The SIM algorithm identifier must match.", simParameters[0], algorithmIdentifier);
        assertEquals("The SIM authority random must match.", simTokens[1], new String(authorityRandom.getOctets()));
        assertEquals("The SIM algorithm identifier must match.", simTokens[2], new String(sim.getOctets()));
        return generalName;
    }

    private void testGetSimStringSequence(String simString, ASN1Primitive generalName) {
        final ASN1Sequence otherName = ASN1Sequence.getInstance(ASN1TaggedObject.getInstance(generalName.toASN1Primitive()).getObject());
        final String simStringBySequence = RFC4683Tools.getSimStringSequence(otherName);
        assertEquals("The SIM string, extracted by its ASN.1 structure must match the original.", simString, simStringBySequence);
    }
}
