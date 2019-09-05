/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate.certextensions;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CAUnitTestBase;
import org.cesecore.certificates.certificate.certextensions.standard.CabForumOrganizationIdentifier;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.Base64;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests of {@link CabForumOrganizationIdentifier}
 * @version $Id$
 */
public class CabForumOrganizationIdentifierUnitTest extends X509CAUnitTestBase {

    private static final String USER_PKCS10 =
            "MIIBOjCB4AIBADAYMRYwFAYDVQQDDA1FQ09jc3BLZXlCaW5kMFkwEwYHKoZIzj0C" + 
            "AQYIKoZIzj0DAQcDQgAERUf9LDFhl9Z5cz89nuax3gg16+ADmh0Te4SdR4R3GUGg" + 
            "ChKhmUFR4pyUi7GOs3yFgTKRER2DBg0kuj8u679HDqBmMGQGCSqGSIb3DQEJDjFX" + 
            "MFUwHQYDVR0OBBYEFD2xZtUDZ3EBvIEFJVM7LNrLLV7zMA4GA1UdDwEB/wQEAwIH" + 
            "gDATBgNVHSUEDDAKBggrBgEFBQcDCTAPBgkrBgEFBQcwAQUEAgUAMAoGCCqGSM49" + 
            "BAMCA0kAMEYCIQCXwHtRMOrzdacju7vJutz6EQmmGY0Q7Mw7RJSpvoJL9AIhAObv" + 
            "Hm1K/5lOqiQtSS6ud9ngv94Po80O2UtafdbsSSX4";
    private static CryptoToken cryptoToken;
    private static CA ca;

    @BeforeClass
    public static void beforeClass() throws Exception {
        cryptoToken = getNewCryptoToken();
        ca = createTestCA(cryptoToken, CADN);
    }

    /** Generates certificate with a a CA/B Forum Organization Identifier extension, without a "state or province" field. */
    @Test
    public void cabfOrganizationIdentifierWithoutState() throws Exception {
        final X509Certificate cert = makeCabfOrgIdentCertificate("VATDE-123456");
        final ASN1Sequence ext = extractExtension(cert);
        final Iterator<ASN1Encodable> seqIter = ext.iterator();
        assertAsn1String("Registration Scheme Identifier", DERPrintableString.class, "VAT", seqIter.next());
        assertAsn1String("Registration Country", DERPrintableString.class, "DE", seqIter.next());
        assertAsn1String("Registration Reference", DERUTF8String.class, "123456", seqIter.next());
        assertFalse("Extranous items in sequence", seqIter.hasNext());
    }

    /** Generates certificate with a a CA/B Forum Organization Identifier extension, with a "state or province" field. */
    @Test
    public void cabfOrganizationIdentifierWithState() throws Exception {
        final X509Certificate cert = makeCabfOrgIdentCertificate("NTRUS+CA-123456");
        final ASN1Sequence ext = extractExtension(cert);
        final Iterator<ASN1Encodable> seqIter = ext.iterator();
        assertAsn1String("Registration Scheme Identifier", DERPrintableString.class, "NTR", seqIter.next());
        assertAsn1String("Registration Country", DERPrintableString.class, "US", seqIter.next());
        final DERTaggedObject tagged = (DERTaggedObject) seqIter.next();
        assertEquals("Wrong tag number for 'Registration State or Province'", 0, tagged.getTagNo());
        assertAsn1String("Registration State or Province", DERPrintableString.class, "CA", DERPrintableString.getInstance(tagged, false));
        assertAsn1String("Registration Reference", DERUTF8String.class, "123456", seqIter.next());
        assertFalse("Extranous items in sequence", seqIter.hasNext());
    }

    private X509Certificate makeCabfOrgIdentCertificate(final String cabfOrgIdent) throws Exception {
        final CertificateProfile prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER);
        prof.setUseCabfOrganizationIdentifier(true);
        final ExtendedInformation extendedInfo = new ExtendedInformation();
        extendedInfo.setCabfOrganizationIdentifier(cabfOrgIdent);
        final EndEntityInformation endEntity = new EndEntityInformation("orgidentuser", "CN=CABFOrgIdent", ca.getCAId(), "DNSNAME=abc123.test", null, EndEntityTypes.ENDUSER.toEndEntityType(),
                123, 456, EndEntityConstants.TOKEN_USERGEN, extendedInfo);
        final PKCS10RequestMessage request = new PKCS10RequestMessage(Base64.decode(USER_PKCS10.getBytes(StandardCharsets.US_ASCII)));
        return (X509Certificate) ca.generateCertificate(cryptoToken, endEntity, request, request.getRequestPublicKey(), /*keyusage*/0, null, null, prof, /*extensions*/null, null, cceConfig);
    }

    private ASN1Sequence extractExtension(final X509Certificate cert) {
        final byte[] extBytes = cert.getExtensionValue(CabForumOrganizationIdentifier.OID);
        final byte[] subBytes = DEROctetString.getInstance(extBytes).getOctets();
        return DERSequence.getInstance(subBytes);
    }

    private void assertAsn1String(final String name, final Class<? extends ASN1String> expectedType, final String expectedString, final ASN1Encodable value) {
        assertNotNull("'" + name + "' should not be present");
        assertTrue("'" + name + "' should be of " + expectedType + " type, was " + value.getClass(), expectedType.isInstance(value));
        final ASN1String asn1String = (ASN1String) value;
        assertEquals("'" + name + "' had the wrong string value", expectedString, asn1String.getString());
    }

}
