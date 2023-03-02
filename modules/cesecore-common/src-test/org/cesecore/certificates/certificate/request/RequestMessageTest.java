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
package org.cesecore.certificates.certificate.request;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.KeyTools;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Testing various aspects of request messages.
 */
public class RequestMessageTest {

    private static KeyPair keyPair;

    @BeforeClass
    public static void beforeClass() throws InvalidAlgorithmParameterException {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        keyPair = KeyTools.genKeys("512", null, "RSA");
    }

    @Test
    public void test01Pkcs10RequestMessage() throws InvalidKeyException, NoSuchAlgorithmException, IOException, OperatorCreationException {

        PKCS10CertificationRequest basicpkcs10 = createP10("CN=Test,OU=foo");

        PKCS10RequestMessage msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        String username = msg.getUsername();
        assertEquals("Test", username);
        assertEquals("CN=Test,OU=foo", msg.getRequestDN());
        assertEquals("dNSName=foo1.bar.com", msg.getRequestAltNames());

        // Same message by try decoding byte array
        msg = new PKCS10RequestMessage(basicpkcs10.getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);
        assertEquals("CN=Test,OU=foo", msg.getRequestDN());
        assertEquals("foo123", msg.getPassword());

        // Check public key
        PublicKey pk = msg.getRequestPublicKey();
        KeyTools.testKey(keyPair.getPrivate(), pk, "BC");
        PKCS10RequestMessage msgempty = new PKCS10RequestMessage();
        assertNull(msgempty.getRequestPublicKey());

        // Verify POP
        assertTrue(msg.verify());
        assertTrue(msg.verify(pk));
        try {
            KeyPair otherkeys = KeyTools.genKeys("512", "RSA");
            assertFalse(msg.verify(otherkeys.getPublic()));
        } catch (InvalidAlgorithmParameterException e) {
            assertTrue("Should not throw", false);
        }

        // Try different DNs and DN oids
        X500Name dn = new X500Name("C=SE, O=Foo, CN=Test Testsson");
        basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

        msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);
        assertEquals("C=SE,O=Foo,CN=Test Testsson", msg.getRequestDN());
        assertEquals(null, msg.getRequestAltNames());
        assertEquals(null, msg.getPassword());

        dn = new X500Name("C=SE, O=Foo, CN=Test Testsson");
        basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", dn, 
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

        msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);
        assertEquals("C=SE,O=Foo,CN=Test Testsson", msg.getRequestDN());
        assertEquals(null, msg.getRequestAltNames());
        assertEquals(null, msg.getPassword());

        // oid for unstructuredName, will be handles specially by EJBCA
        dn = new X500Name("CN=Test + 1.2.840.113549.1.9.2=AttrValue1");
        basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

        msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);
        assertEquals("CN=Test,unstructuredName=AttrValue1", msg.getRequestDN());

        dn = new X500Name("CN=Test + 1.2.840.113549.1.9.2=AttrValue1 AttrValue2");
        basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

        msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);
        assertEquals("CN=Test,unstructuredName=AttrValue1 AttrValue2", msg.getRequestDN());

        dn = new X500Name("CN=Test+1.2.840.113549.1.9.2=AttrValue1");
        basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

        msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);
        assertEquals("CN=Test,unstructuredName=AttrValue1", msg.getRequestDN());

        dn = new X500Name("CN=Test+1.2.840.113549.1.9.2=AttrValue1 AttrValue2");
        basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

        msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);
        assertEquals("CN=Test,unstructuredName=AttrValue1 AttrValue2", msg.getRequestDN());

        // Completely unknown oid
        dn = new X500Name("CN=Test + 1.2.840.113549.1.9.3=AttrValue1");
        basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

        msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);
        assertEquals("CN=Test+1.2.840.113549.1.9.3=AttrValue1", msg.getRequestDN());

        dn = new X500Name("CN=Test + 1.2.840.113549.1.9.3=AttrValue1 AttrValue2");
        basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

        msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);
        assertEquals("CN=Test+1.2.840.113549.1.9.3=AttrValue1 AttrValue2", msg.getRequestDN());

        dn = new X500Name("CN=Test+1.2.840.113549.1.9.3=AttrValue1");
        basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

        msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);
        assertEquals("CN=Test+1.2.840.113549.1.9.3=AttrValue1", msg.getRequestDN());

        dn = new X500Name("CN=Test+1.2.840.113549.1.9.3=AttrValue1 AttrValue2");
        basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

        msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);
        assertEquals("CN=Test+1.2.840.113549.1.9.3=AttrValue1 AttrValue2", msg.getRequestDN());

        dn = new X500Name("1.2.840.113549.1.9.3=AttrValue1 AttrValue2+CN=Test");
        basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

        msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);

        dn = new X500Name("1.2.840.113549.1.9.3=AttrValue1 AttrValue2+CN=Test+O=abc");
        basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

        msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);

        dn = new X500Name("1.2.840.113549.1.9.3=AttrValue1\\+\\= AttrValue2+CN=Test+O=abc");	// very strange, but should still be valid 
        basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

        msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
        username = msg.getUsername();
        assertEquals("Test", username);
    }

    /** a P10 with a PKCS#9 challengePassword encoded as UTF8String */
    private static byte[] p10utf8StringPwd = Base64.decode(("MIIBITCBzAIBADBHMQswCQYDVQQGEwJTRTETMBEGA1UECAwKU29tZS1TdGF0ZTER"+
            "MA8GA1UECgwIUHJpbWVLZXkxEDAOBgNVBAMMB3AxMHRlc3QwXDANBgkqhkiG9w0B"+
            "AQEFAANLADBIAkEArE7GcTm9U3rEqTfldN+Ja3FnMhZXfq3Uq4AWi2VPVqEDmJzX"+
            "TINOlnDeK3y4jJ1kNqrSITfznobbDHR1pNSWYwIDAQABoCAwHgYJKoZIhvcNAQkH"+
            "MREMD2ZTUkVwOHBueHR4M0N1VjANBgkqhkiG9w0BAQsFAANBAGO8WZj42s3lo463"+
            "SdaP7kqE15BdkbReCIV+HA8dw9dphulLyFTTAxGZs8c28O2f81iA9jtW8yLUWnSg"+
            "UaIHwek=").getBytes());

    /** a P10 with a PKCS#9 challengePassword encoded as IA5String */
    private static byte[] p10ia5StringPwd = Base64.decode(("MIICyzCCAbMCAQAwVzELMAkGA1UEBhMCTkwxDTALBgNVBAoTBEJDSUUxIzAhBgNV"+
            "BAsUGk1RX1F1ZXVlX01hbmFnZXItb250d2lra2VsMRQwEgYDVQQDEwtRT0xCTVdV"+
            "MzBPMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANqGLzOMWBAFjbZ0"+
            "EkQ2tgTOaYdyx+T7Jt+6fS5B0FPjzjbzcF922RnJmR/KOqctnrMXdcSDrscO7NQe"+
            "A4BIi9Ap1W8/UYFACoHdERgge6i44nHobfgNo1jtoweSUYjMVtWMX+U6GCsIjIAe"+
            "N+TKtKxrnIbvV7hjw8RypSBuU82tTejNFfOgUtvLGJbFOrVtT2E1lej+soAlicyT"+
            "Y/S87TuF3GoRNmvxpxmLMjNstspS+6Xy2CMfp4qV/m5mQMzLWIpAeL22HBxLXz6/"+
            "I0Nn5HpPqSeam8W+NTsc1FBIebXrsLaQxRWocIDQDiyLScOPtzJbe3TvNVldXl08"+
            "C+/rF3sCAwEAAaAvMC0GCSqGSIb3DQEJBzEgFh5XZ2lfTC1PLGdUa2ZGZ0UudUtC"+
            "OVQ/WElaOXRXN0UwDQYJKoZIhvcNAQEFBQADggEBALtc/mEKlwIY6d9dRFFS5U8q"+
            "BBmHS1t1QYPxCNyXHtJCU72k6BfzECMGnHT5HtcxLm4AmpMFVENNSBLK8sSwPpFe"+
            "ekZjOUZ95rxd7INhwQaBpcRT9Uj4V4/jWVCwToaB/AoZw5ttLTi9rf5tg8hWA9Lu"+
            "dtLL9srbfed/g2Vg9hz+F/QMsDDNah4hRjCCBU33szbP0nHIPbKnHWjdhoWcCi0h"+
            "Bv0HszDnF+H1ihaHJwLNdFhRymEKzXSWs+wbSHUQz9+O2OSiRKUJLbVgQ7diL5JZ"+
            "hS/tGtoRHV11z1MkHasunu0Y4bICWILislBKY224Tiq0LTWjujnHr6/6ewoPU7M=").getBytes());

    /** a P10 with a PKCS#9 challengePassword encoded as PrintableString */
    private static byte[] p10printableStringPwd = Base64.decode(("MIICyzCCAbMCAQAwVzELMAkGA1UEBhMCTkwxDTALBgNVBAoTBEJDSUUxIzAhBgNV"+
            "BAsUGk1RX1F1ZXVlX01hbmFnZXItb250d2lra2VsMRQwEgYDVQQDEwtRT0xCTVdV"+
            "MzBPMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN07joDr5Qe+DEIZ"+
            "X3A441t/rRlFM99MN0pMzelnilAseX43ClAE8y/JjjFOPOzlNh0iYAK6fvQCgODx"+
            "0raXAmjVm+8+ug8P/2awazvufHBI0YGQujlOWtLZH3PV2qPs14DTVvQ+FhqpAPHz"+
            "zG/ut42WzpI9aRb5YK2b8wytLjsoVk9h/S8P1fyXafluZhF+nuyP6K9sDtJZbU0l"+
            "DgZzfJJ5792uOvDzryRZuK1LBvGBblH2mZHsFtEXmmDsgeGcetpe2XTqQc8E6/7p"+
            "0OEbhYslSW7k2AO0/6V+8OTn1dVF763w+58uiaOynDWpAhdd1C4uarOuyq4fiRZ8"+
            "5Key60kCAwEAAaAvMC0GCSqGSIb3DQEJBzEgEx5mU1JFcDhwbnh0eDNDdVZMQmp5"+
            "ZnVYSkFiSW1CdVAwDQYJKoZIhvcNAQEFBQADggEBABW69xlR2ACV2LJmJIg2P/r0"+
            "KJ4+8eK0z+d8a3IUc/9HXDfmTokaZekC3ux+/M2eBHz11UrjVJ3Lv39wMaEVDWf2"+
            "wtRlZ4QUVLdZPQLxVGuLgVScEfjlPe/nCIz5XMCByBaSxsqkdFHuFrlm1lfLxB3Y"+
            "QG+w3tzSxNKfVLpwWjel6i7VjryfgzRUV4p3Too05rU1761E8NWE977ruz7z9vJM"+
            "IE+kadoVCZKqUjpQWYfThNF8w+Blh//eq2Ai3VcQseHV3epxU7iBzmTfGXs5Kjjz"+
            "4Bdl+Nj8V5PRlEf8hjm7VldLczABKfnJM6aVMQ/L8YueRCnNzMNdcgBbfrfGXCU=").getBytes());

    @Test
    public void testOpenSSLChallengepassword() throws IOException {
        PKCS10RequestMessage msg1 = new PKCS10RequestMessage(p10utf8StringPwd);
        assertEquals("Username from P10 message is not what we expect", "p10test", msg1.getUsername());
        assertEquals("Challenge password (UTF8 encoded) from P10 message is not what we expect", "fSREp8pnxtx3CuV", msg1.getPassword());

        PKCS10RequestMessage msg2 = new PKCS10RequestMessage(p10printableStringPwd);
        assertEquals("Username from P10 message is not what we expect", "QOLBMWU30O1", msg2.getUsername());
        assertEquals("Challenge password (PrintableString encoded) from P10 message is not what we expect", "fSREp8pnxtx3CuVLBjyfuXJAbImBuP", msg2.getPassword());

        PKCS10RequestMessage msg3 = new PKCS10RequestMessage(p10ia5StringPwd);
        assertEquals("Username from P10 message is not what we expect", "QOLBMWU30O3", msg3.getUsername());
        assertEquals("Challenge password (IA5String encoded which is invalid according to the standard but we handle it anyway) from P10 message is not what we expect", 
                "Wgi_L-O,gTkfFgE.uKB9T?XIZ9tW7E", msg3.getPassword());

    }
    private PKCS10CertificationRequest createP10(final String subjectDN) throws IOException, OperatorCreationException {
        // Create a P10 with extensions, in this case altNames with a DNS name
        ASN1EncodableVector altnameattr = new ASN1EncodableVector();
        altnameattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        // AltNames
        // String[] namearray = altnames.split(",");
        GeneralNames san = CertTools.getGeneralNamesFromAltName("dNSName=foo1.bar.com");
        ExtensionsGenerator extgen = new ExtensionsGenerator();
        extgen.addExtension(Extension.subjectAlternativeName, false, san );
        Extensions exts = extgen.generate();
        altnameattr.add(new DERSet(exts));

        // Add a challenge password as well
        ASN1EncodableVector pwdattr = new ASN1EncodableVector();
        pwdattr.add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword); 
        ASN1EncodableVector pwdvalues = new ASN1EncodableVector();
        pwdvalues.add(new DERUTF8String("foo123"));
        pwdattr.add(new DERSet(pwdvalues));

        // Complete the Attribute section of the request, the set (Attributes)
        // contains one sequence (Attribute)
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERSequence(altnameattr));
        v.add(new DERSequence(pwdattr));
        DERSet attributes = new DERSet(v);

        // Create the PKCS10
        X500Name dn = new X500Name(subjectDN);
        PKCS10CertificationRequest basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
                keyPair.getPublic(), attributes, keyPair.getPrivate(), null);
        return basicpkcs10;
    }

    @Test
    public void testSNRepresentation () {
        SimpleRequestMessage req = new SimpleRequestMessage(keyPair.getPublic(), "dnorder", "foo123");
        req.setRequestDN("C=SE,O=Foo Company,SN=12345,SURNAME=surname,CN=DnOrderTest"); // This should not matter now
        X500Name reqname = req.getRequestX500Name();
        assertEquals("C=SE,O=Foo Company,SN=12345,SURNAME=surname,CN=DnOrderTest", reqname.toString());
    }

}
