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
package org.cesecore.certificates.certificate.certextensions.standard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.certificate.CertificateImplementationRegistry;
import com.keyfactor.util.certificate.x509.X509CertificateUtility;

/**
 * Unit tests for the {@link NameConstraint} class
 */
public class NameConstraintTest {

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        CertificateImplementationRegistry.INSTANCE.addCertificateImplementation(new X509CertificateUtility());
    }
    
    /**
     * From RFC 5280 4.2.1.10: 
     * 
     * For URIs, the constraint applies to the host part of the name.  The constraint MUST be specified as a fully qualified domain name and MAY
     * specify a host or a domain.  Examples would be "host.example.com" and  ".example.com".  When the constraint begins with a period, it MAY be
     * expanded with one or more labels.  That is, the constraint ".example.com" is satisfied by both host.example.com and my.host.example.com.  However,
     * the constraint ".example.com" is not satisfied by "example.com".  When the constraint does not begin with  a period, it specifies a host.  
     * If a constraint is applied to the uniformResourceIdentifier name form and a subsequent certificate includes a subjectAltName extension with a 
     * uniformResourceIdentifier that does not include an authority component with a host name specified as a fully qualified domain name (e.g., if 
     * the URI either does not include an authority component or includes an authority component in which the host name is specified as an IP address), 
     * then the application MUST reject the certificate.
     */
    @Test
    public void testUriParsing() throws CertificateExtensionException {
        //Prefix defined in RFC 5280 as above
        final String uriPrefix = "uniformResourceIdentifier:";
        assertTrue("host.example.com did not parse as a correct URI name constraint",
                NameConstraint.parseNameConstraintEntry("uri:host.example.com").startsWith(uriPrefix));
        assertTrue(".example.com did not parse as a correct URI name constraint",
                NameConstraint.parseNameConstraintEntry("uri:.example.com").startsWith(uriPrefix));
        try {
            NameConstraint.parseNameConstraintEntry("uri:http://example.com");
            fail("URI name constraint should not contain a protocol.");
        } catch(CertificateExtensionException e) {
            //Expected
        }
        


    }
    
    @Test
    public void testNameConstraintAreCorrectInCert() throws Exception {

        final String excluded = ".\n" + "example.com";

        final List<Extension> extensions = new ArrayList<>();

        List<String> ncList = NameConstraint.parseNameConstraintsList(excluded);

        GeneralSubtree[] excludedSubtrees = NameConstraint.toGeneralSubtrees(ncList);
        byte[] extdata = new NameConstraints(null, excludedSubtrees).toASN1Primitive().getEncoded();
        extensions.add(new Extension(Extension.nameConstraints, false, extdata));

        final KeyPair testkeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate cacert = CertTools.genSelfCertForPurpose("C=SE,CN=Test Name Constraints CA", 365, null, testkeys.getPrivate(),
                testkeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null,
                "BC", true, extensions);

        final byte[] ncbytes = cacert.getExtensionValue(Extension.nameConstraints.getId());
        final ASN1OctetString ncstr = (ncbytes != null ? ASN1OctetString.getInstance(ncbytes) : null);
        final ASN1Sequence ncseq = (ncbytes != null ? ASN1Sequence.getInstance(ncstr.getOctets()) : null);
        final NameConstraints nc = (ncseq != null ? NameConstraints.getInstance(ncseq) : null);

        GeneralSubtree[] excludedST = nc.getExcludedSubtrees();

        assertNotNull("Excluded sub tree was null!", excludedST);
        assertEquals("Array size did not match", 2, excludedST.length);
        assertEquals("Domain not match!", "2: ", excludedST[0].getBase().toString());
        assertEquals("Domain not match!", "2: example.com", excludedST[1].getBase().toString());
    }


}
