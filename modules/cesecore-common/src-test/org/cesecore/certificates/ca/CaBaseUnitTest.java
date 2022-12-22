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

import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.PrintableStringNameStyle;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 */
public class CaBaseUnitTest {
    
    private static Logger log = Logger.getLogger(CaBaseUnitTest.class);

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void testNameConstraintsNonDNS() throws Exception {
        final String excluded = "test@host.com";
                                
        final List<Extension> extensions = new ArrayList<>();
        
        List<String> ncList = NameConstraint.parseNameConstraintsList(excluded);
        
        GeneralSubtree[] excludedSubtrees = NameConstraint.toGeneralSubtrees(ncList);
        byte[] extdata = new NameConstraints(null, excludedSubtrees).toASN1Primitive().getEncoded();
        extensions.add(new Extension(Extension.nameConstraints, false, extdata));
        
        final KeyPair testkeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate cacert = CertTools.genSelfCertForPurpose("C=SE,CN=Test Name Constraints CA", 365, null,
                testkeys.getPrivate(), testkeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true,
                X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, "BC", true, extensions);
        
        // Allowed subject DNs
        final X500Name validDN = new X500Name("C=SE,O=PrimeKey,CN=example.com");
        
        // Disallowed SAN
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, "test.email.com")));
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, "example.com")));
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, "com")));
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, ".com")));
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, ".example.com")));
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, ".")));
    }
    
    /**
     * Tests the following methods:
     * <ul>
     * <li>{@link CertTools#checkNameConstraints}</li>
     * <li>{@link NameConstraint#parseNameConstraintsList}</li>
     * <li>{@link NameConstraint#toGeneralSubtrees}</li>
     * </ul>
     */
    @Test
    public void testNameConstraints() throws Exception {
        final String permitted = "C=SE,O=PrimeKey,CN=example.com\n" +
                                 "example.com\n" +
                                 "@mail.example\n" +
                                 "user@host.com\n" +
                                 "uri:example.com\n" +
                                 "uri:.example.com\n" +
                                 "10.0.0.0/8\n" +
                                 "www.example.com\n" +
                                 "   C=SE,  CN=spacing    \n";
        final String excluded = "forbidden.example.com\n" +
                                "postmaster@mail.example\n" +
                                "uri:def123.test.com\n" +
                                "10.1.0.0/16\n" +
                                "::/0"; // IPv6
        
        final List<Extension> extensions = new ArrayList<>();
        GeneralSubtree[] permittedSubtrees = NameConstraint.toGeneralSubtrees(NameConstraint.parseNameConstraintsList(permitted));
        GeneralSubtree[] excludedSubtrees = NameConstraint.toGeneralSubtrees(NameConstraint.parseNameConstraintsList(excluded));
        byte[] extdata = new NameConstraints(permittedSubtrees, excludedSubtrees).toASN1Primitive().getEncoded();
        extensions.add(new Extension(Extension.nameConstraints, false, extdata));
               
        final KeyPair testkeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate cacert = CertTools.genSelfCertForPurpose("C=SE,CN=Test Name Constraints CA", 365, null,
                testkeys.getPrivate(), testkeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true,
                X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, "BC", true, extensions);
        log.info(CertTools.getPemFromCertificate(cacert));

        // Allowed subject DNs
        final X500Name validDN = new X500Name("C=SE,O=PrimeKey,CN=example.com"); // re-used below
        CABase.checkNameConstraints(cacert, validDN, null);
        CABase.checkNameConstraints(cacert, new X500Name("C=SE,CN=spacing"), null);
        // When importing certificates issued by Name Constrained CAs we may run into issues with DN encoding and DN order
        // In EndEntityManagementSessionBean.addUser we use something like:
        // X500Name subjectDNName1 = CertTools.stringToBcX500Name(CertTools.getSubjectDN(subjectCert), nameStyle, useLdapDnOrder);
        // Where nameStyle and dnOrder can have different values
        X500Name validDN2 = CertTools.stringToBcX500Name("C=SE,O=PrimeKey,CN=example.com", CeSecoreNameStyle.INSTANCE, false);
        CABase.checkNameConstraints(cacert, validDN2, null);
        X500Name invalidDN1 = CertTools.stringToBcX500Name("C=SE,O=PrimeKey,CN=example.com", CeSecoreNameStyle.INSTANCE, true);
        checkNCException(cacert, invalidDN1, null, "ldapDnOrder true was accepted");
        X500Name validDN3 = CertTools.stringToBcX500Name("C=SE,O=PrimeKey,CN=example.com", PrintableStringNameStyle.INSTANCE, false);
        // This should be accepted according to RFC5280, section 4.2.1.10
        // "CAs issuing certificates with a restriction of the form directoryName
        // SHOULD NOT rely on implementation of the full ISO DN name comparison
        // algorithm. This implies name restrictions MUST be stated identically to
        // the encoding used in the subject field or subjectAltName extension."
        // ISO DN matching makes string conversion of various formats, UTF-8, PrintableString etc and compares the result.
        // But, there might be clients who do a binary check, which will likely fail if the encodings differ, so as a CA it's important to encode the NC right
        CABase.checkNameConstraints(cacert, validDN3, null);
        // Before up to BC 1.61, encoding was checked and this was rejected. See ECA-9035
        // checkNCException(cacert, invalidDN2, null, "PrintableStringNameStyle was accepted");


        // Allowed subject alternative names
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, "example.com")));
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, "x.sub.example.com")));
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "someuser@mail.example")));
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "user@host.com")));
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("10.0.0.1").getAddress()))));
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("10.255.255.255").getAddress()))));
        
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, "example.com/")));
        CABase.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, "host.example.com")));


        // Disallowed subject DN
        checkNCException(cacert, new X500Name("C=DK,CN=example.com"), null, "Disallowed DN (wrong field value) was accepted");
        checkNCException(cacert, new X500Name("C=SE,O=Company,CN=example.com"), null, "Disallowed DN (extra field) was accepted");
        
        // Disallowed SAN
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "bad.com"), "Disallowed SAN (wrong DNS name) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "forbidden.example.com"), "Disallowed SAN (excluded DNS subdomain) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.rfc822Name, "wronguser@host.com"), "Disallowed SAN (wrong e-mail) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("10.1.0.1").getAddress())), "Disallowed SAN (excluded IPv4 address) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("192.0.2.1").getAddress())), "Disallowed SAN (wrong IPv4 address) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("2001:DB8::").getAddress())), "Disallowed SAN (IPv6 address) was accepted");
        
        checkNCException(cacert, validDN, new GeneralName(GeneralName.uniformResourceIdentifier, "ldap://def123.test.com:8080"), "Disallowed SAN (wrong URI) was accepted");

    }
    
    @Test
    public void testNameConstraintsEmptyDNS() throws Exception {
        final String excluded = ".";
                                
        final List<Extension> extensions = new ArrayList<>();
        
        List<String> ncList = NameConstraint.parseNameConstraintsList(excluded);
        
        GeneralSubtree[] excludedSubtrees = NameConstraint.toGeneralSubtrees(ncList);
        byte[] extdata = new NameConstraints(null, excludedSubtrees).toASN1Primitive().getEncoded();
        extensions.add(new Extension(Extension.nameConstraints, false, extdata));
        
        final KeyPair testkeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate cacert = CertTools.genSelfCertForPurpose("C=SE,CN=Test Name Constraints CA", 365, null,
                testkeys.getPrivate(), testkeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true,
                X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, "BC", true, extensions);
        
        // Allowed subject DNs
        final X500Name validDN = new X500Name("C=SE,O=PrimeKey,CN=example.com");
        
        // Disallowed SAN
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "test.email.com"), "Disallowed SAN (excluded test.email.com DNS name) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "example.com"), "Disallowed SAN (excluded example.com DNS name) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "com"), "Disallowed SAN (excluded com DNS name) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, ".com"), "Disallowed SAN (excluded .com DNS name) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, ".example.com"), "Disallowed SAN (excluded .example.com DNS name) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "."), "Disallowed SAN (excluded . DNS name) was accepted");

    }
    
    
    /** Check Name Constraints that are expected to fail NC validation, and fail the JUnit test of the NC validation 
     * does not fail with an IllegalNameException
     */
    private void checkNCException(X509Certificate cacert, X500Name subjectDNName, GeneralName subjectAltName, String message) {
        try {
            CABase.checkNameConstraints(cacert, subjectDNName, subjectAltName != null ? new GeneralNames(subjectAltName) : null);
            fail(message);
        } catch (IllegalNameException e) { 
            /* NOPMD expected */ 
        }
    }
}
