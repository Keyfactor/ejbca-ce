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

package org.cesecore.certificates.certificateprofile;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.primitives.Booleans;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Test;

/**
 * Tests the CertificateProfile class.
 * 
 * @version $Id$
 */
public class CertificateProfileTest {

    @Test
    public void test01DefaultValues() {
    	final CertificateProfile prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    	
    	// Check that default values are as they should be
    	assertEquals(CertificateProfile.VERSION_X509V3, prof.getCertificateVersion());
    	assertEquals(CertificateConstants.CERTTYPE_ENDENTITY, prof.getType());
    	// ECA-5141: old setValidity methods are removed, getValidity only reads the old validity value from 
    	// DB to display it on GUI. After post-upgrade the method is supposed not to be called anymore!
//    	assertEquals(730, prof.getValidity());
    	assertEquals("2y", prof.getEncodedValidity());
    	assertNull(prof.getSignatureAlgorithm());
        assertEquals(false, prof.getAllowValidityOverride());
        assertEquals(false, prof.getAllowExtensionOverride());
        assertEquals(false, prof.getAllowDNOverride());
        assertEquals(true, prof.getUseBasicConstraints());
        assertEquals(true, prof.getBasicConstraintsCritical());
        assertEquals(true, prof.getUseSubjectKeyIdentifier());
        assertEquals(false, prof.getSubjectKeyIdentifierCritical());
        assertEquals(true, prof.getUseAuthorityKeyIdentifier());
        assertEquals(false, prof.getAuthorityKeyIdentifierCritical());
        assertEquals(true, prof.getUseSubjectAlternativeName());
        assertEquals(true, prof.getUseIssuerAlternativeName());
        assertEquals(false, prof.getSubjectAlternativeNameCritical());
        assertEquals(false, prof.getUseCRLDistributionPoint());
        assertEquals(false, prof.getUseDefaultCRLDistributionPoint());
        assertEquals(false, prof.getCRLDistributionPointCritical());
        assertEquals("", prof.getCRLDistributionPointURI());
        assertEquals(false, prof.getUseFreshestCRL());
        assertEquals(false, prof.getUseCADefinedFreshestCRL());
        assertEquals("", prof.getFreshestCRLURI());
        assertEquals(false, prof.getUseCertificatePolicies());
        assertEquals(false, prof.getCertificatePoliciesCritical());
        final List<CertificatePolicy> policies = prof.getCertificatePolicies();
        assertEquals(0, policies.size());
        assertEquals(CertificateConstants.CERTTYPE_ENDENTITY, prof.getType());
        final int[] availablebitlen = prof.getAvailableBitLengths();
        assertEquals(0, availablebitlen[0]);
        assertEquals(8192, availablebitlen[availablebitlen.length-1]);
        assertEquals(0, prof.getMinimumAvailableBitLength());
        assertEquals(8192, prof.getMaximumAvailableBitLength());
        assertTrue("Default profile should have all enabled key algorithms available.", prof.getAvailableKeyAlgorithmsAsList().containsAll(AlgorithmTools.getAvailableKeyAlgorithms()));
        assertEquals(true, prof.getUseKeyUsage());
        final boolean[] ku = prof.getKeyUsage();
        assertEquals(9, ku.length);
        for (int i = 0; i < ku.length; i++) {
        	assertEquals(false, ku[i]);
        }
        assertEquals(false, prof.getAllowKeyUsageOverride());
        assertEquals(true, prof.getKeyUsageCritical());
        assertEquals(false, prof.getUseExtendedKeyUsage());
        final List<String> eku = prof.getExtendedKeyUsageOids();
        assertEquals(0, eku.size());
        assertEquals(false, prof.getExtendedKeyUsageCritical());
        final Collection<Integer> cas = prof.getAvailableCAs();
        assertEquals(1, cas.size());
        assertEquals(CertificateProfile.ANYCA, cas.iterator().next().intValue());
        final Collection<Integer> pub = prof.getPublisherList();
        assertEquals(0, pub.size());
        assertEquals(false, prof.getUseOcspNoCheck());
        assertEquals(true, prof.getUseLdapDnOrder());
        assertEquals(false, prof.getUseMicrosoftTemplate());
        assertEquals("", prof.getMicrosoftTemplate());
        assertEquals(false, prof.getUseCardNumber());
        assertEquals(false, prof.getUseCNPostfix());
        assertEquals("", prof.getCNPostfix());
        assertEquals(false, prof.getUseSubjectDNSubSet());
        final Collection<Integer> dnsub = prof.getSubjectDNSubSet();
        assertEquals(0, dnsub.size());
        assertEquals(false, prof.getUseSubjectAltNameSubSet());
        final Collection<Integer> asub = prof.getSubjectAltNameSubSet();
        assertEquals(0, asub.size());
        assertEquals(false, prof.getUsePathLengthConstraint());
        assertEquals(0, prof.getPathLengthConstraint());
        
        assertEquals(false, prof.getUseQCStatement());
        assertEquals(false, prof.getUsePkixQCSyntaxV2());
        assertEquals(false, prof.getQCStatementCritical());
        assertEquals("", prof.getQCStatementRAName());
        assertEquals("", prof.getQCSemanticsIds());
        assertEquals(false, prof.getUseQCEtsiQCCompliance());
        assertEquals(false, prof.getUseQCEtsiSignatureDevice());
        assertEquals(false, prof.getUseQCEtsiValueLimit());
        assertEquals(0, prof.getQCEtsiValueLimit());
        assertEquals(0, prof.getQCEtsiValueLimitExp());
        assertEquals("", prof.getQCEtsiValueLimitCurrency());
        assertEquals(false, prof.getUseQCEtsiRetentionPeriod());
        assertEquals(0, prof.getQCEtsiRetentionPeriod());
        assertEquals(false, prof.getUseQCCountries());
        assertEquals("", prof.getQCCountriesString());
        assertEquals(false, prof.getUseQCCustomString());
        assertEquals("", prof.getQCCustomStringOid());
        assertEquals("", prof.getQCCustomStringText());
        
        assertEquals(false, prof.getUseSubjectDirAttributes());
        assertEquals(false, prof.getUseAuthorityInformationAccess());
        final Collection<String> cai = prof.getCaIssuers();
        assertEquals(0, cai.size());
        assertEquals(false, prof.getUseDefaultOCSPServiceLocator());
        assertEquals("", prof.getOCSPServiceLocatorURI());
        assertEquals(CertificateProfile.CVC_ACCESS_DG3DG4, prof.getCVCAccessRights());
        final Collection<Integer> ext = prof.getUsedCertificateExtensions();
        assertEquals(0, ext.size());
        final Map<ApprovalRequestType, Integer> app = prof.getApprovals();
        assertEquals(0, app.size());
        assertTrue(prof.isApplicableToAnyCA());
    }

    @Test
    public void test02ChangeValues() {
    	final CertificateProfile prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    	prof.setUseCRLDistributionPoint(true);
    	prof.setUseDefaultCRLDistributionPoint(true);
    	prof.setCRLDistributionPointCritical(true);
    	prof.setCRLDistributionPointURI("http://foo.bar/crl.crl");
        assertEquals(true, prof.getUseCRLDistributionPoint());
        assertEquals(true, prof.getUseDefaultCRLDistributionPoint());
        assertEquals(true, prof.getCRLDistributionPointCritical());
        assertEquals("http://foo.bar/crl.crl", prof.getCRLDistributionPointURI());

        final ArrayList<Integer> publishers = new ArrayList<>();
        publishers.add(1);
        publishers.add(2);
        
        prof.setPublisherList(publishers);
        final Collection<Integer> pub = prof.getPublisherList();
        assertEquals(2, pub.size());
        assertEquals(1, pub.iterator().next().intValue());

        final boolean[] kus = new boolean[9];
        kus[8] = true;
        prof.setKeyUsage(kus);
        final boolean[] ku = prof.getKeyUsage();
        assertEquals(9, ku.length);
        for (int i = 0; i < 8; i++) {
        	assertEquals(false, ku[i]);
        }
        assertEquals(true, ku[8]);
        assertNull(prof.getSignatureAlgorithm());
        prof.setSignatureAlgorithm("SHA256WithRSA");
        assertEquals("SHA256WithRSA", prof.getSignatureAlgorithm());
        
        assertTrue(prof.isApplicableToAnyCA());
        ArrayList<Integer> cas = new ArrayList<>();
        cas.add(1);
        prof.setAvailableCAs(cas);
        assertFalse(prof.isApplicableToAnyCA());
        Collection<Integer> cas1 = prof.getAvailableCAs();
        assertEquals(1, cas1.size());
        assertEquals(Integer.valueOf(1), cas.iterator().next());
        
    	final CertificateProfile orgprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
        Map<Object, Object> diff = orgprof.diff(prof);
        Set<Map.Entry<Object, Object>> set = diff.entrySet();
        assertEquals(8, set.size());
        for (Map.Entry<Object, Object> entry : diff.entrySet()) {
        	assertNotNull(entry.getKey()+" is empty", entry.getValue());
        }

        // Check for null when doing diff
        prof.setAvailableCAs(null);
        diff = orgprof.diff(prof);
        set = diff.entrySet();
        assertEquals(8, set.size());
        for (Map.Entry<Object, Object> entry : diff.entrySet()) {
        	assertNotNull(entry.getKey()+" is empty", entry.getValue());
        }

    }   
    
    @Test
    public void test02ChangeValuesForQcExtension() {
        final CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
        
        // Assert defaults.
        assertFalse(profile.getUseQCStatement());
        assertFalse(profile.getQCStatementCritical());
        assertFalse(profile.getUsePkixQCSyntaxV2());
        assertEquals("", profile.getQCSemanticsIds());
        assertFalse(profile.getUseQCEtsiQCCompliance());
        assertFalse(profile.getUseQCEtsiSignatureDevice());
        assertFalse(profile.getUseQCEtsiValueLimit());
        assertEquals("", profile.getQCEtsiValueLimitCurrency());
        assertEquals(0, profile.getQCEtsiValueLimit());
        assertEquals(0, profile.getQCEtsiValueLimitExp());
        assertFalse(profile.getUseQCEtsiRetentionPeriod());
        assertEquals(0, profile.getQCEtsiRetentionPeriod());
        assertNull(profile.getQCEtsiType());
        assertNull(profile.getQCEtsiPds());
        assertFalse(profile.getUseQCPSD2());
        assertFalse(profile.getUseQCCountries());
        assertEquals("", profile.getQCCountriesString());
        assertFalse(profile.getUseQCCustomString());
        assertEquals("", profile.getQCCustomStringOid());
        assertEquals("", profile.getQCCustomStringText());
        
        profile.setUseQCStatement(true);
        profile.setQCStatementCritical(true);
        assertEquals("Use QC statement does not match.", profile.getUseQCStatement(), true);
        assertEquals("QC statement critical does not match.", profile.getQCStatementCritical(), true);
        
        profile.setUsePkixQCSyntaxV2(true);
        assertEquals("Use PKIX QC syntax V2 does not match.", profile.getUsePkixQCSyntaxV2(), true);
        
        profile.setQCSemanticsIds("0.4.0.194121.1.2");
        assertEquals("QC semantics OID does not match.", profile.getQCSemanticsIds(), "0.4.0.194121.1.2");
        
        profile.setUseQCEtsiQCCompliance(true);
        assertEquals("Use QC ETSI QC compliance does not match.", profile.getUseQCEtsiQCCompliance(), true);
        
        profile.setUseQCEtsiSignatureDevice(true);
        assertEquals("Use QC ETSI qualified signature/e-seal signature creation device does not match.", profile.getUseQCEtsiSignatureDevice(), true);
        
        profile.setUseQCEtsiValueLimit(true);
        profile.setQCEtsiValueLimitCurrency("EUR");
        profile.setQCEtsiValueLimit(100);
        profile.setQCEtsiValueLimitExp(2);
        assertEquals("Use QC ETSI transaction value limit does not match.", profile.getUseQCEtsiValueLimit(), true);
        assertEquals("QC ETSI transaction currency does not match.", profile.getQCEtsiValueLimitCurrency(), "EUR");
        assertEquals("QC ETSI transaction value limit does not match.", profile.getQCEtsiValueLimit(), 100);
        assertEquals("QC ETSI transaction value limit exponent does not match.", profile.getQCEtsiValueLimitExp(), 2);
        
        profile.setUseQCEtsiRetentionPeriod(true);
        profile.setQCEtsiRetentionPeriod(3600);
        assertEquals("Use QC ETSI retention period does not match.", profile.getUseQCEtsiRetentionPeriod(), true);
        assertEquals("QC ETSI retention period does not match.", profile.getQCEtsiRetentionPeriod(), 3600);
        
        profile.setQCEtsiType(ETSIQCObjectIdentifiers.id_etsi_qct_esign.getId());
        assertEquals("QC ETSI type does not match.", profile.getQCEtsiType(), ETSIQCObjectIdentifiers.id_etsi_qct_esign.getId());
        
        // Setting an empty list causes it to be changed into null
        profile.setQCEtsiPds(new ArrayList<PKIDisclosureStatement>());
        assertNull(profile.getQCEtsiPds());
        // Test with one PDS
        profile.setQCEtsiPds(Arrays.asList(new PKIDisclosureStatement("https://pds.foo.bar/pds", "en")));
        List<PKIDisclosureStatement> pdsResult = profile.getQCEtsiPds();
        assertNotNull(pdsResult);
        assertEquals(1, pdsResult.size());
        assertEquals("en", pdsResult.get(0).getLanguage());
        assertEquals("https://pds.foo.bar/pds", pdsResult.get(0).getUrl());
        // Test with two PDSes
        profile.setQCEtsiPds(Arrays.asList(new PKIDisclosureStatement("https://pds.foo.bar/pds", "en"), new PKIDisclosureStatement("https://pds.example.com/pds.pdf", "sv")));
        pdsResult = profile.getQCEtsiPds();
        assertNotNull(pdsResult);
        assertEquals(2, pdsResult.size());
        assertEquals("en", pdsResult.get(0).getLanguage());
        assertEquals("https://pds.foo.bar/pds", pdsResult.get(0).getUrl());
        assertEquals("sv", pdsResult.get(1).getLanguage());
        assertEquals("https://pds.example.com/pds.pdf", pdsResult.get(1).getUrl());
        
        profile.setUseQCPSD2(true);
        assertEquals("Use QC ETSI PSD2 statement does not match.", profile.getUseQCPSD2(), true);
        
        profile.setUseQCCountries(true);
        profile.setQCCountriesString("SE,DE,IT");
        assertEquals("Use ETSI QC legislation countries does not match.", profile.getUseQCCountries(), true);
        assertEquals("QC ETSI countries string does not match.", profile.getQCCountriesString(), "SE,DE,IT");
        
        profile.setUseQCCustomString(true);
        profile.setQCCustomStringOid("1.2.3.4.5.6");
        profile.setQCCustomStringText("test-1.2.3.4.5.6");
        assertEquals("Use QC custom string does not match.", profile.getUseQCCustomString(), true);
        assertEquals("QC custom string OID does not match.", profile.getQCCustomStringOid(), "1.2.3.4.5.6");
        assertEquals("QC custom string text does not match.", profile.getQCCustomStringText(), "test-1.2.3.4.5.6");
    }
    
    @Test
    public void test03FixedProfiles() {
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.ROOTCAPROFILENAME));
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.SUBCAPROFILENAME));
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.ENDUSERPROFILENAME));
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.SERVERPROFILENAME));
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.OCSPSIGNERPROFILENAME));
    	assertFalse(CertificateProfile.FIXED_PROFILENAMES.contains("MY_CUSTOM_PROFILE_NAME"));

    	CertificateProfile prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
    	assertTrue(prof.isTypeRootCA());
    	assertFalse(prof.isTypeSubCA());
    	assertFalse(prof.isTypeEndEntity());
    	assertEquals(CertificateConstants.CERTTYPE_ROOTCA, prof.getType());
    	assertTrue(prof.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
    	assertTrue(prof.getKeyUsage(CertificateConstants.KEYCERTSIGN));
    	assertTrue(prof.getKeyUsage(CertificateConstants.CRLSIGN));
    	assertFalse(prof.getKeyUsage(CertificateConstants.KEYENCIPHERMENT));
    	prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
    	assertFalse(prof.isTypeRootCA());
    	assertTrue(prof.isTypeSubCA());
    	assertFalse(prof.isTypeEndEntity());
    	assertEquals(CertificateConstants.CERTTYPE_SUBCA, prof.getType());
    	assertTrue(prof.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
    	assertTrue(prof.getKeyUsage(CertificateConstants.KEYCERTSIGN));
    	assertTrue(prof.getKeyUsage(CertificateConstants.CRLSIGN));
    	assertFalse(prof.getKeyUsage(CertificateConstants.KEYENCIPHERMENT));
    	prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    	assertFalse(prof.isTypeRootCA());
    	assertFalse(prof.isTypeSubCA());
    	assertTrue(prof.isTypeEndEntity());
    	assertEquals(CertificateConstants.CERTTYPE_ENDENTITY, prof.getType());
    	assertTrue(prof.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
    	assertTrue(prof.getKeyUsage(CertificateConstants.KEYENCIPHERMENT));
    	assertTrue(prof.getKeyUsage(CertificateConstants.NONREPUDIATION));
    	assertFalse(prof.getKeyUsage(CertificateConstants.KEYCERTSIGN));
    	assertFalse(prof.getKeyUsage(CertificateConstants.CRLSIGN));
    	prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER);
    	assertFalse(prof.isTypeRootCA());
    	assertFalse(prof.isTypeSubCA());
    	assertTrue(prof.isTypeEndEntity());
    	assertEquals(CertificateConstants.CERTTYPE_ENDENTITY, prof.getType());
    	assertTrue(prof.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
    	assertTrue(prof.getKeyUsage(CertificateConstants.KEYENCIPHERMENT));
    	assertFalse(prof.getKeyUsage(CertificateConstants.NONREPUDIATION));
    	prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER);
    	assertFalse(prof.isTypeRootCA());
    	assertFalse(prof.isTypeSubCA());
    	assertTrue(prof.isTypeEndEntity());
    	assertEquals(CertificateConstants.CERTTYPE_ENDENTITY, prof.getType());
    	assertTrue(prof.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
    	assertFalse(prof.getKeyUsage(CertificateConstants.KEYENCIPHERMENT));
    	assertFalse(prof.getKeyUsage(CertificateConstants.NONREPUDIATION));
    }
    
    @Test
    public void test04createSubjectDNSubSet() throws Exception{
    	CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    	
        ArrayList<Integer> dnsubset = new ArrayList<>();
        dnsubset.add(DNFieldExtractor.CN);
        dnsubset.add(DNFieldExtractor.UID);
        dnsubset.add(DNFieldExtractor.GIVENNAME);
        dnsubset.add(DNFieldExtractor.SURNAME);
    	profile.setSubjectDNSubSet(dnsubset);
    	
    	String indn1 = "UID=PVE,CN=Philip Vendil,SN=123435,GIVENNAME=Philip,SURNAME=Vendil";
    	String outdn1 = profile.createSubjectDNSubSet(indn1);
    	String expecteddn1 = "UID=PVE,CN=Philip Vendil,GIVENNAME=Philip,SURNAME=Vendil";
        assertTrue("createSubjectDNSubSet doesn't work" + outdn1 + " != "+ expecteddn1, expecteddn1.equalsIgnoreCase(outdn1)); 
        
    	String indn2 = "UID=PVE,CN=Philip Vendil,CN=SecondUsername,SN=123435,SN=54321,GIVENNAME=Philip,SURNAME=Vendil";
    	String outdn2 = profile.createSubjectDNSubSet(indn2);
    	String expecteddn2 = "UID=PVE,CN=Philip Vendil,CN=SecondUsername,GIVENNAME=Philip,SURNAME=Vendil";
        assertTrue("createSubjectDNSubSet doesn't work" + outdn2 + " != "+ expecteddn2, expecteddn2.equalsIgnoreCase(outdn2));
    }

    @Test
    public void test05createSubjectAltNameSubSet() throws Exception{
    	CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    	
    	ArrayList<Integer> altnamesubset = new ArrayList<>();
    	altnamesubset.add(DNFieldExtractor.RFC822NAME);
    	altnamesubset.add(DNFieldExtractor.UPN);    	
    	profile.setSubjectAltNameSubSet(altnamesubset);
    	
    	String inaltname1 = "RFC822NAME=test@test.se,UPN=testacc@test.se,IPADDRESS=10.1.1.0";
    	String outaltname1 = profile.createSubjectAltNameSubSet(inaltname1);
    	String expectedaltname1 = "RFC822NAME=test@test.se,UPN=testacc@test.se";
        assertTrue("createSubjectAltNameSubSet doesn't work" + outaltname1 + " != "+ expectedaltname1, expectedaltname1.equalsIgnoreCase(outaltname1)); 
        
    	String inaltname2 = "RFC822NAME=test@test.se,RFC822NAME=test2@test2.se,UPN=testacc@test.se,IPADDRESS=10.1.1.0,IPADDRESS=10.1.1.2";
    	String outaltname2 = profile.createSubjectAltNameSubSet(inaltname2);
    	String expectedaltname2 = "RFC822NAME=test@test.se,RFC822NAME=test2@test2.se,UPN=testacc@test.se";
        assertTrue("createSubjectAltNameSubSet doesn't work" + outaltname2 + " != "+ expectedaltname2, expectedaltname2.equalsIgnoreCase(outaltname2));
    }

    @Test
    public void test06CertificateExtensions() throws Exception{
    	CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    	
    	// Check standard values for the certificate profile
    	List<String> l = profile.getUsedStandardCertificateExtensions();
    	assertEquals(7, l.size());
    	assertTrue(l.contains(Extension.keyUsage.getId()));
    	assertTrue(l.contains(Extension.basicConstraints.getId()));
    	assertTrue(l.contains(Extension.subjectKeyIdentifier.getId()));
    	assertTrue(l.contains(Extension.authorityKeyIdentifier.getId()));
    	assertTrue(l.contains(Extension.subjectAlternativeName.getId()));
    	assertTrue(l.contains(Extension.issuerAlternativeName.getId()));
    	assertTrue(l.contains(CertTools.OID_MS_SZ_OID_NTDS_CA_SEC_EXT));

    	CertificateProfile eprofile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    	
    	// Check standard values for the certificate profile
    	l = eprofile.getUsedStandardCertificateExtensions();
    	assertEquals(8, l.size());
    	assertTrue(l.contains(Extension.keyUsage.getId()));
    	assertTrue(l.contains(Extension.basicConstraints.getId()));
    	assertTrue(l.contains(Extension.subjectKeyIdentifier.getId()));
    	assertTrue(l.contains(Extension.authorityKeyIdentifier.getId()));
    	assertTrue(l.contains(Extension.subjectAlternativeName.getId()));
    	assertTrue(l.contains(Extension.issuerAlternativeName.getId()));
    	assertTrue(l.contains(Extension.extendedKeyUsage.getId()));
    	assertTrue(l.contains(CertTools.OID_MS_SZ_OID_NTDS_CA_SEC_EXT));

    	profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    	profile.setUseAuthorityInformationAccess(true);
    	profile.setUseCertificatePolicies(true);
    	profile.setUseCRLDistributionPoint(true);
    	profile.setUseFreshestCRL(true);
    	profile.setUseMicrosoftTemplate(true);
    	profile.setUseOcspNoCheck(true);
    	profile.setUseQCStatement(true);
    	profile.setUseExtendedKeyUsage(true);
    	profile.setUseSubjectDirAttributes(true);
    	l = profile.getUsedStandardCertificateExtensions();
    	assertEquals(16, l.size());
    	assertTrue(l.contains(Extension.keyUsage.getId()));
    	assertTrue(l.contains(Extension.basicConstraints.getId()));
    	assertTrue(l.contains(Extension.subjectKeyIdentifier.getId()));
    	assertTrue(l.contains(Extension.authorityKeyIdentifier.getId()));
    	assertTrue(l.contains(Extension.subjectAlternativeName.getId()));
    	assertTrue(l.contains(Extension.issuerAlternativeName.getId()));
    	assertTrue(l.contains(Extension.extendedKeyUsage.getId()));
    	assertTrue(l.contains(Extension.authorityInfoAccess.getId()));
    	assertTrue(l.contains(Extension.certificatePolicies.getId()));
    	assertTrue(l.contains(Extension.cRLDistributionPoints.getId()));
    	assertTrue(l.contains(Extension.freshestCRL.getId()));
    	assertTrue(l.contains(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()));
    	assertTrue(l.contains(Extension.qCStatements.getId()));
    	assertTrue(l.contains(Extension.subjectDirectoryAttributes.getId()));
    	assertTrue(l.contains(CertTools.OID_MSTEMPLATE));
    	assertTrue(l.contains(CertTools.OID_MS_SZ_OID_NTDS_CA_SEC_EXT));
    } // test09CertificateExtensions

    @Test
    public void test08Clone() throws Exception {
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
        CertificateProfile clone = profile.clone();
        @SuppressWarnings("unchecked")
        HashMap<Object, Object> profmap = (HashMap<Object, Object>)profile.saveData();
        @SuppressWarnings("unchecked")
        HashMap<Object, Object> clonemap = (HashMap<Object, Object>)clone.saveData();
        assertEquals(profmap.size(), clonemap.size());
        clonemap.put("FOO", "BAR");
        assertEquals(profmap.size()+1, clonemap.size());
        profmap.put("FOO", "BAR");
        assertEquals(profmap.size(), clonemap.size());
        profmap.put("FOO", "FAR");
        // Just changing value
        assertEquals(profmap.size(), clonemap.size());
        String profstr = (String)profmap.get("FOO");
        String clonestr = (String)clonemap.get("FOO");
        assertEquals("FAR", profstr);
        assertEquals("BAR", clonestr);
        CertificateProfile clone2 = clone.clone();
        @SuppressWarnings("unchecked")
        HashMap<Object, Object> clonemap2 = (HashMap<Object, Object>)clone2.saveData();
        // Added FOO, FAR to profmap and clonemap
        assertEquals(clonemap2.size(), clonemap.size()-1);
        assertEquals(clonemap2.size(), profmap.size()-1);
    }
    
    @Test
    public void test09ManyValues() {
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
        assertFalse(profile.getAllowCertSerialNumberOverride());
        profile.setAllowCertSerialNumberOverride(true);
        assertTrue(profile.getAllowCertSerialNumberOverride());
        profile.setAllowCertSerialNumberOverride(false);
        assertFalse(profile.getAllowCertSerialNumberOverride());
        assertFalse(profile.getAllowDNOverride());
        profile.setAllowDNOverride(true);
        assertTrue(profile.getAllowDNOverride());
        profile.setAllowDNOverride(false);
        assertFalse(profile.getAllowDNOverride());
        assertFalse(profile.getAllowExtensionOverride());
        profile.setAllowExtensionOverride(true);
        assertTrue(profile.getAllowExtensionOverride());
        profile.setAllowExtensionOverride(false);
        assertFalse(profile.getAllowExtensionOverride());
        
        assertEquals("", profile.getCRLDistributionPointURI());
        profile.setCRLDistributionPointURI("http://foo");
        assertEquals("http://foo", profile.getCRLDistributionPointURI());
        profile.setCRLDistributionPointURI(null);
        assertEquals("", profile.getCRLDistributionPointURI());
        assertEquals("", profile.getCRLIssuer());
        profile.setCRLIssuer("CN=Foo");
        assertEquals("CN=Foo", profile.getCRLIssuer());
        profile.setCRLIssuer(null);
        assertEquals("", profile.getCRLIssuer());
        assertEquals("", profile.getFreshestCRLURI());
        profile.setFreshestCRLURI("http://bar");
        assertEquals("http://bar", profile.getFreshestCRLURI());
        profile.setFreshestCRLURI(null);
        assertEquals("", profile.getFreshestCRLURI());
        List<String> issuers = profile.getCaIssuers();
        assertEquals(0, issuers.size());
        List<String> caissuers = new ArrayList<>();
        caissuers.add("foo");
        profile.setCaIssuers(caissuers);
        issuers = profile.getCaIssuers();
        assertEquals(1, issuers.size());
        assertEquals("foo", issuers.get(0));
        profile.addCaIssuer("bar");
        issuers = profile.getCaIssuers();
        assertEquals(2, issuers.size());
        assertEquals("foo", issuers.get(0));
        assertEquals("bar", issuers.get(1));
        profile.addCaIssuer("");
        issuers = profile.getCaIssuers();
        assertEquals(2, issuers.size());
        assertEquals("foo", issuers.get(0));
        assertEquals("bar", issuers.get(1));
        profile.removeCaIssuer("foo");
        issuers = profile.getCaIssuers();
        assertEquals(1, issuers.size());
        assertEquals("bar", issuers.get(0));
        profile.setCaIssuers(null);
        issuers = profile.getCaIssuers();
        assertEquals(0, issuers.size());

        assertEquals("", profile.getOCSPServiceLocatorURI());
        profile.setOCSPServiceLocatorURI("http://foo");
        assertEquals("http://foo", profile.getOCSPServiceLocatorURI());
        profile.setOCSPServiceLocatorURI(null);
        assertEquals("", profile.getOCSPServiceLocatorURI());

        List<CertificatePolicy> l = profile.getCertificatePolicies();
        assertEquals(0, l.size());
        profile.addCertificatePolicy(new CertificatePolicy("1.1.1.1", null, null));
        l = profile.getCertificatePolicies();
        assertEquals(1, l.size());
        CertificatePolicy policy = l.get(0);
        assertEquals("1.1.1.1", policy.getPolicyID());
        CertificatePolicy p2 = new CertificatePolicy("1.1.1.2", "1.1.2.1", "qualifiertext");
        profile.addCertificatePolicy(p2);
        l = profile.getCertificatePolicies();
        assertEquals(2, l.size());        
        policy = l.get(1);
        assertEquals("1.1.1.2", policy.getPolicyID());
        assertEquals("1.1.2.1", policy.getQualifierId());
        assertEquals("qualifiertext", policy.getQualifier());
        profile.removeCertificatePolicy(p2);
        assertEquals(1, l.size());
        policy = l.get(0);
        assertEquals("1.1.1.1", policy.getPolicyID());        
    }

    @Test
    public void test10CertificateProfileValues() throws Exception {
        CertificateProfile ep = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        List<CertificatePolicy> l = ep.getCertificatePolicies();
        assertEquals(0, l.size());
        ep.addCertificatePolicy(new CertificatePolicy(CertificatePolicy.ANY_POLICY_OID, null, null));
        l = ep.getCertificatePolicies();
        assertEquals(1, l.size());
        CertificatePolicy pol = l.get(0);
        assertEquals("2.5.29.32.0", pol.getPolicyID() );
        assertEquals(CertificateProfile.LATEST_VERSION, ep.getLatestVersion(),0);
        String qcId = ep.getQCSemanticsIds();
        assertEquals("", qcId);
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
        l = cp.getCertificatePolicies();
        assertEquals(0, l.size());
        cp.addCertificatePolicy(new CertificatePolicy(CertificatePolicy.ANY_POLICY_OID, null, null));
        l = cp.getCertificatePolicies();
        assertEquals(1, l.size());
        pol = l.get(0);
        assertEquals("2.5.29.32.0", pol.getPolicyID());
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.1.1", null, null));
        l = cp.getCertificatePolicies();
        assertEquals(2, l.size());
        pol = l.get(0);
        assertEquals("2.5.29.32.0", pol.getPolicyID());
        pol = l.get(1);
        assertEquals("1.1.1.1.1", pol.getPolicyID());
        assertEquals(CertificateProfile.LATEST_VERSION, cp.getLatestVersion(),0);
        assertEquals("", cp.getQCSemanticsIds());
        cp.setQCSemanticsIds("1.1.1.2");
        assertEquals("1.1.1.2", cp.getQCSemanticsIds());
        cp.setQCSemanticsIds("1.1.1.2,1.1.1.3");
        assertEquals("1.1.1.2,1.1.1.3", cp.getQCSemanticsIds());
        assertNull(cp.getSignatureAlgorithm()); // default value null = inherit from CA
        cp.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, cp.getSignatureAlgorithm());
    } 

    @SuppressWarnings({ "unchecked", "rawtypes" })
    @Test
    public void test11CertificatePolicyClassUpgrade() throws Exception {
        CertificateProfile ep = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        List<CertificatePolicy> l = ep.getCertificatePolicies();
        assertEquals(0, l.size());
        ep.addCertificatePolicy(new CertificatePolicy(CertificatePolicy.ANY_POLICY_OID, null, null));
        l = ep.getCertificatePolicies();
        assertEquals(1, l.size());
        CertificatePolicy pol = l.get(0);
        assertEquals("2.5.29.32.0", pol.getPolicyID() );
        assertNull(pol.getQualifier());
        assertNull(pol.getQualifierId());
        
        // Add policy as if we had run an old EJBCA 4 installation, now running in this version.
        // The class name of CertificatePolicy changed from EJBCA 4 to EJBCA 5.
        List list = new ArrayList();
        list.add(new org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy("1.1.1.2", null, "abc"));
        ep.setCertificatePolicies(list);
        l = ep.getCertificatePolicies();
        assertEquals(1, l.size());
        pol = l.get(0);
        assertEquals("1.1.1.2", pol.getPolicyID() );
        assertEquals("abc", pol.getQualifier());
        assertNull(pol.getQualifierId());

        list.add(new CertificatePolicy("1.1.1.3", "foo", null));
        ep.setCertificatePolicies(list);
        l = ep.getCertificatePolicies();
        assertEquals(2, l.size());
        pol = l.get(0);
        assertEquals("1.1.1.2", pol.getPolicyID() );
        assertEquals("abc", pol.getQualifier());
        assertNull(pol.getQualifierId());
        pol = l.get(1);
        assertEquals("1.1.1.3", pol.getPolicyID() );
        assertNull(pol.getQualifier());
        assertEquals("foo", pol.getQualifierId());
    }
    
    @SuppressWarnings({ "unchecked", "deprecation" })
    @Test
    public void testCertificateProfileUpgradeDefaults() {
        // Test with default/unset values
        final Map<String,Object> data = new HashMap<>();
        initDataMap(data);
        data.put(UpgradeableDataHashMap.VERSION, 1.0F);
        data.put(CertificateProfile.QCETSIPDSLANG, "");
        data.put(CertificateProfile.QCETSIPDSURL, "");
        final CertificateProfile cp = new CertificateProfile();
        cp.loadData(data);
        
        Map<String,Object> res = (Map<String, Object>) cp.saveData();
        assertTrue("Old property should still exist, so 100% uptime upgrades work", res.containsKey(CertificateProfile.QCETSIPDSLANG));
        assertTrue("Old property should still exist, so 100% uptime upgrades work", res.containsKey(CertificateProfile.QCETSIPDSURL));
        assertTrue("New property should have been added", res.containsKey(CertificateProfile.QCETSIPDS));
        assertNull(res.get(CertificateProfile.QCETSIPDS));
        
        cp.setQCEtsiPds(Arrays.asList(new PKIDisclosureStatement("https://example.com/pds", "en")));
        res = (Map<String, Object>) cp.saveData();
        assertFalse("Old property should have been removed after profile modification", res.containsKey(CertificateProfile.QCETSIPDSLANG));
        assertFalse("Old property should have been removed after profile modification", res.containsKey(CertificateProfile.QCETSIPDSURL));
    }
    
    @SuppressWarnings({ "unchecked", "deprecation" })
    @Test
    public void testCertificateProfileUpgradeNonDefaults() {
        final Map<String,Object> data = new HashMap<>();
        initDataMap(data);
        data.put(CertificateProfile.QCETSIPDSLANG, "en");
        data.put(CertificateProfile.QCETSIPDSURL, "https://example.com/pds.pdf");
        final CertificateProfile cp = new CertificateProfile();
        cp.loadData(data);

        final Map<String,Object> res = (Map<String, Object>) cp.saveData();
        assertTrue("Old property should still exist, so 100% uptime upgrades work", res.containsKey(CertificateProfile.QCETSIPDSLANG));
        assertTrue("Old property should still exist, so 100% uptime upgrades work", res.containsKey(CertificateProfile.QCETSIPDSURL));
        assertTrue("New property should have been added", res.containsKey(CertificateProfile.QCETSIPDS));
        final List<PKIDisclosureStatement> pdsList = (List<PKIDisclosureStatement>) res.get(CertificateProfile.QCETSIPDS);
        assertNotNull(pdsList);
        assertEquals(1, pdsList.size());
        assertEquals("en", pdsList.get(0).getLanguage());
        assertEquals("https://example.com/pds.pdf", pdsList.get(0).getUrl());
    }

    /** Initializes a data hash map. This does not (yet) initialize the full data hashmap from "v1", so it might be necessary to add additional properties in the future. */
    private void initDataMap(final Map<String, Object> data) {
        data.put(UpgradeableDataHashMap.VERSION, 1.0F);
        data.put(CertificateProfile.AVAILABLEBITLENGTHS, new ArrayList<>(Arrays.asList(1024)));
        data.put(CertificateProfile.MINIMUMAVAILABLEBITLENGTH, Integer.valueOf(1024));
        data.put(CertificateProfile.MAXIMUMAVAILABLEBITLENGTH, Integer.valueOf(1024));
    }

    @Test
    public void testInvalidKeySpecs() throws InvalidAlgorithmParameterException {
        // Install BC for key generation (if needed)
        CryptoProviderTools.installBCProviderIfNotAvailable();
        final KeyPair keyPairRsa = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        assertEquals("Unexpected key size of key pair used in this test.", 512, KeyTools.getKeyLength(keyPairRsa.getPublic()));
        final String USED_EC_CURVE_NAME = "prime256v1";
        final KeyPair keyPairEc = KeyTools.genKeys(USED_EC_CURVE_NAME, AlgorithmConstants.KEYALGORITHM_ECDSA);
        assertEquals("Unexpected key size of key pair used in this test.", 256, KeyTools.getKeyLength(keyPairEc.getPublic()));
        // Test happy path. RSA 512 bit key. RSA 512 allowed by certificate profile.
        testInvalidKeySpecsInternal(true, keyPairRsa.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_RSA}, new String[]{CertificateProfile.ANY_EC_CURVE}, new int[]{512});
        // Test expected failure. ECDSA 256 bit key. RSA 512 allowed by certificate profile.
        testInvalidKeySpecsInternal(false, keyPairEc.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_RSA}, new String[]{CertificateProfile.ANY_EC_CURVE}, new int[]{512});
        // Test expected failure. ECDSA 256 bit key. RSA 256,512 allowed by certificate profile.
        testInvalidKeySpecsInternal(false, keyPairEc.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_RSA}, new String[]{CertificateProfile.ANY_EC_CURVE}, new int[]{256,512});
        // Test expected failure. ECDSA 256 bit key. ECDSA 512 allowed by certificate profile.
        testInvalidKeySpecsInternal(false, keyPairEc.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_ECDSA}, new String[]{CertificateProfile.ANY_EC_CURVE}, new int[]{512});
        // Test happy path. ECDSA 256 bit key. ECDSA 256,512 allowed by certificate profile.
        testInvalidKeySpecsInternal(true, keyPairEc.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_ECDSA}, new String[]{CertificateProfile.ANY_EC_CURVE}, new int[]{256,512});
        // Test expected failure. RSA 512 bit key. ECDSA 512 allowed by certificate profile.
        testInvalidKeySpecsInternal(false, keyPairRsa.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_ECDSA}, new String[]{CertificateProfile.ANY_EC_CURVE}, new int[]{512});
        // Test expected failure. RSA 512 bit key. RSA 1024 allowed by certificate profile.
        testInvalidKeySpecsInternal(false, keyPairRsa.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_RSA}, new String[]{CertificateProfile.ANY_EC_CURVE}, new int[]{1024});
        // Test happy path. RSA 512 bit key. ECDSA, RSA 256,512,1024 allowed by certificate profile.
        testInvalidKeySpecsInternal(true, keyPairRsa.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmConstants.KEYALGORITHM_RSA},
                new String[]{CertificateProfile.ANY_EC_CURVE}, new int[]{256,512,1024});
        // Test happy path. RSA 512 bit key. ECDSA, RSA 256,1024 allowed by certificate profile.
        testInvalidKeySpecsInternal(true, keyPairRsa.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmConstants.KEYALGORITHM_RSA},
                new String[]{CertificateProfile.ANY_EC_CURVE}, new int[]{256,1024});
        // Test happy path. EC 256 bit "prime256v1" key. ECDSA (bit restricted + "prime256v1"), RSA 256,1024 allowed by certificate profile.
        testInvalidKeySpecsInternal(true, keyPairEc.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmConstants.KEYALGORITHM_RSA},
                new String[]{CertificateProfile.ANY_EC_CURVE, USED_EC_CURVE_NAME}, new int[]{256,1024});
        // Test happy path. EC 256 bit "prime256v1" key. ECDSA (bit restricted + "secp256k1"), 256,1024 allowed by certificate profile.
        testInvalidKeySpecsInternal(true, keyPairEc.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_ECDSA},
                new String[]{CertificateProfile.ANY_EC_CURVE, USED_EC_CURVE_NAME}, new int[]{256,1024});
        // Test happy path. EC 256 bit "prime256v1" key. ECDSA (bit restricted + "secp256k1"), RSA 256,1024 allowed by certificate profile.
        testInvalidKeySpecsInternal(true, keyPairEc.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmConstants.KEYALGORITHM_RSA},
                new String[]{CertificateProfile.ANY_EC_CURVE, "secp256k1"}, new int[]{256,1024});
        // Test expected failure. EC 256 bit "prime256v1" key. ECDSA (bit restricted + "secp256k1"), RSA 512,1024 allowed by certificate profile.
        testInvalidKeySpecsInternal(false, keyPairEc.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmConstants.KEYALGORITHM_RSA},
                new String[]{CertificateProfile.ANY_EC_CURVE, "secp256k1"}, new int[]{512,1024});
        // Test happy path. EC 256 bit "prime256v1" key. ECDSA (bit restricted + "prime256v1"), RSA 512,1024 allowed by certificate profile.
        testInvalidKeySpecsInternal(true, keyPairEc.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmConstants.KEYALGORITHM_RSA},
                new String[]{CertificateProfile.ANY_EC_CURVE, USED_EC_CURVE_NAME}, new int[]{512,1024});
        // Test expected failure. EC 256 bit "prime256v1" key. ECDSA ("secp256k1"), RSA 256,1024 allowed by certificate profile.
        testInvalidKeySpecsInternal(false, keyPairEc.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmConstants.KEYALGORITHM_RSA},
                new String[]{"secp256k1"}, new int[]{256,1024});
        // Test happy path. EC 256 bit "prime256v1" key. ECDSA allowing alias for "prime256v1" ("secp256r1") by certificate profile.
        testInvalidKeySpecsInternal(true, keyPairEc.getPublic(), new String[]{AlgorithmConstants.KEYALGORITHM_ECDSA},
                new String[]{"secp256r1"}, new int[]{});
    }

    
    private void testInvalidKeySpecsInternal(final boolean expectedNoIllegalKeyException, final PublicKey publicKey, final String[] availableKeyAlgorithms, 
            final String[] availableEcCurves, final int[] availableBitLengths) {
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setAvailableKeyAlgorithms(availableKeyAlgorithms);
        certificateProfile.setAvailableEcCurves(availableEcCurves);
        certificateProfile.setAvailableBitLengths(availableBitLengths);
        try {
            certificateProfile.verifyKey(publicKey);
            if (!expectedNoIllegalKeyException) {
                fail("Validation should not work with invalid key size and/or algoritmh,");
            }
        } catch (IllegalKeyException e) {
            if (expectedNoIllegalKeyException) {
                fail("Key algorithm and spec should have been allowed by certificate profile.");
            }
        }
    }
    
    @Test
    public void testIsKeyTypeAllowed() {
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setAvailableKeyAlgorithms(new String[] {AlgorithmConstants.KEYALGORITHM_RSA});
        certificateProfile.setAvailableEcCurves(new String[] {});
        certificateProfile.setAvailableBitLengths(new int[] {2048});
        assertFalse(certificateProfile.isKeyTypeAllowed("OTHER", "2048"));
        assertFalse(certificateProfile.isKeyTypeAllowed(AlgorithmConstants.KEYALGORITHM_RSA, "1024"));
        assertTrue(certificateProfile.isKeyTypeAllowed(AlgorithmConstants.KEYALGORITHM_RSA, "2048"));
        assertFalse(certificateProfile.isKeyTypeAllowed(AlgorithmConstants.KEYALGORITHM_ECDSA, "secp256r1"));
        assertFalse(certificateProfile.isKeyTypeAllowed(AlgorithmConstants.KEYALGORITHM_ECDSA, "secp256k1"));
        
        certificateProfile.setAvailableKeyAlgorithms(new String[] {AlgorithmConstants.KEYALGORITHM_ECDSA});
        certificateProfile.setAvailableEcCurves(new String[] {"secp256r1"});
        certificateProfile.setAvailableBitLengths(new int[] {});
        assertFalse(certificateProfile.isKeyTypeAllowed("OTHER", "2048"));
        assertFalse(certificateProfile.isKeyTypeAllowed(AlgorithmConstants.KEYALGORITHM_RSA, "1024"));
        assertFalse(certificateProfile.isKeyTypeAllowed(AlgorithmConstants.KEYALGORITHM_RSA, "2048"));
        assertTrue(certificateProfile.isKeyTypeAllowed(AlgorithmConstants.KEYALGORITHM_ECDSA, "secp256r1"));
        assertFalse(certificateProfile.isKeyTypeAllowed(AlgorithmConstants.KEYALGORITHM_ECDSA, "secp256k1"));
        
        certificateProfile.setAvailableKeyAlgorithms(new String[] {AlgorithmConstants.KEYALGORITHM_ECDSA});
        certificateProfile.setAvailableEcCurves(new String[] {CertificateProfile.ANY_EC_CURVE});
        certificateProfile.setAvailableBitLengths(new int[] {});
        assertFalse(certificateProfile.isKeyTypeAllowed("OTHER", "2048"));
        assertFalse(certificateProfile.isKeyTypeAllowed(AlgorithmConstants.KEYALGORITHM_RSA, "1024"));
        assertFalse(certificateProfile.isKeyTypeAllowed(AlgorithmConstants.KEYALGORITHM_RSA, "2048"));
        assertTrue(certificateProfile.isKeyTypeAllowed(AlgorithmConstants.KEYALGORITHM_ECDSA, "secp256r1"));
        assertTrue(certificateProfile.isKeyTypeAllowed(AlgorithmConstants.KEYALGORITHM_ECDSA, "secp256k1"));
    }

    @Test
    public void testDefaultEncodedValiditySetCorrectly() {
        final CertificateProfile cpRootCa = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
        final CertificateProfile cpSubCa = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
        final CertificateProfile cpEndUser = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        final CertificateProfile ocspSigner = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER);
        final CertificateProfile server = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER);

        assertEquals(CertificateProfile.DEFAULT_CERTIFICATE_VALIDITY_FOR_FIXED_CA, cpRootCa.getEncodedValidity());
        assertEquals(CertificateProfile.DEFAULT_CERTIFICATE_VALIDITY_FOR_FIXED_CA, cpSubCa.getEncodedValidity());
        assertEquals(CertificateProfile.DEFAULT_CERTIFICATE_VALIDITY, cpEndUser.getEncodedValidity());
        assertEquals(CertificateProfile.DEFAULT_CERTIFICATE_VALIDITY, ocspSigner.getEncodedValidity());
        assertEquals(CertificateProfile.DEFAULT_CERTIFICATE_VALIDITY, server.getEncodedValidity());
    }

    @Test
    public void testDefaultExtendedKeyUsageSetCorrectlyForRootCa() {
        final CertificateProfile cpRootCa = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);

        assertFalse(cpRootCa.getUseExtendedKeyUsage());
        assertFalse(cpRootCa.getExtendedKeyUsageCritical());
        assertEquals(new ArrayList<>(), cpRootCa.getExtendedKeyUsageOids());
    }

    @Test
    public void testDefaultExtendedKeyUsageSetCorrectlyForSubCa() {
        final CertificateProfile cpSubCa = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);

        assertFalse(cpSubCa.getUseExtendedKeyUsage());
        assertFalse(cpSubCa.getExtendedKeyUsageCritical());
        assertEquals(new ArrayList<>(), cpSubCa.getExtendedKeyUsageOids());
    }

    @Test
    public void testDefaultExtendedKeyUsageSetCorrectlyForEndUser() {
        final CertificateProfile cpEndUser = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

        final ArrayList<String> expectedEku = new ArrayList<>();
        expectedEku.add(KeyPurposeId.id_kp_clientAuth.getId());
        expectedEku.add(KeyPurposeId.id_kp_emailProtection.getId());

        assertTrue(cpEndUser.getUseExtendedKeyUsage());
        assertFalse(cpEndUser.getExtendedKeyUsageCritical());
        assertEquals(expectedEku, cpEndUser.getExtendedKeyUsageOids());
    }

    @Test
    public void testDefaultExtendedKeyUsageSetCorrectlyForOcspSigner() {
        final CertificateProfile cpOcspSigner = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER);

        final ArrayList<String> expectedEku = new ArrayList<>();
        expectedEku.add(KeyPurposeId.id_kp_OCSPSigning.getId());

        assertTrue(cpOcspSigner.getUseExtendedKeyUsage());
        assertFalse(cpOcspSigner.getExtendedKeyUsageCritical());
        assertEquals(expectedEku, cpOcspSigner.getExtendedKeyUsageOids());
    }

    @Test
    public void testDefaultExtendedKeyUsageSetCorrectlyForServer() {
        final CertificateProfile cpServer = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER);

        final ArrayList<String> expectedEku = new ArrayList<>();
        expectedEku.add(KeyPurposeId.id_kp_serverAuth.getId());

        assertTrue(cpServer.getUseExtendedKeyUsage());
        assertFalse(cpServer.getExtendedKeyUsageCritical());
        assertEquals(expectedEku, cpServer.getExtendedKeyUsageOids());
    }

    @Test
    public void testDefaultKeyUsageSetCorrectlyForRootCa() {
        final CertificateProfile cpRootCa = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);

        final long expectedKeyCount = Booleans.asList(cpRootCa.getKeyUsage()).stream().filter(key -> key).count();

        assertTrue(cpRootCa.getUseKeyUsage());
        assertTrue(cpRootCa.getKeyUsageCritical());

        assertEquals(3, expectedKeyCount);
        assertTrue(cpRootCa.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
        assertTrue(cpRootCa.getKeyUsage(CertificateConstants.KEYCERTSIGN));
        assertTrue(cpRootCa.getKeyUsage(CertificateConstants.CRLSIGN));
    }

    @Test
    public void testDefaultKeyUsageSetCorrectlyForSubCa() {
        final CertificateProfile cpSubCa = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);

        final long expectedKeyCount = Booleans.asList(cpSubCa.getKeyUsage()).stream().filter(key -> key).count();

        assertTrue(cpSubCa.getUseKeyUsage());
        assertTrue(cpSubCa.getKeyUsageCritical());

        assertEquals(3, expectedKeyCount);
        assertTrue(cpSubCa.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
        assertTrue(cpSubCa.getKeyUsage(CertificateConstants.KEYCERTSIGN));
        assertTrue(cpSubCa.getKeyUsage(CertificateConstants.CRLSIGN));
    }

    @Test
    public void testDefaultKeyUsageSetCorrectlyForEndUser() {
        final CertificateProfile cpEndUser = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

        final long expectedKeyCount = Booleans.asList(cpEndUser.getKeyUsage()).stream().filter(key -> key).count();

        assertTrue(cpEndUser.getUseKeyUsage());
        assertTrue(cpEndUser.getKeyUsageCritical());

        assertEquals(3, expectedKeyCount);
        assertTrue(cpEndUser.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
        assertTrue(cpEndUser.getKeyUsage(CertificateConstants.NONREPUDIATION));
        assertTrue(cpEndUser.getKeyUsage(CertificateConstants.KEYENCIPHERMENT));
    }

    @Test
    public void testDefaultKeyUsageSetCorrectlyForOcspSigner() {
        final CertificateProfile cpOcspSigner = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER);

        final long expectedKeyCount = Booleans.asList(cpOcspSigner.getKeyUsage()).stream().filter(key -> key).count();

        assertTrue(cpOcspSigner.getUseKeyUsage());
        assertTrue(cpOcspSigner.getKeyUsageCritical());

        assertEquals(1, expectedKeyCount);
        assertTrue(cpOcspSigner.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
    }

    @Test
    public void testDefaultKeyUsageSetCorrectlyForServer() {
        final CertificateProfile cpServer = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER);

        final long expectedKeyCount = Booleans.asList(cpServer.getKeyUsage()).stream().filter(key -> key).count();

        assertTrue(cpServer.getUseKeyUsage());
        assertTrue(cpServer.getKeyUsageCritical());

        assertEquals(2, expectedKeyCount);
        assertTrue(cpServer.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
        assertTrue(cpServer.getKeyUsage(CertificateConstants.KEYENCIPHERMENT));
    }
}
