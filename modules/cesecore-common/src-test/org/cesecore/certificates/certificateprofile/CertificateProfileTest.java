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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.util.CertTools;
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
    	assertEquals(730, prof.getValidity());
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
        assertEquals(false, prof.getUseCRLDistributionPointOnCRL());
        assertEquals(false, prof.getUseFreshestCRL());
        assertEquals(false, prof.getUseCADefinedFreshestCRL());
        assertEquals("", prof.getFreshestCRLURI());
        assertEquals(false, prof.getUseCertificatePolicies());
        assertEquals(false, prof.getCertificatePoliciesCritical());
        final List<CertificatePolicy> policies = prof.getCertificatePolicies();
        assertEquals(0, policies.size());
        assertEquals(CertificateConstants.CERTTYPE_ENDENTITY, prof.getType());
        final int[] availablebitlen = prof.getAvailableBitLengths();
        assertEquals(15, availablebitlen.length);
        assertEquals(0, availablebitlen[0]);
        assertEquals(8192, availablebitlen[14]);
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
        assertEquals("", prof.getQCSemanticsId());
        assertEquals(false, prof.getUseQCEtsiQCCompliance());
        assertEquals(false, prof.getUseQCEtsiSignatureDevice());
        assertEquals(false, prof.getUseQCEtsiValueLimit());
        assertEquals(0, prof.getQCEtsiValueLimit());
        assertEquals(0, prof.getQCEtsiValueLimitExp());
        assertEquals("", prof.getQCEtsiValueLimitCurrency());
        assertEquals(false, prof.getUseQCEtsiRetentionPeriod());
        assertEquals(0, prof.getQCEtsiRetentionPeriod());
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
        assertEquals(1, prof.getNumOfReqApprovals());
        final Collection<Integer> app = prof.getApprovalSettings();
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

        final ArrayList<Integer> publishers = new ArrayList<Integer>();
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
        ArrayList<Integer> cas = new ArrayList<Integer>();
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
    public void test03FixedProfiles() {
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.ROOTCAPROFILENAME));
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.SUBCAPROFILENAME));
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.ENDUSERPROFILENAME));
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.SERVERPROFILENAME));
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.OCSPSIGNERPROFILENAME));
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.HARDTOKENAUTHENCPROFILENAME));
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.HARDTOKENAUTHPROFILENAME));
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.HARDTOKENENCPROFILENAME));
    	assertTrue(CertificateProfile.FIXED_PROFILENAMES.contains(CertificateProfile.HARDTOKENSIGNPROFILENAME));
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
    	prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTHENC);
    	assertFalse(prof.isTypeRootCA());
    	assertFalse(prof.isTypeSubCA());
    	assertTrue(prof.isTypeEndEntity());
    	assertEquals(CertificateConstants.CERTTYPE_ENDENTITY, prof.getType());
    	assertTrue(prof.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
    	assertTrue(prof.getKeyUsage(CertificateConstants.KEYENCIPHERMENT));
    	assertFalse(prof.getKeyUsage(CertificateConstants.NONREPUDIATION));
    	prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENENC);
    	assertFalse(prof.isTypeRootCA());
    	assertFalse(prof.isTypeSubCA());
    	assertTrue(prof.isTypeEndEntity());
    	assertEquals(CertificateConstants.CERTTYPE_ENDENTITY, prof.getType());
    	assertFalse(prof.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
    	assertFalse(prof.getKeyUsage(CertificateConstants.NONREPUDIATION));
    	assertTrue(prof.getKeyUsage(CertificateConstants.KEYENCIPHERMENT));
    	prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTH);
    	assertFalse(prof.isTypeRootCA());
    	assertFalse(prof.isTypeSubCA());
    	assertTrue(prof.isTypeEndEntity());
    	assertEquals(CertificateConstants.CERTTYPE_ENDENTITY, prof.getType());
    	assertTrue(prof.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
    	assertFalse(prof.getKeyUsage(CertificateConstants.KEYENCIPHERMENT));
    	assertFalse(prof.getKeyUsage(CertificateConstants.NONREPUDIATION));
    	prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENSIGN);
    	assertFalse(prof.isTypeRootCA());
    	assertFalse(prof.isTypeSubCA());
    	assertTrue(prof.isTypeEndEntity());
    	assertEquals(CertificateConstants.CERTTYPE_ENDENTITY, prof.getType());
    	assertTrue(prof.getKeyUsage(CertificateConstants.NONREPUDIATION));
    	assertFalse(prof.getKeyUsage(CertificateConstants.DIGITALSIGNATURE));
    	assertFalse(prof.getKeyUsage(CertificateConstants.KEYENCIPHERMENT));
    }
    
    @Test
    public void test04createSubjectDNSubSet() throws Exception{
    	CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    	
    	ArrayList<String> dnsubset = new ArrayList<String>();
    	dnsubset.add(Integer.toString(DNFieldExtractor.CN));
    	dnsubset.add(Integer.toString(DNFieldExtractor.UID));
    	dnsubset.add(Integer.toString(DNFieldExtractor.GIVENNAME));
    	dnsubset.add(Integer.toString(DNFieldExtractor.SURNAME));    	
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
    	
    	ArrayList<Integer> altnamesubset = new ArrayList<Integer>();
    	altnamesubset.add(Integer.valueOf(DNFieldExtractor.RFC822NAME));
    	altnamesubset.add(Integer.valueOf(DNFieldExtractor.UPN));    	
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
    	assertEquals(6, l.size());
    	assertTrue(l.contains(Extension.keyUsage.getId()));
    	assertTrue(l.contains(Extension.basicConstraints.getId()));
    	assertTrue(l.contains(Extension.subjectKeyIdentifier.getId()));
    	assertTrue(l.contains(Extension.authorityKeyIdentifier.getId()));
    	assertTrue(l.contains(Extension.subjectAlternativeName.getId()));
    	assertTrue(l.contains(Extension.issuerAlternativeName.getId()));

    	CertificateProfile eprofile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    	
    	// Check standard values for the certificate profile
    	l = eprofile.getUsedStandardCertificateExtensions();
    	assertEquals(7, l.size());
    	assertTrue(l.contains(Extension.keyUsage.getId()));
    	assertTrue(l.contains(Extension.basicConstraints.getId()));
    	assertTrue(l.contains(Extension.subjectKeyIdentifier.getId()));
    	assertTrue(l.contains(Extension.authorityKeyIdentifier.getId()));
    	assertTrue(l.contains(Extension.subjectAlternativeName.getId()));
    	assertTrue(l.contains(Extension.issuerAlternativeName.getId()));
    	assertTrue(l.contains(Extension.extendedKeyUsage.getId()));

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
    	assertEquals(15, l.size());
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
    } // test09CertificateExtensions

    @Test
    public void test08Clone() throws Exception {
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
        CertificateProfile clone = (CertificateProfile)profile.clone();
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
        CertificateProfile clone2 = (CertificateProfile)clone.clone();
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
        List<String> caissuers = new ArrayList<String>();
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
        
        assertFalse(profile.isApprovalRequired(CAInfo.REQ_APPROVAL_ADDEDITENDENTITY));
        ArrayList<Integer> approvals = new ArrayList<Integer>();
        approvals.add(CAInfo.REQ_APPROVAL_ADDEDITENDENTITY);
        profile.setApprovalSettings(approvals);
        assertTrue(profile.isApprovalRequired(CAInfo.REQ_APPROVAL_ADDEDITENDENTITY));
        assertFalse(profile.isApprovalRequired(CAInfo.REQ_APPROVAL_KEYRECOVER));
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
        String qcId = ep.getQCSemanticsId();
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
        assertEquals("", cp.getQCSemanticsId());
        cp.setQCSemanticsId("1.1.1.2");
        assertEquals("1.1.1.2", cp.getQCSemanticsId());
        
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
        ep.setCertificatePolicies((List<CertificatePolicy>)list);
        l = ep.getCertificatePolicies();
        assertEquals(1, l.size());
        pol = l.get(0);
        assertEquals("1.1.1.2", pol.getPolicyID() );
        assertEquals("abc", pol.getQualifier());
        assertNull(pol.getQualifierId());

        list.add(new CertificatePolicy("1.1.1.3", "foo", null));
        ep.setCertificatePolicies((List<CertificatePolicy>)list);
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


}
