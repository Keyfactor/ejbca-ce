package org.ejbca.core.ejb.ra;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.cert.X509CertificateHolder;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Tests name constraint attribute for different combinations of settings in certificate authority, 
 * certificate profile, end entity profile and end entity. 
 * 
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CertificateNameConstraintTest extends CaTestCase {
    
    private static final Logger log = Logger.getLogger(CertificateNameConstraintTest.class);
        
    private static final String REPLACABLE_TAG = "$TAG$";
    
    private static final String TEST_NC_ROOT_CA_NAME = "testNCRootCa";
    private static final String TEST_NC_SUB_CA_NAME = "testNCSubCa" + REPLACABLE_TAG;
    private static final String TEST_NC_END_ENTITY_NAME = "testNCEndEntity" + REPLACABLE_TAG;
    private static final String TEST_NC_DUMMY_CA_NAME = "testNCCa" + REPLACABLE_TAG;

    private static final String TEST_NC_ROOT_CA_DN = "CN=" + TEST_NC_ROOT_CA_NAME;
    private static final String TEST_NC_SUB_CA_DN = "CN=" + TEST_NC_SUB_CA_NAME + REPLACABLE_TAG;
    private static final String TEST_NC_END_ENTITY_DN = "CN=" + TEST_NC_END_ENTITY_NAME + REPLACABLE_TAG;
    private static final String TEST_NC_DUMMY_CA_DN = "CN=dummyDomain" + REPLACABLE_TAG;
    
    private static final String TEST_NC_CERT_PROFILE_ROOT = "testNCRootProfile";
    private static final String TEST_NC_CERT_PROFILE_SUBCA = "testNCSubCaProfile";
    private static final String TEST_NC_CERT_PROFILE_EE = "testNCEndEntityProfile";
    private static final String TEST_NC_CERT_PROFILE_DUMMY = "testNCProfile" + REPLACABLE_TAG;
    
    private static final String TEST_NC_EE_PROFILE_NAME = "testNCEndEntityProfile";
    private static final String TEST_NC_EE_DUMMY_PROFILE_NAME = "testNCEndEntityProfile" + REPLACABLE_TAG;
    
    private static final String TEST_NC_EE_PASSWORD = "foo123";
        
    private static int rootCaId;
    private static int rootCertificateProfileId, endEntityCertificateProfileId, subCaCertificateProfileId;
    private static int endEntityProfileId;
    
    private static CertificateProfile rootCertProfile, subCaCertprofile, endEntityCertprofile;
    private static EndEntityProfile endEntityProfile;
    private EndEntityInformation lastCreatedUser;
    
    private static List<String> formatedNCPermitted, formatedNCExcluded;
    
    private static List<String> createdSubCas;
    
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertificateNameConstraintTest"));
    
    private static final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final CertificateProfileSessionRemote certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static final KeyStoreCreateSessionRemote keyStoreCreateSessionBean = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyStoreCreateSessionRemote.class);
    private static final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
    
    @BeforeClass
    public static void setUpNameConstraintsTest() throws Exception {
        
        CryptoProviderTools.installBCProvider();
        createdSubCas = new ArrayList<String>();
        
        List<String> nameConstPermitted = new ArrayList<String>();
        //nameConstPermitted.add("C=SE,O=PrimeKey,CN=example.com");
        nameConstPermitted.add("exampleinc.com");
        nameConstPermitted.add("@mail.example");
        nameConstPermitted.add("user@host.com");
        nameConstPermitted.add("10.0.0.0/8");
        nameConstPermitted.add("2001:db8::/32");
        //nameConstPermitted.add("C=SE,  CN=spacing");
        
        List<String> nameConstExcluded = new ArrayList<String>();
        nameConstExcluded.add("forbidden.example.com");
        nameConstExcluded.add("postmaster@mail.example");
        nameConstExcluded.add("10.1.0.0/16");
        nameConstExcluded.add("2005:ac7::/64");
        nameConstExcluded.add("C=SE,O=PrimeKey,CN=example.com");
        nameConstExcluded.add("C=SE,  CN=spacing");
        
        formatedNCPermitted = formatAllNameConstraints(nameConstPermitted); 
        formatedNCExcluded = formatAllNameConstraints(nameConstExcluded);
        
        // verify nothing is left from last run 
        tearDownNameConstraintsTest();
        
        // create
        // root cert profile
        rootCertProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
        rootCertProfile.setUseNameConstraints(true);
        // rootCertProfile.setNameConstraintsCritical(true);
        rootCertificateProfileId = certProfileSession.addCertificateProfile(admin, TEST_NC_CERT_PROFILE_ROOT, rootCertProfile);
        log.info("created root certificate profile id: " + rootCertificateProfileId);
        
        // root CA
        log.info("adding root CA: " + TEST_NC_ROOT_CA_NAME);
        rootCaId = CaTestCase.createTestCA(TEST_NC_ROOT_CA_NAME, 4096, TEST_NC_ROOT_CA_DN, 
                CAInfo.SELFSIGNED, null, rootCertificateProfileId, 
                formatedNCPermitted, formatedNCExcluded, true, true);
        log.info("Root CA id: " + rootCaId);
        CAInfo cainfo = caSession.getCAInfo(admin, TEST_NC_ROOT_CA_NAME);
        log.info("Refetched root CA id by name: " + cainfo.getCAId());
        
        
        // subca cert profile (updated once)
        subCaCertprofile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
        subCaCertprofile.setUseNameConstraints(true);
        subCaCertificateProfileId = certProfileSession.addCertificateProfile(admin, TEST_NC_CERT_PROFILE_SUBCA, subCaCertprofile);
        log.info("created subca certificate profile id: " + subCaCertificateProfileId);
        
        // ee cert profile (updated multiple times)
        endEntityCertprofile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        endEntityCertprofile.setUseNameConstraints(true);
        endEntityCertprofile.setUseLdapDnOrder(false);
        endEntityCertificateProfileId = certProfileSession.addCertificateProfile(admin, TEST_NC_CERT_PROFILE_EE, endEntityCertprofile);
        log.info("created end entity certificate profile id: " + endEntityCertificateProfileId);
        
        // end entity profile (updated multiple times)
        endEntityProfile = new EndEntityProfile();
        endEntityProfile.setNameConstraintsPermittedUsed(true);
        endEntityProfile.setNameConstraintsPermittedRequired(false);
        endEntityProfile.setNameConstraintsExcludedUsed(true);
        endEntityProfile.setNameConstraintsExcludedRequired(false);
        List<Integer> availableCertProfiles = endEntityProfile.getAvailableCertificateProfileIds();
        availableCertProfiles.add(endEntityCertificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(availableCertProfiles);
        endEntityProfile.setAvailableCAs(Arrays.asList(new Integer[]{SecConst.ALLCAS}));
        endEntityProfile.addField(DnComponents.COUNTRY);
        
        endEntityProfileId = endEntityProfileSession.addEndEntityProfile(admin, TEST_NC_EE_PROFILE_NAME, endEntityProfile);
        log.info("Created end entity profile id: " + endEntityProfileId);
        
    }
    
    @AfterClass
    public static void tearDownNameConstraintsTest() throws Exception {
        
        // remove:
        // ee profile
        endEntityProfileSession.removeEndEntityProfile(admin, TEST_NC_EE_PROFILE_NAME);

        // ee cert profile
        certProfileSession.removeCertificateProfile(admin, TEST_NC_CERT_PROFILE_EE);
        
        // remove all sub ca
        for(String s: createdSubCas)
            CaTestCase.removeTestCA(s);
        
        // subca cert profile
        certProfileSession.removeCertificateProfile(admin, TEST_NC_CERT_PROFILE_SUBCA);
        
        // Root CA
        CaTestCase.removeTestCA(TEST_NC_ROOT_CA_NAME);
        
        // root cert profile
        certProfileSession.removeCertificateProfile(admin, TEST_NC_CERT_PROFILE_ROOT);      
        
    }
    
    private String getRandomizedName(String nameTemplate) {
        return nameTemplate.replace(REPLACABLE_TAG, genRandomUserName());
    }
    
    private static List<String> formatAllNameConstraints(List<String> nameConstraints) throws CertificateExtensionException {
        List<String> nameConstraintsFormatted = new ArrayList<String>();
        for(String nc: nameConstraints)
            nameConstraintsFormatted.add(NameConstraint.parseNameConstraintEntry(nc));
        return nameConstraintsFormatted;
    }
    
    private void createAndRenewEndEntityVerified(String testCase, 
            List<String> permittedNCs, List<String> excludedNCs) throws Exception {
        
        boolean result = createAndVerifyEndEntity(testCase, permittedNCs, excludedNCs, endEntityProfileId, 
                endEntityCertificateProfileId, false, false, false, true);
        Assert.assertTrue("End entity creation failed at " + testCase, result);
        
        List<String> permittedNCUpdated = new ArrayList<String>();
        if(permittedNCs!=null) {
            permittedNCUpdated.addAll(permittedNCs);
            permittedNCUpdated.remove(0);
        }
        
        List<String> excludedNCUpdated = new ArrayList<String>();
        if(excludedNCs!=null) {
            excludedNCUpdated.addAll(excludedNCs);
            excludedNCUpdated.remove(0);
        }
        
        permittedNCUpdated.add(NameConstraint.parseNameConstraintEntry("addpermitted.check.com"));
        excludedNCUpdated.add(NameConstraint.parseNameConstraintEntry("addexclusion.check.com"));
        
        lastCreatedUser.setStatus(EndEntityConstants.STATUS_INPROCESS);
        ExtendedInformation extendedInfo = new ExtendedInformation();
        extendedInfo.setNameConstraintsPermitted(permittedNCUpdated);
        extendedInfo.setNameConstraintsExcluded(excludedNCUpdated);
        lastCreatedUser.setExtendedInformation(extendedInfo);
        
        endEntityManagementSession.changeUser(admin, lastCreatedUser, false);
        byte[] encodedKeyStore = keyStoreCreateSessionBean.generateOrKeyRecoverTokenAsByteArray(admin,
                lastCreatedUser.getUsername(), lastCreatedUser.getPassword(), 
                lastCreatedUser.getCAId(), "2048", AlgorithmConstants.KEYALGORITHM_RSA,
                SecConst.TOKEN_SOFT_JKS, false, false, false, endEntityProfileId); 
        
        verifyGeneratedKeystore(testCase, encodedKeyStore, lastCreatedUser, permittedNCUpdated, excludedNCUpdated, false);
        endEntityManagementSession.deleteUser(admin, lastCreatedUser.getUsername());
        lastCreatedUser = null;
        return;
    }
    
    private boolean createAndVerifyEndEntity(String testCase, List<String> permittedNCs, List<String> excludedNCs,
            int endEntityProfileId, int endEntityCertificateProfileId,
            boolean exceptionOnEndEntityCreationExpected,
            boolean exceptionOnKeyStoreCreationExpected,
            boolean isCriticalNameConstraint) throws Exception {
        return createAndVerifyEndEntity(testCase, permittedNCs, excludedNCs, endEntityProfileId, 
                endEntityCertificateProfileId, exceptionOnEndEntityCreationExpected, 
                exceptionOnKeyStoreCreationExpected, 
                isCriticalNameConstraint, false);
    }
    
    /**
     * Always same end entity certificate profile id and end entity profile id is used.
     * Name constraints are formatted before hand.
     */
    private boolean createAndVerifyEndEntity(String testCase, List<String> permittedNCs, List<String> excludedNCs,
            int endEntityProfileId, int endEntityCertificateProfileId,
            boolean exceptionOnEndEntityCreationExpected,
            boolean exceptionOnKeyStoreCreationExpected,
            boolean isCriticalNameConstraint,
            boolean retainUser) throws Exception {
        
        String endEntityName = getRandomizedName(TEST_NC_END_ENTITY_NAME);
        String endEntityDomain = getRandomizedName(TEST_NC_END_ENTITY_DN);
        EndEntityInformation createdUser = null;
        
        EndEntityInformation user = new EndEntityInformation(endEntityName, endEntityDomain, rootCaId, null,
                null, new EndEntityType(EndEntityTypes.ENDUSER), 
                endEntityProfileId, endEntityCertificateProfileId, EndEntityConstants.TOKEN_SOFT_JKS, null);
        user.setStatus(EndEntityConstants.STATUS_NEW); 
        user.setPassword(TEST_NC_EE_PASSWORD);
        ExtendedInformation extendedInfo = new ExtendedInformation();
        extendedInfo.setNameConstraintsPermitted(permittedNCs);
        extendedInfo.setNameConstraintsExcluded(excludedNCs);
        extendedInfo.setCertificateEndTime("2y");
        user.setExtendedInformation(extendedInfo);
        
        try {
            createdUser = endEntityManagementSession.addUser(admin, user, false);
            log.info("Check end entity " + endEntityName + " exists: " + 
                                endEntityManagementSession.existsUser(endEntityName));
        } catch (Exception e) {
             if(!exceptionOnEndEntityCreationExpected) {
                 log.error("Unexpected error during end entity creation during " + testCase, e);
                 return false;
             }
             log.info("Expected error during end entity creation during " + testCase);
             return true;
        }
        if(exceptionOnEndEntityCreationExpected) {
            log.error("Expected error did not happen during end entity creation during " + testCase);
            return false;
        }
        
        
        byte[] encodedKeyStore = null;
        try {
            encodedKeyStore = keyStoreCreateSessionBean.generateOrKeyRecoverTokenAsByteArray(admin, 
                createdUser.getUsername(),  createdUser.getPassword(), createdUser.getCAId(), 
                "2048", AlgorithmConstants.KEYALGORITHM_RSA, SecConst.TOKEN_SOFT_JKS, 
                false, false, false, endEntityProfileId);
        } catch (Exception e) {
            if(exceptionOnKeyStoreCreationExpected) {
                log.info("Expected error during end entity key store creation during " + testCase);
                return true;
            }
            log.error("Expected error did not happen during end entity key store creation during " + testCase);
        }
        Assert.assertNotNull("Unable to create key store during " + testCase, encodedKeyStore);
        
        verifyGeneratedKeystore(testCase, encodedKeyStore, user, permittedNCs, excludedNCs, isCriticalNameConstraint);
        
        if(retainUser)
            lastCreatedUser = user;
        else
            endEntityManagementSession.deleteUser(admin, user.getUsername());

        return true;
        
    }
    
    private void verifyGeneratedKeystore(String testCase, byte[] encodedKeyStore, EndEntityInformation user,
            List<String> permittedNCs, List<String> excludedNCs, boolean isCriticalNameConstraint) throws Exception {
        
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(encodedKeyStore);

            java.security.KeyStore keyStore = java.security.KeyStore.getInstance("JKS");
            keyStore.load(byteArrayInputStream, user.getPassword().toCharArray());
            Assert.assertNotNull("Unable to create key store during " + testCase, keyStore);
            
            Enumeration<String> aliases = keyStore.aliases();
            String alias = aliases.nextElement();
            Certificate eeCert = keyStore.getCertificate(alias);
            if (CertTools.isSelfSigned(eeCert)) {
                alias = aliases.nextElement();
                eeCert = keyStore.getCertificate(alias);
            }
            log.trace("Subject DN in retrieved cert: " + CertTools.getSubjectDN(eeCert));
            log.trace("Subject DN in user: " + user.getDN());
            Assert.assertEquals("Mismatch in end entity subject DN: ", CertTools.getSubjectDN(eeCert), user.getDN());
            
            assertNameConstraint(testCase, permittedNCs, excludedNCs, eeCert, isCriticalNameConstraint);
            keyStore.getKey(alias, TEST_NC_EE_PASSWORD.toCharArray());
                    
    }
    
    private void assertNameConstraint(String testCase, List<String> permittedNCs, List<String> excludedNCs, 
            Certificate certificate, boolean assertCritical) throws Exception {
        
        X509CertificateHolder x509Cert = new X509CertificateHolder(certificate.getEncoded());
        boolean nameConstraintsFound = false;
        for(int i=0; i<x509Cert.getExtensionOIDs().size(); i++) {
            Extension x509Extension = x509Cert.getExtension((ASN1ObjectIdentifier)x509Cert.getExtensionOIDs().get(i));
            
            if(x509Extension.getExtnId() == Extension.nameConstraints) {
                
                final byte[] ncbytes = x509Extension.getExtnValue().getEncoded();
                final ASN1OctetString ncstr = (ncbytes != null ? DEROctetString.getInstance(ncbytes) : null);
                final ASN1Sequence ncseq = (ncbytes != null ? DERSequence.getInstance(ncstr.getOctets()) : null);
                final NameConstraints nc = (ncseq != null ? NameConstraints.getInstance(ncseq) : null);
                                
                GeneralSubtree[] permittedExpected = NameConstraint.toGeneralSubtrees(permittedNCs);
                GeneralSubtree[] excludedExpected = NameConstraint.toGeneralSubtrees(excludedNCs);

                NameConstraints ncExpected = new NameConstraints(permittedExpected, excludedExpected);
                if(ncExpected.equals(nc)) {
                    if(assertCritical)
                        Assert.assertTrue("Name constraints are not considered critical.", 
                                x509Cert.getCriticalExtensionOIDs().contains(Extension.nameConstraints));
                    else
                        Assert.assertFalse("Name constraints are considered critical.", 
                                x509Cert.getCriticalExtensionOIDs().contains(Extension.nameConstraints));
                } else {
                    ASN1InputStream is = new ASN1InputStream(x509Extension.getExtnValue().getOctetStream());
                    ASN1Primitive p;
                    while ((p = is.readObject()) != null) {
                        log.error("Mismatched name constraints. Fetched name constraints from certificate: " 
                                        + ASN1Dump.dumpAsString(p));
                    }
                }
                Assert.assertTrue("Expected name constraint did not match during " + testCase, ncExpected.equals(nc));
                nameConstraintsFound = true;
            }
        }
        
        log.info("Asserted name constraints");
        if((permittedNCs==null || permittedNCs.size()==0) && 
                (excludedNCs==null || excludedNCs.size()==0)) {
            Assert.assertFalse("Unexpected name constraints are included.", nameConstraintsFound);
            return;
        }
        
        if(!nameConstraintsFound) {
            log.error("Name constraint not found in certificate during " + testCase);
            Assert.fail("Name constraint not found in certificate during " + testCase);
        }
    }
    
    @Test
    public void testA_RootCaCertificateNameConstraints() throws Exception {
        
        String testCase = "testRootCaCertificateNameConstraints";
        log.info("Running: " + testCase);
        CAInfo cainfo = caSession.getCAInfo(admin, TEST_NC_ROOT_CA_NAME);
        
        Assert.assertEquals("Expected root certificate chain length is 1.", cainfo.getCertificateChain().size(), 1);
        assertNameConstraint(testCase, formatedNCPermitted, formatedNCExcluded, cainfo.getCertificateChain().get(0), false);
    }
    
    
    @Test
    public void testRootCaCreateWithDisabledNameConstraintInRootCertProfile() throws Exception {
        
        log.info("Running: testRootCaCreateWithDisabledNameConstraintInRootCertProfile");
        
        // create root cert profile without NC
        String dummyProfileName = getRandomizedName(TEST_NC_CERT_PROFILE_DUMMY);
        CertificateProfile dummyProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
        dummyProfile.setUseNameConstraints(false);
        int dummyProfileId = certProfileSession.addCertificateProfile(admin, dummyProfileName, dummyProfile);
        log.info("created root certificate profile with disabled name constraint id: " + dummyProfileId);
        
        // create root CA with NC - NEG
        String dummyCAName = getRandomizedName(TEST_NC_EE_DUMMY_PROFILE_NAME);
        int dummyCAId = 0;
        try {
            dummyCAId = CaTestCase.createTestCA(dummyCAName, 4096, getRandomizedName(TEST_NC_DUMMY_CA_DN), 
                    CAInfo.SELFSIGNED, null, dummyProfileId, 
                    formatedNCPermitted, formatedNCExcluded, true, true);
            log.error("Root CA created without name constraint enabled in certificate profile id: " + dummyCAId);
        } catch (Exception e) {
            log.info("Root CA creation failed as expected without name constraint enabled in certificate profile.");
        } 
        
        if(dummyCAId!=0)
            CaTestCase.removeTestCA(dummyCAName);
        Assert.assertEquals("Root CA profile created with name constraint "
                + "without name constraint enabled in certificate profile", dummyCAId, 0);
        
        // create Root CA without name constraint
        dummyCAName = getRandomizedName(TEST_NC_DUMMY_CA_NAME);
        dummyCAId = 0;
        try {
            dummyCAId = CaTestCase.createTestCA(dummyCAName, 4096, getRandomizedName(TEST_NC_DUMMY_CA_DN), 
                    CAInfo.SELFSIGNED, null, dummyProfileId, 
                    null, null, true, true);
            log.info("Root CA created without name constraint enabled in certificate profile id: " + dummyCAId);
        } catch (Exception e) {
            log.error("Root CA without name constraint creation failed without name constraint enabled in certificate profile.");
        } 
        
        if(dummyCAId!=0)
            CaTestCase.removeTestCA(dummyCAName);
        certProfileSession.removeCertificateProfile(admin, dummyProfileName);
        Assert.assertNotEquals("Root CA profile creation failed without name constraint "
                + "without name constraint enabled in certificate profile", dummyCAId, 0);
        
    }
    
    @Test
    public void testEndEntityCreateWithDisabledNameConstraintInEndEntityCertProfile() throws Exception {
        
        String testCase = "testEndEntityCreateWithDisabledNameConstraintInEndEntityCertProfile";
        log.info("Running: " + testCase);
        
        // create EE cert profile without NC
        String dummyProfileName = getRandomizedName(TEST_NC_CERT_PROFILE_DUMMY);
        CertificateProfile dummyProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        dummyProfile.setUseNameConstraints(false);
        int dummyProfileId = certProfileSession.addCertificateProfile(admin, dummyProfileName, dummyProfile);
        log.info("created end entity certificate profile with disabled name constraint id: " + dummyProfileId);
        
        // create end entity profile
        String dummyEEProfileName = getRandomizedName(TEST_NC_CERT_PROFILE_DUMMY);
        EndEntityProfile endEntityProfile = new EndEntityProfile();
        endEntityProfile.setNameConstraintsPermittedUsed(true);
        endEntityProfile.setNameConstraintsPermittedRequired(false);
        endEntityProfile.setNameConstraintsExcludedUsed(true);
        endEntityProfile.setNameConstraintsExcludedRequired(false);
        List<Integer> availableCertProfiles = endEntityProfile.getAvailableCertificateProfileIds();
        availableCertProfiles.add(dummyProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(availableCertProfiles);
        endEntityProfile.setAvailableCAs(Arrays.asList(new Integer[]{SecConst.ALLCAS}));
        
        int endEntityProfileId = endEntityProfileSession.addEndEntityProfile(admin, dummyEEProfileName, endEntityProfile);
        log.info("Created end entity profile id: " + endEntityProfileId);
        
        // create EE with NC - NEG
        boolean resultEndEntityCreateWithNC = createAndVerifyEndEntity(testCase, formatedNCPermitted, null, 
                                endEntityProfileId, dummyProfileId, false, true, false);
        
               
        // create Root CA without name constraint
        boolean resultEndEntityCreateWithoutNC = createAndVerifyEndEntity(testCase, null, null, 
                endEntityProfileId, dummyProfileId, false, false, false);

        endEntityProfileSession.removeEndEntityProfile(admin, dummyEEProfileName);
        certProfileSession.removeCertificateProfile(admin, dummyProfileName);
        Assert.assertTrue("End entiy creation failed without name constraint.", resultEndEntityCreateWithoutNC);
        Assert.assertTrue("End entiy created with name constraint with disabled at certificate profile.", 
                                    resultEndEntityCreateWithNC);
        
    }
    
    @Test
    public void testEndEntityWithCriticalNameConstraintInEndEntityCertProfile() throws Exception {
        
        String testCase = "testEndEntityWithCriticalNameConstraintInEndEntityCertProfile ";
        log.info("Running: " + testCase);
        
        // update EE certificate profile with critical NC
        endEntityCertprofile.setNameConstraintsCritical(true);
        certProfileSession.changeCertificateProfile(admin, TEST_NC_CERT_PROFILE_EE, endEntityCertprofile);
        
        // generate EE
        createAndVerifyEndEntity(testCase, formatedNCPermitted, formatedNCExcluded, 
                endEntityProfileId, endEntityCertificateProfileId, false, false, true);
                
        // reset critical NC at EE certificate profile
        endEntityCertprofile.setNameConstraintsCritical(false);
        certProfileSession.changeCertificateProfile(admin, TEST_NC_CERT_PROFILE_EE, endEntityCertprofile);
        
    }
    
    @Test
    public void testRootCARenewWithCriticalNameConstraintInRootCertProfile() throws Exception {
        
        String testCase = "testRootCAWithCriticalNameConstraintInRootCertProfile";
        log.info("Running: " + testCase);
        
        // update Root certificate profile with critical NC
        rootCertProfile.setNameConstraintsCritical(true);
        certProfileSession.changeCertificateProfile(admin, TEST_NC_CERT_PROFILE_ROOT, rootCertProfile);
        
        // renew root CA with additional NCs
        List<String> formatedNCPermittedUpdated = new ArrayList<String>(formatedNCPermitted);
        List<String> formatedNCExcludedUpdated = new ArrayList<String>(formatedNCExcluded);
        formatedNCPermittedUpdated.remove(0);
        formatedNCExcludedUpdated.add(NameConstraint.parseNameConstraintEntry("addexclusion.check.com"));
        
        // update root CA
        log.info("updating root CA: " + TEST_NC_ROOT_CA_NAME);
        X509CAInfo cainfo = (X509CAInfo) caSession.getCAInfo(admin, TEST_NC_ROOT_CA_NAME);
        cainfo.setNameConstraintsPermitted(formatedNCPermittedUpdated);
        cainfo.setNameConstraintsExcluded(formatedNCExcludedUpdated);
        caAdminSession.editCA(admin, cainfo);
        
        // verify no change in certificate
        CAInfo cainfoRefetched = caSession.getCAInfo(admin, TEST_NC_ROOT_CA_NAME);
        log.info("Refetched root CA id by name: " + cainfo.getCAId());
        Assert.assertEquals("Expected root certificate chain length is 1.", 
                                cainfoRefetched.getCertificateChain().size(), 1);
        assertNameConstraint("Verify renewed root CA", formatedNCPermitted, formatedNCExcluded, 
                                cainfoRefetched.getCertificateChain().get(0), false);
        
        // renew CA and verify updated certificate
        caAdminSession.renewCA(admin, rootCaId, false, null, true);
        CAInfo cainfoRenewed = caSession.getCAInfo(admin, TEST_NC_ROOT_CA_NAME);
        
        Assert.assertEquals("Expected root certificate chain length is 1.", cainfoRenewed.getCertificateChain().size(), 1);
        assertNameConstraint("Verify renewed root CA", formatedNCPermittedUpdated, formatedNCExcludedUpdated, 
              cainfoRenewed.getCertificateChain().get(0), true);
        
        // reset critical NC at root certificate profile
        rootCertProfile.setNameConstraintsCritical(false);
        certProfileSession.changeCertificateProfile(admin, TEST_NC_CERT_PROFILE_ROOT, rootCertProfile);
        
    }
    
    @Test
    public void testCreateAndRenewSubCAWithNameConstraint() throws Exception {
        
        String testCase = "testCreateAndRenewSubCAWithNameConstraint";
        log.info("Running: " + testCase);
        
         // generate subca with NC
        String subCAName = getRandomizedName(TEST_NC_SUB_CA_NAME);
        String subCADomain = getRandomizedName(TEST_NC_SUB_CA_DN);
        createdSubCas.add(subCAName);
        
        List<String> formatedNCPermittedUpdated = new ArrayList<String>();
        List<String> formatedNCExcludedUpdated = new ArrayList<String>();
        formatedNCPermittedUpdated.addAll(formatedNCPermitted);
        formatedNCExcludedUpdated.addAll(formatedNCExcluded);
        formatedNCPermittedUpdated.remove(0);
        formatedNCPermittedUpdated.add(NameConstraint.parseNameConstraintEntry("addpermitted.check.com"));
        formatedNCExcludedUpdated.add(NameConstraint.parseNameConstraintEntry("addexclusion.check.com"));
        
        log.info("adding sub CA: " + subCAName);
        int subCaId = CaTestCase.createTestCA(subCAName, 4096, subCADomain, 
                rootCaId, null, subCaCertificateProfileId, 
                formatedNCPermittedUpdated, formatedNCExcludedUpdated, true, true);
        log.info("sub CA id: " + subCaId);
            
         // verify same NC
        CAInfo subCaInfo = caSession.getCAInfo(admin, subCAName);
        Assert.assertEquals("Expected sub ca certificate chain length is 2.", subCaInfo.getCertificateChain().size(), 2);
        assertNameConstraint(testCase, formatedNCPermittedUpdated, formatedNCExcludedUpdated, 
                subCaInfo.getCertificateChain().get(0), false);
    
            
         // update subca
        formatedNCPermittedUpdated.add(NameConstraint.parseNameConstraintEntry("addpermitted2.check.com"));
        formatedNCExcludedUpdated.remove(0);
        formatedNCExcludedUpdated.add(NameConstraint.parseNameConstraintEntry("addexclusion2.check.com"));
        log.info("updating sub CA: " + subCAName);
        X509CAInfo cainfo = (X509CAInfo) caSession.getCAInfo(admin, subCAName);
        cainfo.setNameConstraintsPermitted(formatedNCPermittedUpdated);
        cainfo.setNameConstraintsExcluded(formatedNCExcludedUpdated);
        caAdminSession.editCA(admin, cainfo);
        
        // renew subca
        caAdminSession.renewCA(admin, subCaId, false, null, true);
        CAInfo cainfoRenewed = caSession.getCAInfo(admin, subCAName);
        
        Assert.assertEquals("Expected sub ca certificate chain length is 2.", cainfoRenewed.getCertificateChain().size(), 2);
        assertNameConstraint(testCase, formatedNCPermittedUpdated, formatedNCExcludedUpdated, 
                cainfoRenewed.getCertificateChain().get(0), false);
          
        
    }
    
    @Test
    public void testCreateAndRenewSubCAWithoutNameConstraint() throws Exception {
        
        String testCase = "testCreateAndRenewSubCAWithoutNameConstraint";
        log.info("Running: " + testCase);
        
        // generate subca without NC
        String subCAName = getRandomizedName(TEST_NC_SUB_CA_NAME);
        String subCADomain = getRandomizedName(TEST_NC_SUB_CA_DN);
        createdSubCas.add(subCAName);
        
        log.info("adding sub CA: " + subCAName);
        int subCaId = CaTestCase.createTestCA(subCAName, 4096, subCADomain, 
                rootCaId, null, subCaCertificateProfileId, null, null, true, true);
        log.info("sub CA id: " + subCaId);
            
         // verify same NC
        CAInfo subCaInfo = caSession.getCAInfo(admin, subCAName);
        Assert.assertEquals("Expected sub ca certificate chain length is 2.", subCaInfo.getCertificateChain().size(), 2);
        assertNameConstraint(testCase, null, null, 
                subCaInfo.getCertificateChain().get(0), false);
        
        // renew subca
        caAdminSession.renewCA(admin, subCaId, false, null, true);
        CAInfo cainfoRenewed = caSession.getCAInfo(admin, subCAName);
        
        Assert.assertEquals("Expected sub ca certificate chain length is 2.", cainfoRenewed.getCertificateChain().size(), 2);
        assertNameConstraint(testCase, null, null, 
                cainfoRenewed.getCertificateChain().get(0), false);
                
        // disable NC at subca profile
        subCaCertprofile.setUseNameConstraints(false);
        certProfileSession.changeCertificateProfile(admin, TEST_NC_CERT_PROFILE_SUBCA, subCaCertprofile);
        
        // generate subca with NC - NEG
        subCAName = getRandomizedName(TEST_NC_SUB_CA_NAME);
        subCADomain = getRandomizedName(TEST_NC_SUB_CA_DN);
        
        log.info("trying to sub CA with NC with disabled NC at certificate profile: " + subCAName);
        boolean createdIncompatibleSubCA = false;
        try {
            CaTestCase.createTestCA(subCAName, 4096, subCADomain, 
                rootCaId, null, subCaCertificateProfileId, 
                formatedNCPermitted, formatedNCExcluded, true, true);
            createdIncompatibleSubCA = true;
            createdSubCas.add(subCAName);
        } catch(Exception e) {
            log.info("Sub CA with NC enabled creation failed with incompatible certificate profile.");
        }
        
        // RESET - enable NC at subca profile
        subCaCertprofile.setUseNameConstraints(true);
        certProfileSession.changeCertificateProfile(admin, TEST_NC_CERT_PROFILE_SUBCA, subCaCertprofile);
        
        Assert.assertFalse("Created Sub CA with NC enabled with NC disbaled at certificate profile.", 
                createdIncompatibleSubCA);
        
    }
    
    @Test
    public void testEndEntityNameConstraintsPermitted() throws Exception {
        
        log.trace("running: testEndEntityNameConstraintsPermitted");
        createAndRenewEndEntityVerified("EndEntityNameConstraintsPermitted", formatedNCPermitted, null);
        
    }
    
    @Test
    public void testEndEntityNameConstraintsExcluded() throws Exception {
        
        log.trace("running: testEndEntityNameConstraintsExcluded");
        createAndRenewEndEntityVerified("EndEntityNameConstraintsPermitted", null, formatedNCExcluded);
        
    }
    
    @Test
    public void testEndEntityNameConstraintsBoth() throws Exception {
        
        log.trace("running: testEndEntityNameConstraintsBoth");
        createAndRenewEndEntityVerified("EndEntityNameConstraintsPermitted", formatedNCPermitted, formatedNCExcluded);
        
    }
    
    @Test
    public void testEndEntityCertPermittedDomainNameInRootCA() throws Exception {
        
        String dummyCAName = getRandomizedName(TEST_NC_DUMMY_CA_NAME);
        int dummyCAId = 0;
        List<String> permittedNCs = new ArrayList<String> (formatedNCPermitted);
        permittedNCs.add(NameConstraint.parseNameConstraintEntry("CN=primeKey.com"));
        
        try {
            dummyCAId = CaTestCase.createTestCA(dummyCAName, 4096, getRandomizedName(TEST_NC_DUMMY_CA_DN), 
                    CAInfo.SELFSIGNED, null, rootCertificateProfileId, 
                    permittedNCs, null, true, true);
            log.error("Root CA created without name constraint enabled in certificate profile id: " + dummyCAId);
        } catch (Exception e) {
            log.info("Root CA creation failed as expected without name constraint enabled in certificate profile.");
        } 
        
        // EE with same CN only
        String endEntityName = getRandomizedName(TEST_NC_END_ENTITY_NAME);
        String endEntityDomain = "CN=primeKey.com";
        
        EndEntityInformation user = new EndEntityInformation(endEntityName, endEntityDomain, dummyCAId, null,
                null, new EndEntityType(EndEntityTypes.ENDUSER), 
                endEntityProfileId, endEntityCertificateProfileId, EndEntityConstants.TOKEN_SOFT_JKS, null);
        user.setStatus(EndEntityConstants.STATUS_NEW); 
        user.setPassword(TEST_NC_EE_PASSWORD);        
        user = endEntityManagementSession.addUser(admin, user, false);
        endEntityManagementSession.deleteUser(admin, user.getUsername());
                
        // EE with different CN
        endEntityName = getRandomizedName(TEST_NC_END_ENTITY_NAME);
        endEntityDomain = "CN=notprimeKey.com";
        
        user = new EndEntityInformation(endEntityName, endEntityDomain, dummyCAId, null,
                null, new EndEntityType(EndEntityTypes.ENDUSER), 
                endEntityProfileId, endEntityCertificateProfileId, EndEntityConstants.TOKEN_SOFT_JKS, null);
        user.setStatus(EndEntityConstants.STATUS_NEW); 
        user.setPassword(TEST_NC_EE_PASSWORD);
        try {
            endEntityManagementSession.addUser(admin, user, false);
            Assert.fail("Successfully created end entity for different domain than permitted in root CA.");
        } catch(Exception e) {
            
        }
        
        CaTestCase.removeTestCA(dummyCAName);
        
    }
    
    @Test
    public void testEndEntityCertPermittedDomainNameInRootCA2() throws Exception {
        
        String dummyCAName = getRandomizedName(TEST_NC_DUMMY_CA_NAME);
        int dummyCAId = 0;
        List<String> permittedNCs = new ArrayList<String> (formatedNCPermitted);
        permittedNCs.add(NameConstraint.parseNameConstraintEntry("C=SE,CN=primeKey.com"));
        
        try {
            dummyCAId = CaTestCase.createTestCA(dummyCAName, 4096, getRandomizedName(TEST_NC_DUMMY_CA_DN), 
                    CAInfo.SELFSIGNED, null, rootCertificateProfileId, 
                    permittedNCs, null, true, true);
            log.error("Root CA created without name constraint enabled in certificate profile id: " + dummyCAId);
        } catch (Exception e) {
            log.info("Root CA creation failed as expected without name constraint enabled in certificate profile.");
        } 
        
//        endEntityProfile.addField(DnComponents.COUNTRY);
//        endEntityProfileSession.changeEndEntityProfile(admin, TEST_NC_EE_PROFILE_NAME, endEntityProfile);
        
        // EE with same CN only
        String endEntityName = getRandomizedName(TEST_NC_END_ENTITY_NAME);
        String endEntityDomain = "C=SE,CN=primeKey.com";
        
        EndEntityInformation user = new EndEntityInformation(endEntityName, endEntityDomain, dummyCAId, null,
                null, new EndEntityType(EndEntityTypes.ENDUSER), 
                endEntityProfileId, endEntityCertificateProfileId, EndEntityConstants.TOKEN_SOFT_JKS, null);
        user.setStatus(EndEntityConstants.STATUS_NEW); 
        user.setPassword(TEST_NC_EE_PASSWORD);        
        user = endEntityManagementSession.addUser(admin, user, false);
        endEntityManagementSession.deleteUser(admin, user.getUsername());
                
        // EE with different CN
        endEntityName = getRandomizedName(TEST_NC_END_ENTITY_NAME);
        endEntityDomain = "C=AU,CN=primeKey.com";
        
        user = new EndEntityInformation(endEntityName, endEntityDomain, dummyCAId, null,
                null, new EndEntityType(EndEntityTypes.ENDUSER), 
                endEntityProfileId, endEntityCertificateProfileId, EndEntityConstants.TOKEN_SOFT_JKS, null);
        user.setStatus(EndEntityConstants.STATUS_NEW); 
        user.setPassword(TEST_NC_EE_PASSWORD);
        try {
            endEntityManagementSession.addUser(admin, user, false);
            Assert.fail("Successfully created end entity for different domain than permitted in root CA.");
        } catch(Exception e) {
            
        }
        
        CaTestCase.removeTestCA(dummyCAName);
        
    }
    
    @Test
    public void testEndEntityCertExcludedDomainNameInRootCA() throws Exception {
        
        String dummyCAName = getRandomizedName(TEST_NC_DUMMY_CA_NAME);
        int dummyCAId = 0;
        List<String> excludedNCs = new ArrayList<String> (formatedNCPermitted);
        excludedNCs.add(NameConstraint.parseNameConstraintEntry("CN=primeKey.com"));
        
        try {
            dummyCAId = CaTestCase.createTestCA(dummyCAName, 4096, getRandomizedName(TEST_NC_DUMMY_CA_DN), 
                    CAInfo.SELFSIGNED, null, rootCertificateProfileId, 
                    null, excludedNCs, true, true);
            log.error("Root CA created without name constraint enabled in certificate profile id: " + dummyCAId);
        } catch (Exception e) {
            log.info("Root CA creation failed as expected without name constraint enabled in certificate profile.");
        } 
        
        // EE with different CN
        String endEntityName = getRandomizedName(TEST_NC_END_ENTITY_NAME);
        String endEntityDomain = "CN=notprimeKey.com";
        
        EndEntityInformation user = new EndEntityInformation(endEntityName, endEntityDomain, dummyCAId, null,
                null, new EndEntityType(EndEntityTypes.ENDUSER), 
                endEntityProfileId, endEntityCertificateProfileId, EndEntityConstants.TOKEN_SOFT_JKS, null);
        user.setStatus(EndEntityConstants.STATUS_NEW); 
        user.setPassword(TEST_NC_EE_PASSWORD);        
        user = endEntityManagementSession.addUser(admin, user, false);
        endEntityManagementSession.deleteUser(admin, user.getUsername());
        
        // EE with same CN
        endEntityName = getRandomizedName(TEST_NC_END_ENTITY_NAME);
        endEntityDomain = "CN=primeKey.com";
        
        user = new EndEntityInformation(endEntityName, endEntityDomain, dummyCAId, null,
                null, new EndEntityType(EndEntityTypes.ENDUSER), 
                endEntityProfileId, endEntityCertificateProfileId, EndEntityConstants.TOKEN_SOFT_JKS, null);
        user.setStatus(EndEntityConstants.STATUS_NEW); 
        user.setPassword(TEST_NC_EE_PASSWORD);
        try {
            endEntityManagementSession.addUser(admin, user, false);
            Assert.fail("Successfully created end entity for a domain than forbidden in root CA.");
        } catch(Exception e) {
            
        }
        
        CaTestCase.removeTestCA(dummyCAName);
        
    }
    
    @Test
    public void testEndEntityCertExcludedDomainNameInRootCA2() throws Exception {
        
        String dummyCAName = getRandomizedName(TEST_NC_DUMMY_CA_NAME);
        int dummyCAId = 0;
        List<String> excludedNCs = new ArrayList<String> (formatedNCPermitted);
        excludedNCs.add(NameConstraint.parseNameConstraintEntry("C=SE,CN=primeKey.com"));
        
        try {
            dummyCAId = CaTestCase.createTestCA(dummyCAName, 4096, getRandomizedName(TEST_NC_DUMMY_CA_DN), 
                    CAInfo.SELFSIGNED, null, rootCertificateProfileId, 
                    null, excludedNCs, true, true);
            log.error("Root CA created without name constraint enabled in certificate profile id: " + dummyCAId);
        } catch (Exception e) {
            log.info("Root CA creation failed as expected without name constraint enabled in certificate profile.");
        } 
        
        // EE with different CN
        String endEntityName = getRandomizedName(TEST_NC_END_ENTITY_NAME);
        String endEntityDomain = "C=AU,CN=primeKey.com";
        
        EndEntityInformation user = new EndEntityInformation(endEntityName, endEntityDomain, dummyCAId, null,
                null, new EndEntityType(EndEntityTypes.ENDUSER), 
                endEntityProfileId, endEntityCertificateProfileId, EndEntityConstants.TOKEN_SOFT_JKS, null);
        user.setStatus(EndEntityConstants.STATUS_NEW); 
        user.setPassword(TEST_NC_EE_PASSWORD);        
        user = endEntityManagementSession.addUser(admin, user, false);
        endEntityManagementSession.deleteUser(admin, user.getUsername());
        
        // EE with same CN
        endEntityName = getRandomizedName(TEST_NC_END_ENTITY_NAME);
        endEntityDomain = "C=SE,CN=primeKey.com";
        
        user = new EndEntityInformation(endEntityName, endEntityDomain, dummyCAId, null,
                null, new EndEntityType(EndEntityTypes.ENDUSER), 
                endEntityProfileId, endEntityCertificateProfileId, EndEntityConstants.TOKEN_SOFT_JKS, null);
        user.setStatus(EndEntityConstants.STATUS_NEW); 
        user.setPassword(TEST_NC_EE_PASSWORD);
        try {
            endEntityManagementSession.addUser(admin, user, false);
            Assert.fail("Successfully created end entity for a domain than forbidden in root CA.");
        } catch(Exception e) {
            
        }
        
        CaTestCase.removeTestCA(dummyCAName);
        
    }
    
    private EndEntityInformation createEndEntityWithNameConstraintAndUserGeneratedToken() throws Exception {

        String endEntityName = getRandomizedName(TEST_NC_END_ENTITY_NAME);
        String endEntityDomain = getRandomizedName(TEST_NC_END_ENTITY_DN);
        
        EndEntityInformation user = new EndEntityInformation(endEntityName, endEntityDomain, rootCaId, null,
                null, new EndEntityType(EndEntityTypes.ENDUSER), 
                endEntityProfileId, endEntityCertificateProfileId, EndEntityConstants.TOKEN_USERGEN, null);
        user.setStatus(EndEntityConstants.STATUS_NEW); 
        user.setPassword(TEST_NC_EE_PASSWORD);
        ExtendedInformation extendedInfo = new ExtendedInformation();
        extendedInfo.setNameConstraintsPermitted(formatedNCPermitted);
        extendedInfo.setNameConstraintsExcluded(formatedNCExcluded);
        extendedInfo.setCertificateEndTime("2y");
        user.setExtendedInformation(extendedInfo);
        
        user = endEntityManagementSession.addUser(admin, user, false);
        return user;
    }
    
    private RequestMessage prepareRequestMessage(String csr, EndEntityInformation user) {
        RequestMessage req;
        req = RequestMessageUtils.parseRequestMessage(csr.getBytes());
        req.setUsername(user.getUsername());
        req.setPassword(user.getPassword());
        Date expDate = new Date();
        Calendar c = Calendar.getInstance();
        c.setTime(expDate);
        c.add(Calendar.YEAR, 2);
        expDate = c.getTime();
        req.setRequestValidityNotAfter(expDate);
        return req;
    }
    
    @Test
    public void testUploadedCRLAgainstEndEntityNameConstraintDifferentNCinCSR() throws Exception {
        
        EndEntityInformation user = createEndEntityWithNameConstraintAndUserGeneratedToken();
        
        // upload CRL with different NC
        RequestMessage req = prepareRequestMessage(csrDiferentNC, user);
        
        ResponseMessage resp = signSession.createCertificate(admin, req, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), Certificate.class);
        assertNameConstraint("", formatedNCPermitted, formatedNCExcluded, cert, false);
        
        endEntityManagementSession.deleteUser(admin, user.getUsername());
        
    }
    
    @Test
    public void testUploadedCRLAgainstEndEntityNameConstraintNoNCinCSR() throws Exception {
        
        EndEntityInformation user = createEndEntityWithNameConstraintAndUserGeneratedToken();
        
        RequestMessage req = prepareRequestMessage(csrNoNC, user);
        
        ResponseMessage resp = signSession.createCertificate(admin, req, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), Certificate.class);
        assertNameConstraint("", formatedNCPermitted, formatedNCExcluded, cert, false);
        
        endEntityManagementSession.deleteUser(admin, user.getUsername());
        
    }
    
    String csrDiferentNC = "-----BEGIN CERTIFICATE REQUEST-----\n"
            + "MIIC8zCCAdsCAQAwVjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx\n"
            + "ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEPMA0GA1UEAwwGdHJ5\n"
            + "TkMzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw7aweI8CFWiN1A9e\n"
            + "p96eYVvL2TlhUqiXoRzEn65rNrJrHagX2NROqe9D4oDFBjjHhtiYwDuHRXx11xUD\n"
            + "R4MHUGXnXKFf4MRxzMlDLcL/q+ZgCUYyWWoZ+lPgAg7GQgm0GCEQO2oU0zweue58\n"
            + "2ojqtyZ67hxYvOqsi7ml4oEmCLhOEB5u8l7IrV/lsJgZ4jBAmlYf0y1v3tpnQbBc\n"
            + "5z2HKtO887+AkdmAnXzQLyuAQehzyV6/ULQh/qVIy0sJOgkNlgCVKv+vGVI18J6s\n"
            + "B2Iv9xa/h9KFZJsFwmDCYsv0zY+OvubnH/r7JNYBTG6ObiUjbVafzmrSMlC9bW6U\n"
            + "XQzGkwIDAQABoFgwVgYJKoZIhvcNAQkOMUkwRzBFBgNVHR4EPjA8oDowOIE2ZXht\n"
            + "ZXhjLmNvbSBuYW1lQ29uc3RyYWludHM9cGVybWl0dGVkO2VtYWlsOmV4bWluYzIu\n"
            + "Y29tMA0GCSqGSIb3DQEBCwUAA4IBAQAuONEJ6xBfHLsApUV8ICXy3xV4Gq1/E2Zl\n"
            + "G+MopEd1rNw/FrGhESt8cWU0JeAleQA0FIae9Nd+XL9r0I9YhNkjs8fYHYY7HAsx\n"
            + "kK2CpmqbVwE4FDwFlKx67uoY50A+Dbthe8RbQMnkEbynAA5ICeqfmD99JQsiBcjD\n"
            + "D5IP/1YJ7xMiMQ/yLp2sAahh59eBCDnBb1MTFRQRn6zCN5ANUKvl6W5d4DEDIkv8\n"
            + "CnsU1YdU+OjJzBw/zx/29+YBHi/JuLspgy/3MXymZzxLhmx0cZbJVJeQbZ/P40iz\n"
            + "1Bziuqu40swS0K9cVRf7FAqlNAka9dU26z06bLNmb4evrFWGqHOt\n"
            + "-----END CERTIFICATE REQUEST-----";
    
    String csrNoNC = "-----BEGIN CERTIFICATE REQUEST-----\n"
            + "MIICoTCCAYkCAQAwXDELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx\n"
            + "ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEVMBMGA1UEAwwMY2hl\n"
            + "Y2tOQzExMTExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGcAQb+r\n"
            + "tq711FO890av7eIYInzJ7MDSskxlV3RAWBqaeMjY2d4jwjVq5scEKakkT4oNfXRc\n"
            + "mjQBYkI+clHMroYKZluztkCec+XqruHzGyrwa1m1TM66wNT3RS0l8n8ZOYeDRaNx\n"
            + "7sWbjZuVQK3E2Fa6CcBJAysr7Rcg/r3W3sJIDpW1Uulqj4QZSOX4BUm6Pge6rg91\n"
            + "GSMhovD83TDvFEcnAqkOfyGROqyrVo79LFRVJkl22XwTW4nZCwPtE+dtB5eUmzkd\n"
            + "FW0fI4mVe5GLQHhz/hUZNmUvHPxz1BabjIxSoGoSdfIhRUVhV1TvGkYAF0Z9O8T3\n"
            + "kyO/F+ioj5RqbwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAClLOUFOAXWxemr8\n"
            + "WoGbBtNzkD268NF8tL15o/uAofAg6cJmi+1+FrPxqe4RmUSBUnztK0WY4KWxrqdK\n"
            + "4wXA0Bq3M0aYh3aC+/fp+M4fcvG7/VqmInHuA5R200Id1LyXa9MwLfygygiDqvyQ\n"
            + "hvf94hZ+s5T0py4IcO2jGIoX4suSv7PP9LzZPZMQ1QPNTqh/9p7jrmn3Ozh6psDf\n"
            + "q8LBUrD86sdCJt32lNRngXMVrjpnIMt9BKW/2dAr9zxftthSRDgY2W7m+jIEOu8C\n"
            + "duqrkQdiE09DcUE9r6xEK3l0kzZdwJM5uLEISH1AJOGB+iIFJqBFmwN/GxrRwCa4\n"
            + "EyOsab4=\n"
            + "-----END CERTIFICATE REQUEST-----";

}
