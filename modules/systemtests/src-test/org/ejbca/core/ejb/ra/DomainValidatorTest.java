/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.ra;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.KeyValidatorSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.validation.DomainAllowlistValidator;
import org.ejbca.core.model.validation.DomainBlacklistValidator;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DomainValidatorTest extends CaTestCase {
    
    private static final Logger log = Logger.getLogger(DomainValidatorTest.class);
    
    private static final String TEST_EEV_ROOT_CA_NAME = "testEEVRootCa";
    private static final String TEST_EEV_END_ENTITY_NAME = "testEEVEndEntity" + REPLACABLE_TAG;

    private static final String TEST_EEV_CERT_PROFILE_ROOT = "testEEVRootCertProfile";
    private static final String TEST_EEV_CERT_PROFILE_EE = "testEEVEndEntityCertProfile";    
    private static final String TEST_EEV_EE_PROFILE_NAME = "testEEVEndEntityProfile";
    
    private static final String TEST_EEV_EE_PASSWORD = "foo123";
    
    private static final String TEST_EEV_DOMAIN_ALLOW_VALIDATOR = "testDomainAllowValidator" + REPLACABLE_TAG;
    private static final String TEST_EEV_DOMAIN_BLOCK_VALIDATOR = "testDomainBlockValidator" + REPLACABLE_TAG;
        
    private static int rootCaId;
    private static int rootCertificateProfileId, endEntityCertificateProfileId;
    
    private static int domainAllowValidatorId, domainBlockValidatorId;
    private static String domainAllowValidatorName, domainBlockValidatorName;
    
    private static CertificateProfile rootCertProfile, endEntityCertprofile;
    private static EndEntityProfile endEntityProfile;
    private static int endEntityProfileId;
    
    private static List<String> createdUsers = new ArrayList<String>();
    
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EndEntityValidatorTest"));
    
    private static final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final CertificateProfileSessionRemote certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static final KeyStoreCreateSessionRemote keyStoreCreateSessionBean = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyStoreCreateSessionRemote.class);

    private static final KeyValidatorSessionRemote keyValidatorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyValidatorSessionRemote.class);

    private static String WHITELIST = "permit.com\n" + 
            "permit.example.com\n" + 
            "#good.example.com\n" + 
            "permit2.example.com # this is a comment\n" + 
            "    permit3.example.com     \n" + 
            "permit4.example.com# comment\n" + 
            "permit5.*.example.com\n" +
            "*.permit6.*.example.com\n" +
            "permit7.example.*\n" +
            "permit8.partial*.com\n" +
            "common.in.bothlist.com\n" +
            "\n";
    
    private static String BLACKLIST = "bank\n" + 
            "forbidden.example.com\n" + 
            "#good.example.com\n" + 
            "forbidden2.example.com # this is a comment\n" + 
            "    forbidden3.example.com     \n" + 
            "forbidden4.example.com# comment\n" +
            "common.in.bothlist.com\n" +
            "\n";
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
    
    @BeforeClass
    public static void setUpEndEntityValidatorTest() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();

        // create root cert profile
        rootCertProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
        rootCertificateProfileId = certProfileSession.addCertificateProfile(admin, 
                                                TEST_EEV_CERT_PROFILE_ROOT, rootCertProfile);
        log.info("created root certificate profile id: " + rootCertificateProfileId);
        
        // create end entity cert profile
        endEntityCertprofile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        endEntityCertprofile.setUseLdapDnOrder(false);
        endEntityCertificateProfileId = certProfileSession.addCertificateProfile(admin, TEST_EEV_CERT_PROFILE_EE, endEntityCertprofile);
        log.info("created end entity certificate profile id: " + endEntityCertificateProfileId);
        
        // create end entity profile
        endEntityProfile = new EndEntityProfile();
        List<Integer> availableCertProfiles = endEntityProfile.getAvailableCertificateProfileIds();
        availableCertProfiles.add(endEntityCertificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(availableCertProfiles);
        endEntityProfile.setAvailableCAs(Arrays.asList(new Integer[]{SecConst.ALLCAS}));
        endEntityProfile.addField(DnComponents.DNSNAME);
        endEntityProfile.addField(DnComponents.DNSNAME);
        endEntityProfile.setRequired(DnComponents.COMMONNAME, 0, false);
        endEntityProfile.setRequired(DnComponents.DNSNAME, 0, true);
        endEntityProfile.setRequired(DnComponents.DNSNAME, 1, false);
        endEntityProfileId = endEntityProfileSession.addEndEntityProfile(admin, TEST_EEV_EE_PROFILE_NAME, endEntityProfile);
        log.info("Created end entity profile id: " + endEntityProfileId);
        
        // create domain allowed list
        DomainAllowlistValidator domainAllowValidator = new DomainAllowlistValidator();
        domainAllowValidatorName = getRandomizedName(TEST_EEV_DOMAIN_ALLOW_VALIDATOR);
        domainAllowValidator.setProfileName(domainAllowValidatorName);
        domainAllowValidator.setAllCertificateProfileIds(true);
        domainAllowValidator.setPhase(IssuancePhase.DATA_VALIDATION.getIndex());
        domainAllowValidator.changeWhitelist(WHITELIST.getBytes(StandardCharsets.UTF_8));
        domainAllowValidatorId = keyValidatorSession.addKeyValidator(admin, domainAllowValidator);
        log.info("domainAllowValidatorId: " + domainAllowValidatorId);
        
        // create domain blocked list
        DomainBlacklistValidator domainBlockValidator = new DomainBlacklistValidator();
        domainBlockValidatorName = getRandomizedName(TEST_EEV_DOMAIN_BLOCK_VALIDATOR);
        domainBlockValidator.setProfileName(domainBlockValidatorName);
        domainBlockValidator.setAllCertificateProfileIds(true);
        List<String> checks = new ArrayList<String>();
        checks.add("org.ejbca.core.model.validation.domainblacklist.DomainBlacklistExactMatchChecker");
        domainBlockValidator.setChecks(checks);
        domainBlockValidator.setPhase(IssuancePhase.DATA_VALIDATION.getIndex());
        domainBlockValidator.changeBlacklist(BLACKLIST.getBytes(StandardCharsets.UTF_8));
        domainBlockValidatorId = keyValidatorSession.addKeyValidator(admin, domainBlockValidator);
        log.info("domainBlockValidatorId: " + domainBlockValidatorId);
        
        // root CA
        log.info("adding root CA: " + TEST_EEV_ROOT_CA_NAME);
        List<Integer> validators = new ArrayList<Integer>();
        validators.add(domainAllowValidatorId);
        // validators.add(domainBlockValidatorId);
        rootCaId = CaTestCase.createTestCA(TEST_EEV_ROOT_CA_NAME, 4096, "CN=" + TEST_EEV_ROOT_CA_NAME, 
                CAInfo.SELFSIGNED, rootCertificateProfileId, 
                validators);
        log.info("Root CA id: " + rootCaId);
        
    }
    
    @AfterClass
    public static void teardown() throws Exception {
        
        for(String user: createdUsers)
            endEntityManagementSession.deleteUser(admin, user);
        
        // remove:
        // ee profile
        endEntityProfileSession.removeEndEntityProfile(admin, TEST_EEV_EE_PROFILE_NAME);
    
        // ee cert profile
        certProfileSession.removeCertificateProfile(admin, TEST_EEV_CERT_PROFILE_EE);
        
        // Root CA
        CaTestCase.removeTestCA(TEST_EEV_ROOT_CA_NAME);
        
        keyValidatorSession.removeKeyValidator(admin, domainAllowValidatorName);
        keyValidatorSession.removeKeyValidator(admin, domainBlockValidatorName);
        
        // root cert profile
        certProfileSession.removeCertificateProfile(admin, TEST_EEV_CERT_PROFILE_ROOT); 
    }
    
    private boolean createUserWithDomains(String... domains) throws Exception {
        return createUserWithDomains(rootCaId, domains);
    }
    
    private boolean createUserWithDomains(int rootCaId, String... domains) throws Exception {

        String endEntityName = getRandomizedName(TEST_EEV_END_ENTITY_NAME);
        String endEntityDomain = "";
        
        for(String domain: domains)
            endEntityDomain += "DNSNAME=" + domain + ", ";
        endEntityDomain = endEntityDomain.substring(0, endEntityDomain.length() - 2);
        
        EndEntityInformation user = new EndEntityInformation(endEntityName, null, rootCaId, null,
                null, new EndEntityType(EndEntityTypes.ENDUSER), 
                endEntityProfileId, endEntityCertificateProfileId, EndEntityConstants.TOKEN_SOFT_JKS, null);
        user.setStatus(EndEntityConstants.STATUS_NEW); 
        user.setPassword(TEST_EEV_EE_PASSWORD);
        user.setSubjectAltName(endEntityDomain);
        
        // user creation should never fail
        user = endEntityManagementSession.addUser(admin, user, false);
        createdUsers.add(endEntityName);
        
        try {
             keyStoreCreateSessionBean.generateOrKeyRecoverTokenAsByteArray(admin, 
                user.getUsername(),  user.getPassword(), user.getCAId(), 
                "2048", AlgorithmConstants.KEYALGORITHM_RSA, SecConst.TOKEN_SOFT_JKS, 
                false, false, false, endEntityProfileId);
        } catch (Exception e) {
            return false;
        }
        
        return true;
    }
    
    private void updateRootCaValidators(int... validatorIds) throws Exception {
        
        X509CAInfo cainfo = (X509CAInfo) caSession.getCAInfo(admin, TEST_EEV_ROOT_CA_NAME);
        List<Integer> validators = new ArrayList<Integer>();
        for(int v: validatorIds)
            validators.add(v);

        cainfo.setValidators(validators);
        caAdminSession.editCA(admin, cainfo);
        
    }
    
    @Test
    public void testCreateUserInPermittedDomainWithOnlyAllowedValidator() throws Exception {
        
        updateRootCaValidators(domainAllowValidatorId);
        
        String[] domainList = new String[] {"permit.com", "permit.example.com", "permit2.example.com", 
                "permit3.example.com", "permit4.example.com", 
                "permit5.abc.example.com", "abc.permit6.def.example.com", "permit7.example.de",
                "common.in.bothlist.com", "permit8.partialxyz.com", "permit5.*.example.com", "*.permit6.*.example.com",
                "permit7.example.*", "permit8.partial*.com" };
        List<String> failedDomains = new ArrayList<String>();
        boolean result;
        for(String domain: domainList) {
            result = createUserWithDomains(domain);
            if(!result)
                failedDomains.add(domain);
            log.debug("tested permitted domain: " + domain);
        }
        Assert.assertTrue("User with permitted domains were not issued certificate: " + 
                                                    failedDomains.toString(), failedDomains.isEmpty());
    }
    
    @Test
    public void testCreateUserInForbiddenDomainWithOnlyBlockValidator() throws Exception {
        
        updateRootCaValidators(domainBlockValidatorId);
        
        String[] domainList = new String[] {"forbidden.example.com", "forbidden2.example.com",
                "forbidden4.example.com", "common.in.bothlist.com"};
        // possible to issue certificate for invalid domains: "hiIAmInvalid**.com" 
        List<String> failedDomains = new ArrayList<String>();
        boolean result;
        for(String domain: domainList) {
            result = createUserWithDomains(domain);
            if(result)
                failedDomains.add(domain);
            log.debug("tested forbidden domain: " + domain);
        }
        Assert.assertTrue("User with forbidden domains were issued certificate: " + 
                                                    failedDomains.toString(), failedDomains.isEmpty());
    }
    
    @Test
    public void testCreateUserNotInForbiddenDomainWithOnlyBlockValidator() throws Exception {
        
        updateRootCaValidators(domainBlockValidatorId);
        
        String[] domainList = new String[] {"forbid.example.com", "forbidden21.example.com",
                "forbidden4.com", "common.xx.bothlist.com"};
        List<String> failedDomains = new ArrayList<String>();
        boolean result;
        for(String domain: domainList) {
            result = createUserWithDomains(domain);
            if(!result)
                failedDomains.add(domain);
            log.debug("tested not forbidden domain: " + domain);
        }
        Assert.assertTrue("User with domains not forbidden domains were not issued certificate: " + 
                                                    failedDomains.toString(), failedDomains.isEmpty());
    }
    
    @Test
    public void testCreateUserNotInPermittedDomainWithOnlyAllowedValidator() throws Exception {
        
        updateRootCaValidators(domainAllowValidatorId);
        
        String[] domainList = new String[] {"permit1.com", "permit.example1.com", ".permit2.example.com", 
                "permit3..example.com", "permit4.example.com1", 
                "permit5.example.com", "permit6.def.example.com", "permit6.example.com", "permit7.example",
                "hiIAmInvalid**.com"};
        List<String> failedDomains = new ArrayList<String>();
        boolean result;
        for(String domain: domainList) {
            result = createUserWithDomains(domain);
            if(result)
                failedDomains.add(domain);
            log.debug("tested not permitted domain: " + domain);
        }
        Assert.assertTrue("User with not permitted domains were issued certificate: " + 
                                                    failedDomains.toString(), failedDomains.isEmpty());
    }
    
    @Test
    public void testCreateUserMultiplePermittedDomains() throws Exception {
        updateRootCaValidators(domainAllowValidatorId, domainBlockValidatorId);
        boolean result = createUserWithDomains("abc.permit6.def.example.com", "permit7.example.de");
        Assert.assertTrue("User with multiple permitted domains were not issed certificate.", result);
    }
    
    @Test
    public void testCreateUserPermittedAndNonPermittedDomains() throws Exception {
        updateRootCaValidators(domainAllowValidatorId, domainBlockValidatorId);
        boolean result = createUserWithDomains("abc.permit6.def.example.com", "permit6.example.com");
        Assert.assertFalse("User with permitted and not permitted domains were issued certificate.", result);
    }
    
    @Test
    public void testCreateUserPermittedAndForbiddenDomains() throws Exception {
        updateRootCaValidators(domainAllowValidatorId, domainBlockValidatorId);
        boolean result = createUserWithDomains("abc.permit6.def.example.com", "forbidden.example.com");
        Assert.assertFalse("User with permitted and not permitted domains were issued certificate.", result);
    }
    
    @Test
    public void testCreateUserDomainOnNothPermittedAndForbiddenDomains() throws Exception {
        updateRootCaValidators(domainAllowValidatorId, domainBlockValidatorId);
        boolean result = createUserWithDomains("common.in.bothlist.com");
        Assert.assertFalse("User with domain on both blocked and allowed list were issued certificate.", result);
    }
    
    @Test
    public void testX_updateValidators() {
        try {
            DomainAllowlistValidator domainAllowValidator = 
                    (DomainAllowlistValidator) keyValidatorSession.getValidator(domainAllowValidatorId);
            
            String newWhiteList = WHITELIST + "permit.another.com\n permit.also.*.com\n";
            newWhiteList = newWhiteList.replace("permit.com\n", "");
            domainAllowValidator.changeWhitelist(newWhiteList.getBytes(StandardCharsets.UTF_8));
            keyValidatorSession.changeKeyValidator(admin, domainAllowValidator);
            
            DomainAllowlistValidator allowValidator = 
                    (DomainAllowlistValidator) keyValidatorSession.getValidator(domainAllowValidatorId);
            log.info("allow list sha256: " + allowValidator.getWhitelistSha256());
        } catch(Exception e) {
            log.error("updating allow validator error, ", e);
            Assert.fail("Error during updating allow validator");
        }
        
        try {
            DomainBlacklistValidator domainBlockValidator = 
                            (DomainBlacklistValidator) keyValidatorSession.getValidator(domainBlockValidatorId);

            String newBlackList = "forbid.onlyme.com\n";
            domainBlockValidator.changeBlacklist(newBlackList.getBytes(StandardCharsets.UTF_8));
            keyValidatorSession.changeKeyValidator(admin, domainBlockValidator);
            
            DomainBlacklistValidator blockValidator = 
                    (DomainBlacklistValidator) keyValidatorSession.getValidator(domainBlockValidatorId);
            log.info("block list sha256: " + blockValidator.getBlacklistSha256());
        } catch(Exception e) {
            log.error("updating block validator error, ", e);
            Assert.fail("Error during updating block validator");
        }

    }
    
    @Test
    public void testY_createUserInPermittedDomain() throws Exception {
        updateRootCaValidators(domainAllowValidatorId);
        String[] domainList = new String[] {"permit.example.com", "permit.another.com", "permit.also.xx.com"};
        List<String> failedDomains = new ArrayList<String>();
        boolean result;
        for(String domain: domainList) {
            result = createUserWithDomains(domain);
            if(!result)
                failedDomains.add(domain);
            log.debug("tested permitted domain: " + domain);
        }
        Assert.assertTrue("User with permitted domains were not issued certificate: " + 
                                                    failedDomains.toString(), failedDomains.isEmpty());
    }
    
    @Test
    public void testY_createUserInForbiddenDomain() throws Exception {
        updateRootCaValidators(domainBlockValidatorId);
        boolean result = createUserWithDomains("forbid.onlyme.com");
        Assert.assertFalse("User with forbidden domains were issued certificate.", result);
    }
    
    @Test
    public void testY_createUserNotInPermittedDomain() throws Exception {
        updateRootCaValidators(domainAllowValidatorId);
        String[] domainList = new String[] {"permit.com", "permit.also.com"};
        List<String> failedDomains = new ArrayList<String>();
        boolean result;
        for(String domain: domainList) {
            result = createUserWithDomains(domain);
            if(result)
                failedDomains.add(domain);
            log.debug("tested not permitted domain: " + domain);
        }
        Assert.assertTrue("User with not permitted domains were issued certificate: " + 
                                                    failedDomains.toString(), failedDomains.isEmpty());
    }
    
    @Test
    public void testEmptyAllowValidatorList() throws Exception {
        // create empty domain allowed list
        DomainAllowlistValidator domainAllowValidator = new DomainAllowlistValidator();
        String domainAllowValidatorName = getRandomizedName(TEST_EEV_DOMAIN_ALLOW_VALIDATOR);
        domainAllowValidator.setProfileName(domainAllowValidatorName);
        domainAllowValidator.setAllCertificateProfileIds(true);
        domainAllowValidator.setPhase(IssuancePhase.DATA_VALIDATION.getIndex());
        int domainAllowValidatorId = keyValidatorSession.addKeyValidator(admin, domainAllowValidator);
        log.info("domainAllowValidatorId with blank list: " + domainAllowValidatorId);
        
        String rootCaName = TEST_EEV_ROOT_CA_NAME + "1";
        log.info("adding root CA: " + rootCaName);
        List<Integer> validators = new ArrayList<Integer>();
        validators.add(domainAllowValidatorId);
        int rootCaId = CaTestCase.createTestCA(rootCaName, 4096, "CN=" + rootCaName, 
                CAInfo.SELFSIGNED, rootCertificateProfileId, 
                validators);
        log.info("Root CA id: " + rootCaId);
        
        boolean result = createUserWithDomains(rootCaId, "test.com");
        removeTestCA(rootCaId);
        keyValidatorSession.removeKeyValidator(admin, domainAllowValidatorName);
        
        Assert.assertFalse("User with empty allwed domains were issued certificate.", result);

    }
    
    @Test
    public void testEmptyBlockValidatorList() throws Exception {
        // create empty domain blocked list
        DomainBlacklistValidator domainBlockValidator = new DomainBlacklistValidator();
        String domainBlockValidatorName = getRandomizedName(TEST_EEV_DOMAIN_BLOCK_VALIDATOR);
        domainBlockValidator.setProfileName(domainBlockValidatorName);
        domainBlockValidator.setAllCertificateProfileIds(true);
        domainBlockValidator.setChecks(
                Arrays.asList("org.ejbca.core.model.validation.domainblacklist.DomainBlacklistExactMatchChecker"));
        domainBlockValidator.setPhase(IssuancePhase.DATA_VALIDATION.getIndex());
        int domainBlockValidatorId = keyValidatorSession.addKeyValidator(admin, domainBlockValidator);
        log.info("domainBlockValidatorId with blank list: " + domainBlockValidatorId);
        
        String rootCaName = TEST_EEV_ROOT_CA_NAME + "2";
        log.info("adding root CA: " + rootCaName);
        List<Integer> validators = new ArrayList<Integer>();
        validators.add(domainBlockValidatorId);
        int rootCaId = CaTestCase.createTestCA(rootCaName, 4096, "CN=" + rootCaName, 
                CAInfo.SELFSIGNED, rootCertificateProfileId, 
                validators);
        log.info("Root CA id: " + rootCaId);
        
        boolean result = createUserWithDomains(rootCaId, "test.com");
        removeTestCA(rootCaId);
        keyValidatorSession.removeKeyValidator(admin, domainBlockValidatorName);
        
        Assert.assertTrue("User with empty blocked domains were not issued certificate.", result);

    }

}
