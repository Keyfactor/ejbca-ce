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
package org.ejbca.core.ejb.ca.caadmin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionRemote;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.userdatasource.CustomUserDataSourceContainer;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.junit.Test;

/**
 * Tests initialization of uninitialized CAs (e.g. imported from statedumps).
 * 
 * @version $Id$
 */
public class InitCATest extends CaTestCase {

    private static final Logger log = Logger.getLogger(CAsTest.class);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CAsTest"));

    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final InternalKeyBindingMgmtSessionRemote keyBindMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private final RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private final RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private final ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
    private final UserDataSourceSessionRemote userDataSourceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(UserDataSourceSessionRemote.class);

    private static final String RENAME_CA = "testInitializeCaAndChangeSubjectDn";
    private static final String CERT_PROFILE_NAME = "TestChangeSubjectDN_CP";
    private static final String ENDENTITY_PROFILE_NAME = "TestChangeSubjectDN_EEP";
    private static final String DATASOURCE_NAME = "TestChangeSubjectDN_UDS";
    private static final String SERVICE_NAME = "TestChangeSubjectDN_Service";
    private static final String KEYBINDING_NAME = "TestChangeSubjectDN_IKB";
    private static final String ROLE_NAME = "TestChangeSubjectDN_Role";
    private static final String CMP_ALIAS = "TestChangeSubjectDN_CMP";
    
    private static final String NEW_DN = "CN=RenamedTestCA";

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    /**
     * Tests creating an unitialized CA and then initializing it.
     */
    @Test
    public void testInitializeCa() throws Exception {
        log.trace(">testInitializeCa");
        final String caName = "testInitializeCa";
        
        removeOldCa(caName);
        final CAInfo x509CaInfo = createUnititializedCaInfo(caName, caName);
        caAdminSession.createCA(admin, x509CaInfo);
        try {
            final CAInfo retrievedCaInfo = caSession.getCAInfo(admin, x509CaInfo.getCAId());
            assertEquals("CA was not created unitialized", CAConstants.CA_UNINITIALIZED, retrievedCaInfo.getStatus());
            assertTrue("Unitialized CA was given certificate chain", retrievedCaInfo.getCertificateChain().isEmpty());
            //Now initialize
            caAdminSession.initializeCa(admin, retrievedCaInfo);
            final CAInfo updatedCaInfo = caSession.getCAInfo(admin, retrievedCaInfo.getCAId());
            assertEquals("CA was not set to active", CAConstants.CA_ACTIVE, updatedCaInfo.getStatus());
            assertFalse("Initialized CA was not given certificate chain", updatedCaInfo.getCertificateChain().isEmpty());
        } finally {
            removeOldCa(caName);
        }
        log.trace("<testInitializeCa");
    }
    
    /**
     * Tests creating an unitialized CA and then initializing it.
     */
    @Test
    public void testInitializeCaAndChangeSubjectDn() throws Exception {
        log.trace(">testInitializeCaAndChangeSubjectDn");
        
        Integer keybindId = null;
        
        // Remove old test data
        deleteTestData();
        
        // Create CA
        log.debug("Creating CA");
        final CAInfo x509CaInfo = createUnititializedCaInfo(RENAME_CA, RENAME_CA);
        caAdminSession.createCA(admin, x509CaInfo);
        try {
            final CAInfo retrievedCaInfo = caSession.getCAInfo(admin, x509CaInfo.getCAId());
            assertEquals("CA was not created unitialized", CAConstants.CA_UNINITIALIZED, retrievedCaInfo.getStatus());
            assertTrue("Unitialized CA was given certificate chain", retrievedCaInfo.getCertificateChain().isEmpty());
            
            // Add some data that references the CA
            log.debug("Adding CA references");
            final int origCaId = x509CaInfo.getCAId();
            CertificateProfile certProf = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
            certProf.setAvailableCAs(new ArrayList<Integer>(Collections.singletonList(origCaId)));
            certificateProfileSession.addCertificateProfile(admin, CERT_PROFILE_NAME, certProf);
            
            EndEntityProfile eeProf = new EndEntityProfile();
            eeProf.setAvailableCAs(new ArrayList<Integer>(Collections.singletonList(origCaId)));
            eeProf.setValue(EndEntityProfile.DEFAULTCA, 0, String.valueOf(origCaId));
            endEntityProfileSession.addEndEntityProfile(admin, ENDENTITY_PROFILE_NAME, eeProf);
            
            CustomUserDataSourceContainer userdatasource = new CustomUserDataSourceContainer();
            userdatasource.setClassPath("org.ejbca.core.model.ra.userdatasource.DummyCustomUserDataSource");
            userdatasource.setDescription("Used in Junit Test, Remove this one");
            userdatasource.setApplicableCAs(new ArrayList<Integer>(Collections.singletonList(origCaId)));
            userDataSourceSession.addUserDataSource(admin, DATASOURCE_NAME, userdatasource);
            
            ServiceConfiguration sc = new ServiceConfiguration();
            Properties workerProperties = new Properties();
            workerProperties.put(BaseWorker.PROP_CAIDSTOCHECK, "1234;"+origCaId);
            sc.setWorkerProperties(workerProperties);
            sc.setPinToNodes(new String[] {"some","hosts"});
            sc.setActive(false);
            serviceSession.addService(admin, SERVICE_NAME, sc);
            
            final CAToken caToken = x509CaInfo.getCAToken();
            final Map<String, Serializable> dataMap = new LinkedHashMap<String, Serializable>();
            final List<InternalKeyBindingTrustEntry> trustedcerts = new ArrayList<InternalKeyBindingTrustEntry>();
            trustedcerts.add(new InternalKeyBindingTrustEntry(origCaId, BigInteger.valueOf(12345678)));
            keybindId = keyBindMgmtSession.createInternalKeyBinding(admin, OcspKeyBinding.IMPLEMENTATION_ALIAS, KEYBINDING_NAME, InternalKeyBindingStatus.DISABLED, null,
                    caToken.getCryptoTokenId(), caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN),
                    caToken.getSignatureAlgorithm(), dataMap, trustedcerts);
            
            // Global configuration is not tested since we can't test that without overwriting data 
            
            CmpConfiguration cmpConfig = (CmpConfiguration)globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
            cmpConfig.addAlias(CMP_ALIAS);
            cmpConfig.setCMPDefaultCA(CMP_ALIAS, "CN="+RENAME_CA);
            cmpConfig.setRACAName(CMP_ALIAS, RENAME_CA); // this one shouldn't need to be updated, but it's tested anyway
            globalConfigurationSession.saveConfiguration(admin, cmpConfig);
            
            final Role role = roleSession.persistRole(admin, new Role(null, ROLE_NAME));
            final RoleMember roleMember = roleMemberSession.persist(admin, new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED,
                    X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, origCaId, X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                    AccessMatchType.TYPE_EQUALCASE.getNumericValue(), "TestUser", role.getRoleId(), null, null));
            // Do the same in the legacy system (TODO: Remove this)
            AdminGroupData adminGroupData = roleManagementSession.create(admin, ROLE_NAME);
            final List<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
            subjects.add(new AccessUserAspectData(ROLE_NAME, origCaId, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, "TestUser"));
            adminGroupData = roleManagementSession.addSubjectsToRole(admin, adminGroupData, subjects);
            
            // Now change a value and initialize
            log.debug("Trying to initialize with changed Subject DN");
            retrievedCaInfo.setSubjectDN(NEW_DN);
            caAdminSession.initializeCa(admin, retrievedCaInfo);
            
            final CAInfo updatedCaInfo = caSession.getCAInfo(admin, CertTools.stringToBCDNString(NEW_DN).hashCode());
            assertEquals("CA was not set to active", CAConstants.CA_ACTIVE, updatedCaInfo.getStatus());
            assertFalse("Initialized CA was not given certificate chain", updatedCaInfo.getCertificateChain().isEmpty());
            
            // Check references from other tables
            final int newCaId = caSession.getCAInfo(admin, RENAME_CA).getCAId();
            
            certProf = certificateProfileSession.getCertificateProfile(CERT_PROFILE_NAME);
            assertEquals("CAId was not updated in certificate profile.", newCaId, (int)certProf.getAvailableCAs().get(0));
            
            eeProf = endEntityProfileSession.getEndEntityProfile(ENDENTITY_PROFILE_NAME);
            assertEquals("CAId was not updated in end-entity profile.", newCaId, Integer.parseInt(eeProf.getAvailableCAs().iterator().next()));
            assertEquals("CAId was not updated in end-entity profile.", newCaId, eeProf.getDefaultCA());
            
            userdatasource = (CustomUserDataSourceContainer)userDataSourceSession.getUserDataSource(admin, DATASOURCE_NAME);
            assertEquals("CAId was not updated in user data source.", newCaId, (int)userdatasource.getApplicableCAs().iterator().next());
            
            // Unfortunately, CA Id replacement inside services does not work on all app servers
            /*final int serviceId = serviceSession.getServiceId(SERVICE_NAME);
            sc = serviceSession.getServiceConfiguration(admin, serviceId);
            workerProperties = sc.getWorkerProperties();
            assertEquals("CAIds were not updated (or were incorrect) in service.", "1234;"+newCaId, workerProperties.getProperty(BaseWorker.PROP_CAIDSTOCHECK));*/
            
            final InternalKeyBindingInfo keybind = keyBindMgmtSession.getInternalKeyBindingInfo(admin, keybindId);
            assertEquals("CAId was not updated in keybinding trusted certificate reference.", newCaId, keybind.getTrustedCertificateReferences().get(0).getCaId());
            
            cmpConfig = (CmpConfiguration)globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
            assertEquals("CA Subject DN was not updated in CMP config", NEW_DN, cmpConfig.getCMPDefaultCA(CMP_ALIAS));
            
            adminGroupData = roleAccessSession.findRole(ROLE_NAME);
            assertEquals("CAId was not updated in role subject", newCaId, adminGroupData.getAccessUsers().values().iterator().next().getCaId().intValue());
            final RoleMember roleMemberAfterInit = roleMemberSession.getRoleMember(admin, roleMember.getId());
            assertEquals("CAId was not updated in role subject", newCaId, roleMemberAfterInit.getTokenIssuerId());
        } finally {
            log.debug("Cleaning up");
            deleteTestData();
        }
    }
    
    private CAInfo createUnititializedCaInfo(String cryptoTokenName, String caName) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, AuthorizationDeniedException, InvalidKeyException, InvalidAlgorithmParameterException {
        log.trace(">createUnititializedCaInfo");
        
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo123");
        int cryptoTokenId;
        if (!cryptoTokenManagementProxySession.isCryptoTokenNameUsed(cryptoTokenName)) {
            try {
                cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(admin, cryptoTokenName, SoftCryptoToken.class.getName(),
                        cryptoTokenProperties, null, null);
            } catch (NoSuchSlotException e) {
                throw new IllegalStateException("Attempted to find a slot for a soft crypto token. This should not happen.", e);
            }
        } else {
            cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
        }
        if (!cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS)) {
            cryptoTokenManagementSession.createKeyPair(admin, cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS, "1024");
        }
        if (!cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS)) {
            cryptoTokenManagementSession.createKeyPair(admin, cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS, "1024");
        }

        final CryptoToken cryptoToken = cryptoTokenManagementProxySession.getCryptoToken(cryptoTokenId);
        
        final Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        final CAToken catoken = new CAToken(cryptoToken.getId(), caTokenProperties);
        // Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
        catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        final X509CAInfo x509CaInfo = new X509CAInfo("CN="+caName, caName, CAConstants.CA_UNINITIALIZED,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, catoken);
        x509CaInfo.setDescription("JUnit RSA CA");
                
        log.trace("<createUnititializedCaInfo");
        return x509CaInfo;
    }
    
    private void deleteTestData() throws AuthorizationDeniedException {
        log.trace(">deleteTestData");
        removeOldCa(RENAME_CA);
        certificateProfileSession.removeCertificateProfile(admin, CERT_PROFILE_NAME);
        endEntityProfileSession.removeEndEntityProfile(admin, ENDENTITY_PROFILE_NAME);
        userDataSourceSession.removeUserDataSource(admin, DATASOURCE_NAME);
        serviceSession.removeService(admin, SERVICE_NAME);
        final Integer keybindIdToDelete = keyBindMgmtSession.getIdFromName(KEYBINDING_NAME);
        if (keybindIdToDelete != null) {
            keyBindMgmtSession.deleteInternalKeyBinding(admin, keybindIdToDelete);
        }
        try {
            final Role role = roleSession.getRole(admin, null, ROLE_NAME);
            if (role!=null) {
                roleSession.deleteRoleIdempotent(admin, role.getRoleId());
            }
        } catch (Exception e) {
            log.debug(e.getMessage());
        }
        try {
            roleManagementSession.remove(admin, ROLE_NAME);
        } catch (RoleNotFoundException e) { } // NOPMD already deleted or non-existent
        final CmpConfiguration cmpConfig = (CmpConfiguration)globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        if (cmpConfig.aliasExists(CMP_ALIAS)) {
            cmpConfig.removeAlias(CMP_ALIAS);
            globalConfigurationSession.saveConfiguration(admin, cmpConfig);
        }
        log.trace("<deleteTestData");
    }

}
