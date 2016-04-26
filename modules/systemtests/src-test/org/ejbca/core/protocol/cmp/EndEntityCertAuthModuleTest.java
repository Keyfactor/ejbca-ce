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

package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Principal;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.ejb.ObjectNotFoundException;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSession;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * System tests for EndEntityCertificateAuthenticationModule
 * 
 * @version $Id$
 *
 */

public class EndEntityCertAuthModuleTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(EndEntityCertAuthModuleTest.class);
    
    private final static String RA1_ALIAS = "EECertAuthModTestRA1ConfAlias";
    private final static String RA2_ALIAS = "EECertAuthModTestRA2ConfAlias";
    private final static String CA1 = "EECertAuthModTestRA1CA1";
    private final static String CA2 = "EECertAuthModTestRA2CA2";
    private final static String CP1 = "EECertAuthModTestRA1CP1";
    private final static String CP2 = "EECertAuthModTestRA2CP2";
    private final static String EEP1 = "EECertAuthModTestRA1EEP1";
    private final static String EEP2 = "EECertAuthModTestRA2EEP2";
    private final static String AUTH_PARAM_CA = "EECertAuthModTestAuthCA";
    private final static String RA1_ADMIN_ROLE = "EECertAuthModTestRA1AdminRole";
    private final static String RA2_ADMIN_ROLE = "ECertAuthModTestRA2AdminRole";
    private final static String RA1_ADMIN = "EECertAuthModTestRA1Admin";
    private final static String RA2_ADMIN = "EECertAuthModTestRA2Admin";
    
    private final CmpConfiguration cmpConfiguration;
    private final byte[] nonce;
    private final byte[] transid;
    private static CA ca1;
    private static CA ca2;
    private static CA adminca;
    private Certificate ra1admincert;
    private Certificate ra2admincert;
    private KeyPair ra1adminkeys;
    private KeyPair ra2adminkeys;
    
    private static final GlobalConfigurationSession globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final RoleManagementSession roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private static final RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);


    public EndEntityCertAuthModuleTest() throws Exception {
        nonce = CmpMessageHelper.createSenderNonce();
        transid = CmpMessageHelper.createSenderNonce();
  
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        adminca = CaTestUtils.createTestX509CA("CN=" + AUTH_PARAM_CA, "foo123".toCharArray(), false, keyusage);
        if(!caSession.existsCa(adminca.getCAId())) {
            caSession.addCA(ADMIN, adminca);
        }
        
        ra1adminkeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        AuthenticationToken ra1admin = createAdminToken(ra1adminkeys, RA1_ADMIN, "CN="+RA1_ADMIN, adminca.getCAId(), 
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        ra1admincert = getCertFromAuthenticationToken(ra1admin);

        ra2adminkeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        AuthenticationToken ra2admin = createAdminToken(ra2adminkeys, RA2_ADMIN, "CN="+RA2_ADMIN, adminca.getCAId(), 
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        ra2admincert = getCertFromAuthenticationToken(ra2admin);

        
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        ca1 = CaTestUtils.createTestX509CA("CN=" + CA1, null, false, keyusage);
        ca2 = CaTestUtils.createTestX509CA("CN=" + CA2, null, false, keyusage);
        
        // Add CA, CP and EEP for RA1
        if(!caSession.existsCa(ca1.getCAId())) {
            caSession.addCA(ADMIN, ca1);
        }
        if (certProfileSession.getCertificateProfile(CP1) == null) {
            final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            List<Integer> availablecas = new ArrayList<Integer>();
            availablecas.add(ca1.getCAId());
            cp.setAvailableCAs(availablecas);
            try {
                certProfileSession.addCertificateProfile(ADMIN, CP1, cp);
            } catch (CertificateProfileExistsException e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }
        int cp1Id = certProfileSession.getCertificateProfileId(CP1);
        if (endEntityProfileSession.getEndEntityProfile(EEP1) == null) {
            final EndEntityProfile eep = new EndEntityProfile(true);
            eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, ""+cp1Id);
            eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, ""+cp1Id);
            eep.setValue(EndEntityProfile.AVAILCAS, 0, ""+ca1.getCAId());
            eep.setValue(EndEntityProfile.DEFAULTCA, 0, ""+ca1.getCAId());
            try {
                endEntityProfileSession.addEndEntityProfile(ADMIN, EEP1, eep);
            } catch (EndEntityProfileExistsException e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }
        final int eepId = endEntityProfileSession.getEndEntityProfileId(EEP1);
        // Configure CMP alias for RA1
        cmpConfiguration.addAlias(RA1_ALIAS);
        cmpConfiguration.setRAMode(RA1_ALIAS, true);
        cmpConfiguration.setAuthenticationModule(RA1_ALIAS, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(RA1_ALIAS, AUTH_PARAM_CA);
        cmpConfiguration.setRAEEProfile(RA1_ALIAS, String.valueOf(eepId));
        cmpConfiguration.setRACertProfile(RA1_ALIAS, CP1);
        cmpConfiguration.setRACAName(RA1_ALIAS, CA1);
        cmpConfiguration.setExtractUsernameComponent(RA1_ALIAS, "CN");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);

        
        
        // Add CA, CP and EEP for RA2
        if(!caSession.existsCa(ca2.getCAId())) {
            caSession.addCA(ADMIN, ca2);
        }
        if (certProfileSession.getCertificateProfile(CP2) == null) {
            final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            List<Integer> availablecas = new ArrayList<Integer>();
            availablecas.add(ca2.getCAId());
            cp.setAvailableCAs(availablecas);
            try {
                certProfileSession.addCertificateProfile(ADMIN, CP2, cp);
            } catch (CertificateProfileExistsException e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }
        final int cp2Id = certProfileSession.getCertificateProfileId(CP2);
        if (endEntityProfileSession.getEndEntityProfile(EEP2) == null) {
            final EndEntityProfile eep = new EndEntityProfile(true);
            eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, ""+cp2Id);
            eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, ""+cp2Id);
            eep.setValue(EndEntityProfile.AVAILCAS, 0, ""+ca2.getCAId());
            eep.setValue(EndEntityProfile.DEFAULTCA, 0, ""+ca2.getCAId());
            try {
                endEntityProfileSession.addEndEntityProfile(ADMIN, EEP2, eep);
            } catch (EndEntityProfileExistsException e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }
        final int eep2Id = endEntityProfileSession.getEndEntityProfileId(EEP2);
        // Configure CMP alias for RA2
        cmpConfiguration.addAlias(RA2_ALIAS);
        cmpConfiguration.setRAMode(RA2_ALIAS, true);
        cmpConfiguration.setAuthenticationModule(RA2_ALIAS, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(RA2_ALIAS, AUTH_PARAM_CA);
        cmpConfiguration.setRAEEProfile(RA2_ALIAS, String.valueOf(eep2Id));
        cmpConfiguration.setRACertProfile(RA2_ALIAS, CP2);
        cmpConfiguration.setRACAName(RA2_ALIAS, CA2);
        cmpConfiguration.setExtractUsernameComponent(RA2_ALIAS, "CN");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);


        // Create AdminRoles for RA1 and RA2
        RoleData ra1role = roleManagementSession.create(ADMIN, RA1_ADMIN_ROLE);
        RoleData ra2role = roleManagementSession.create(ADMIN, RA2_ADMIN_ROLE);
        
        // Add Admins to roles RA1 and RA2
        List<AccessUserAspectData> accessUsers = new ArrayList<AccessUserAspectData>();
        accessUsers.add(new AccessUserAspectData(RA1_ADMIN_ROLE, adminca.getCAId(), X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, RA1_ADMIN));
        roleManagementSession.addSubjectsToRole(ADMIN, ra1role, accessUsers);

        accessUsers = new ArrayList<AccessUserAspectData>();
        accessUsers.add(new AccessUserAspectData(RA2_ADMIN_ROLE, adminca.getCAId(), X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, RA2_ADMIN));
        roleManagementSession.addSubjectsToRole(ADMIN, ra2role, accessUsers);

        
        int eep1id = endEntityProfileSession.getEndEntityProfileId(EEP1);
        // Add access rules to roles
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();       
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false));            
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, StandardRules.CREATECERT.resource(), AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.REGULAR_STORECERTIFICATE, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.REGULAR_CREATEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.REGULAR_EDITENDENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.REGULAR_DELETEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.REGULAR_REVOKEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, StandardRules.CAACCESS.resource() + ca1.getCAId(), AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep1id, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep1id + AccessRulesConstants.VIEW_END_ENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep1id + AccessRulesConstants.EDIT_END_ENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep1id + AccessRulesConstants.CREATE_END_ENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep1id + AccessRulesConstants.DELETE_END_ENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep1id + AccessRulesConstants.REVOKE_END_ENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA1_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep1id + AccessRulesConstants.VIEW_END_ENTITY_HISTORY, AccessRuleState.RULE_ACCEPT, false));    
        roleManagementSession.addAccessRulesToRole(ADMIN, ra1role, accessRules);            

        int eep2id = endEntityProfileSession.getEndEntityProfileId(EEP2);
        accessRules = new ArrayList<AccessRuleData>();       
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false));            
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, StandardRules.CREATECERT.resource(), AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.REGULAR_STORECERTIFICATE, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.REGULAR_CREATEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.REGULAR_EDITENDENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.REGULAR_DELETEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.REGULAR_REVOKEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, StandardRules.CAACCESS.resource() + ca2.getCAId(), AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep2id, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep2id + AccessRulesConstants.VIEW_END_ENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep2id + AccessRulesConstants.EDIT_END_ENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep2id + AccessRulesConstants.CREATE_END_ENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep2id + AccessRulesConstants.DELETE_END_ENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep2id + AccessRulesConstants.REVOKE_END_ENTITY, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(RA2_ADMIN_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eep2id + AccessRulesConstants.VIEW_END_ENTITY_HISTORY, AccessRuleState.RULE_ACCEPT, false));    
        roleManagementSession.addAccessRulesToRole(ADMIN, ra2role, accessRules);            
    }
    
    @After
    public void restore() throws Exception{
        
        CmpConfiguration cmpconf = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        cmpconf.removeAlias(RA1_ALIAS);
        cmpconf.removeAlias(RA2_ALIAS);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpconf);

        roleManagementSession.remove(ADMIN, roleAccessSession.findRole(RA1_ADMIN_ROLE));
        log.debug("Removed role: " + RA1_ADMIN_ROLE);
        roleManagementSession.remove(ADMIN, roleAccessSession.findRole(RA2_ADMIN_ROLE));
        log.debug("Removed role: " + RA2_ADMIN_ROLE);
        
        EndEntityManagementSessionRemote eeManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        if(eeManagementSession.existsUser(RA1_ADMIN)) {
            eeManagementSession.revokeAndDeleteUser(ADMIN, RA1_ADMIN, ReasonFlags.unused);
            internalCertStoreSession.removeCertificate(CertTools.getFingerprintAsString(ra1admincert));
            log.debug("Removed and revoked EndEntity: " + RA1_ADMIN);
        }
        if(eeManagementSession.existsUser(RA2_ADMIN)) {
            eeManagementSession.revokeAndDeleteUser(ADMIN, RA2_ADMIN, ReasonFlags.unused);
            internalCertStoreSession.removeCertificate(CertTools.getFingerprintAsString(ra2admincert));
            log.debug("Removed and revoked EndEntity: " + RA2_ADMIN);
        }
        
        EndEntityProfileSessionRemote eeProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
        if(eeProfileSession.getEndEntityProfile(EEP1) != null) {
            eeProfileSession.removeEndEntityProfile(ADMIN, EEP1);
            log.debug("Removed EndEntityProfile: " + EEP1);
        }
        if(eeProfileSession.getEndEntityProfile(EEP2) != null) {
            eeProfileSession.removeEndEntityProfile(ADMIN, EEP2);
            log.debug("Removed EndEntityProfile: " + EEP2);
        }
        
        CertificateProfileSessionRemote certProfSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
        if(certProfileSession.getCertificateProfile(CP1)!=null) {
            certProfSession.removeCertificateProfile(ADMIN, CP1);
            log.debug("Removed CertificateProfile: " + CP1);
        }
        if(certProfileSession.getCertificateProfile(CP2)!=null) {
            certProfSession.removeCertificateProfile(ADMIN, CP2);
            log.debug("Removed CertificateProfile: " + CP2);
        }
        
        if(caSession.existsCa(AUTH_PARAM_CA)) {
            caSession.removeCA(ADMIN, adminca.getCAId());
            log.debug("Removed CA: " + AUTH_PARAM_CA);
        }
        if(caSession.existsCa(CA1)) {
            caSession.removeCA(ADMIN, ca1.getCAId());
            log.debug("Removed CA: " + CA1);
        }
        if(caSession.existsCa(CA2)) {
            caSession.removeCA(ADMIN, ca2.getCAId());
            log.debug("Removed CA: " + CA2);
        }
        
    }

    /**
     * 1- Sends a CRMF request signed by RA1Admin to RA1. Expected: Success
     * 2- Sends a CRMF request signed by RA2Admin to RA2. Expected: Success
     * 
     * @throws Exception
     */
    @Test
    public void test01RA1SuccessfullCRMF() throws Exception {

        // Send CRMF message signed by RA1Admin to RA1
        String testUsername = "ra1testuser";
        String fingerprintCert = null;
        try {
            
            final X500Name testUserDN = new X500Name("CN=" + testUsername);
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
            PKIMessage msg = genCertReq(ca1.getSubjectDN(), testUserDN, keys, ca1.getCACertificate(), nonce, 
                    transid, false, null, null, null, null, pAlg, new DEROctetString(nonce));
            assertNotNull("Generating CrmfRequest failed.", msg);

            CMPCertificate[] extraCert = getCMPCert(ra1admincert);
            msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, ra1adminkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            assertNotNull("Signing CMP message failed", msg);
            //******************************************''''''
            final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getAlgorithm().getId(), "BC");
            sig.initVerify(ra1admincert.getPublicKey());
            sig.update(CmpMessageHelper.getProtectedBytes(msg));
            boolean verified = sig.verify(msg.getProtection().getBytes());
            assertTrue("Signing the message failed.", verified);
            //***************************************************

            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(msg);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, RA1_ALIAS);
            checkCmpResponseGeneral(resp, ca1.getSubjectDN(), testUserDN, ca1.getCACertificate(), msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                    .getTransactionID().getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            CertReqMessages ir = (CertReqMessages) msg.getBody().getContent();
            Certificate cert = checkCmpCertRepMessage(testUserDN, (X509Certificate) ca1.getCACertificate(), resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                    .getValue().intValue());
            assertNotNull("CrmfRequest did not return a certificate", cert);
            fingerprintCert = CertTools.getFingerprintAsString(cert);
        } finally {
            internalCertStoreSession.removeCertificate(fingerprintCert);
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, testUsername, ReasonFlags.unused);
        }
        
        
        
        // Send CRMF message signed by RA2Admin to RA2
        testUsername = "ra2testuser";
        try {
            
            final X500Name testUserDN = new X500Name("CN=" + testUsername);
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
            PKIMessage msg = genCertReq(ca2.getSubjectDN(), testUserDN, keys, ca2.getCACertificate(), nonce, 
                    transid, false, null, null, null, null, pAlg, new DEROctetString(nonce));
            assertNotNull("Generating CrmfRequest failed.", msg);

            CMPCertificate[] extraCert = getCMPCert(ra2admincert);
            msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, ra2adminkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            assertNotNull("Signing CMP message failed.", msg);
            //******************************************''''''
            final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getAlgorithm().getId(), "BC");
            sig.initVerify(ra2admincert.getPublicKey());
            sig.update(CmpMessageHelper.getProtectedBytes(msg));
            boolean verified = sig.verify(msg.getProtection().getBytes());
            assertTrue("Signing the message failed.", verified);
            //***************************************************

            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(msg);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, RA2_ALIAS);
            checkCmpResponseGeneral(resp, ca2.getSubjectDN(), testUserDN, ca2.getCACertificate(), msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                    .getTransactionID().getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            CertReqMessages ir = (CertReqMessages) msg.getBody().getContent();
            Certificate cert = checkCmpCertRepMessage(testUserDN, (X509Certificate) ca2.getCACertificate(), resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                    .getValue().intValue());
            assertNotNull("CrmfRequest did not return a certificate", cert);
            fingerprintCert = CertTools.getFingerprintAsString(cert);
        } finally {
            internalCertStoreSession.removeCertificate(fingerprintCert);
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, testUsername, ReasonFlags.unused);
        }

    }
    

    
    
    /**
     * 1- Sends a CRMF request signed by RA2Admin to RA1. Expected: Fail
     * 2- Sends a CRMF request signed by RA1Admin to RA2. Expected: Fail
     * 
     * @throws Exception
     */
    @Test
    public void test01RA1FailedCRMF() throws Exception {

        // Send CRMF message signed by RA2Admin to RA1
        String testUsername = "ra1testuser";
        X500Name testUserDN = new X500Name("CN=" + testUsername);
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage msg = genCertReq(ca1.getSubjectDN(), testUserDN, keys, ca1.getCACertificate(), nonce, 
                transid, false, null, null, null, null, pAlg, new DEROctetString(nonce));
        assertNotNull("Generating CrmfRequest failed.", msg);
            
        CMPCertificate[] extraCert = getCMPCert(ra2admincert);
        msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, ra2adminkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull("Signing CMP message failed.", msg);
        //******************************************''''''
        Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getAlgorithm().getId(), "BC");
        sig.initVerify(ra2admincert.getPublicKey());
        sig.update(CmpMessageHelper.getProtectedBytes(msg));
        boolean verified = sig.verify(msg.getProtection().getBytes());
        assertTrue("Signing the message failed.", verified);
        //***************************************************
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, RA1_ALIAS);
        checkCmpResponseGeneral(resp, ca1.getSubjectDN(), testUserDN, ca1.getCACertificate(), 
                msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), 
                false, null, null);
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        PKIMessage respObject = null;
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull("Reading CMP response failed.", respObject);
        PKIBody body = respObject.getBody();
        assertEquals(PKIBody.TYPE_ERROR, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        String expectedErrMsg = "'CN=" + RA2_ADMIN + "' is not an authorized administrator.";
        assertEquals(expectedErrMsg, errMsg);

            
        
        // Send CRMF message signed by RA1Admin to RA2
        testUsername = "ra2testuser";
        testUserDN = new X500Name("CN=" + testUsername);
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        msg = genCertReq(ca2.getSubjectDN(), testUserDN, keys, ca2.getCACertificate(), nonce, 
                transid, false, null, null, null, null, pAlg, new DEROctetString(nonce));
        assertNotNull("Generating CrmfRequest failed.", msg);
        
        extraCert = getCMPCert(ra1admincert);
        msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, ra1adminkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull("Signing CMP message failed.", msg);
        //******************************************''''''
        sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getAlgorithm().getId(), "BC");
        sig.initVerify(ra1admincert.getPublicKey());
        sig.update(CmpMessageHelper.getProtectedBytes(msg));
        verified = sig.verify(msg.getProtection().getBytes());
        assertTrue("Signing the message failed.", verified);
        //***************************************************
        
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(msg);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpHttp(ba, 200, RA2_ALIAS);
        checkCmpResponseGeneral(resp, ca2.getSubjectDN(), testUserDN, ca2.getCACertificate(), msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                .getTransactionID().getOctets(), false, null, null);
        asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull("Reading CMP response failed.", respObject);
        body = respObject.getBody();
        assertEquals(PKIBody.TYPE_ERROR, body.getType());
        err = (ErrorMsgContent) body.getContent();
        errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        expectedErrMsg = "'CN=" + RA1_ADMIN + "' is not an authorized administrator.";
        assertEquals(expectedErrMsg, errMsg);
        
    }

    
    
    
    /**
     * 1- Sends a revocation request signed by RA2Admin to RA1. Expected: Fail
     * 2- Sends a revocation request signed by RA1Admin to RA1. Expected: Success
     * 
     * @throws Exception
     */
    @Test
    public void test03RevocationRequest() throws Exception {

        String username = "ra1testuser";
        String fingerprintCert = null;
        try {
            
            // Issue a cert by CA1
            String userDN = "CN="+username;
            createUser(username, userDN, "foo123", true, ca1.getCAId(), 
                    endEntityProfileSession.getEndEntityProfileId(EEP1), certProfileSession.getCertificateProfileId(CP1));
            KeyPair userkeys = KeyTools.genKeys("1024", "RSA");
            Certificate cert = signSession.createCertificate(ADMIN, username, "foo123", new PublicKeyWrapper(userkeys.getPublic()));
            assertNotNull("No certificate to revoke.", cert);
            fingerprintCert = CertTools.getFingerprintAsString(cert);

            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
            PKIMessage msg = genRevReq(ca1.getSubjectDN(), new X500Name(userDN), CertTools.getSerialNumber(cert), ca1.getCACertificate(), 
                    nonce, transid, false, pAlg, null);
            assertNotNull("Generating revocation request failed.", msg);

            // Sign the revocation request with RA2 Admin
            CMPCertificate[] extraCert = getCMPCert(ra2admincert);
            PKIMessage protectedMsg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, ra2adminkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            assertNotNull("Signing CMP message failed.", protectedMsg);

            // Send the CMP request to RA1. Expected: Fail
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(protectedMsg);
            byte[] ba = bao.toByteArray();
            byte[] resp = sendCmpHttp(ba, 200, RA1_ALIAS);
            checkCmpResponseGeneral(resp, ca1.getSubjectDN(), new X500Name(userDN), ca1.getCACertificate(), 
                    msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), 
                    false, null, null);
            ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
            final PKIMessage respObject;
            try {
                respObject = PKIMessage.getInstance(asn1InputStream.readObject());
            } finally {
                asn1InputStream.close();
            }
            assertNotNull("Reading CMP response failed.", respObject);
            PKIBody body = respObject.getBody();
            assertEquals(PKIBody.TYPE_ERROR, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            String expectedErrMsg = "'CN=" + RA2_ADMIN + "' is not an authorized administrator.";
            assertEquals(expectedErrMsg, errMsg);

            
            // Sign the revocation request with RA1 Admin
            extraCert = getCMPCert(ra1admincert);
            protectedMsg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, ra1adminkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            assertNotNull("Signing CMP message failed.", protectedMsg);

            // Send the CMP request to RA1. Expected: Success
            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(protectedMsg);
            ba = bao.toByteArray();
            resp = sendCmpHttp(ba, 200, RA1_ALIAS);
            checkCmpResponseGeneral(resp, ca1.getSubjectDN(), new X500Name(userDN), ca1.getCACertificate(), 
                    msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), 
                    true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revStatus = checkRevokeStatus(ca1.getSubjectDN(), CertTools.getSerialNumber(cert));
            assertNotEquals("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
        } finally {
            internalCertStoreSession.removeCertificate(fingerprintCert);
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, username, ReasonFlags.unused);
        }
    }
    
    /**
     * Sends a revocation request signed by RA2Admin to revoke a certificate issued by a CA RA2Admin is not authorized to. Expected: Fail
     * 
     * @throws Exception
     */
    @Test
    public void test04RevocationRequest() throws Exception {

        String username = "ra1testuser";
        String fingerprintCert = null;
        try {
            
            // Issue a cert by CA1
            String userDN = "CN="+username;
            createUser(username, userDN, "foo123", true, ca1.getCAId(), 
                    endEntityProfileSession.getEndEntityProfileId(EEP1), certProfileSession.getCertificateProfileId(CP1));
            KeyPair userkeys = KeyTools.genKeys("1024", "RSA");
            Certificate cert = signSession.createCertificate(ADMIN, username, "foo123", new PublicKeyWrapper(userkeys.getPublic()));
            assertNotNull("No certificate to revoke.", cert);
            fingerprintCert = CertTools.getFingerprintAsString(cert);

            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
            PKIMessage msg = genRevReq(ca1.getSubjectDN(), new X500Name(userDN), CertTools.getSerialNumber(cert), ca1.getCACertificate(), 
                    nonce, transid, false, pAlg, null);
            assertNotNull("Generating revocation request failed.", msg);

            // Sign the revocation request with RA2 Admin
            CMPCertificate[] extraCert = getCMPCert(ra2admincert);
            PKIMessage protectedMsg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, ra2adminkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            assertNotNull("Signing CMP message failed", protectedMsg);

            // Send the CMP request to RA2. Expected: Fail
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(protectedMsg);
            byte[] ba = bao.toByteArray();
            byte[] resp = sendCmpHttp(ba, 200, RA2_ALIAS);
            checkCmpResponseGeneral(resp, ca1.getSubjectDN(), new X500Name(userDN), ca1.getCACertificate(), 
                    msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), 
                    false, null, null);
            ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
            final PKIMessage respObject;
            try {
                respObject = PKIMessage.getInstance(asn1InputStream.readObject());
            } finally {
                asn1InputStream.close();
            }
            assertNotNull("Reading CMP response failed.", respObject);
            PKIBody body = respObject.getBody();
            assertEquals(PKIBody.TYPE_ERROR, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            String expectedErrMsg = "'CN=" + RA2_ADMIN + "' is not an authorized administrator.";
            assertEquals(expectedErrMsg, errMsg);

        } finally {
            internalCertStoreSession.removeCertificate(fingerprintCert);
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, username, ReasonFlags.unused);
        }
    }
    
    
    
    private static CMPCertificate[] getCMPCert(Certificate cert) throws CertificateEncodingException, IOException {
        ASN1InputStream ins = new ASN1InputStream(cert.getEncoded());
        ASN1Primitive pcert = ins.readObject();
        ins.close();
        org.bouncycastle.asn1.x509.Certificate c = org.bouncycastle.asn1.x509.Certificate.getInstance(pcert.toASN1Primitive());
        CMPCertificate[] res = { new CMPCertificate(c) };
        return res;
    }

    private EndEntityInformation createUser(String username, String subjectDN, String password, boolean clearpassword, int _caid, int eepid, int cpid)
            throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, EjbcaException, Exception {

        EndEntityInformation user = new EndEntityInformation(username, subjectDN, _caid, null, username + "@primekey.se", new EndEntityType(
                EndEntityTypes.ENDUSER), eepid, cpid, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword(password);
        try {
            endEntityManagementSession.addUser(ADMIN, user, clearpassword);
            log.debug("created user: " + username);
        } catch (EndEntityExistsException e) {
            log.debug("User " + username + " already exists. Setting the user status to NEW");
            endEntityManagementSession.changeUser(ADMIN, user, clearpassword);
            endEntityManagementSession.setUserStatus(ADMIN, username, EndEntityConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }

        return user;

    }

    private static X509Certificate getCertFromAuthenticationToken(AuthenticationToken authToken) {
        X509Certificate certificate = null;
        Set<?> inputcreds = authToken.getCredentials();
        if (inputcreds != null) {
            for (Object object : inputcreds) {
                if (object instanceof X509Certificate) {
                    certificate = (X509Certificate) object;
                }
            }
        }
        return certificate;
    }

    private AuthenticationToken createAdminToken(KeyPair keys, String name, String dn, int _caid, int eepid, int cpid) throws RoleNotFoundException,
            AuthorizationDeniedException {
        Set<Principal> principals = new HashSet<Principal>();
        X500Principal p = new X500Principal(dn);
        principals.add(p);
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        AuthenticationToken token = createTokenWithCert(name, subject, keys, _caid, eepid, cpid);
        assertNotNull("Failed to create authentication token.", token);
        X509Certificate cert = (X509Certificate) token.getCredentials().iterator().next();
        assertNotNull("Failed to retrieve authentication token certificate.", cert);
        return token;
    }

    private AuthenticationToken createTokenWithCert(String adminName, AuthenticationSubject subject, KeyPair keys, int _caid, int eepid, int cpid) {

        // A small check if we have added a "fail" credential to the subject.
        // If we have we will return null, so we can test authentication failure.
        Set<?> usercredentials = subject.getCredentials();
        if ((usercredentials != null) && (usercredentials.size() > 0)) {
            Object o = usercredentials.iterator().next();
            if (o instanceof String) {
                String str = (String) o;
                if (StringUtils.equals("fail", str)) {
                    return null;
                }
            }
        }

        X509Certificate certificate = null;
        // If there was no certificate input, create a self signed
        String dn = "CN="+adminName;
        // If we have created a subject with an X500Principal we will use this DN to create the dummy certificate.
        {
            Set<Principal> principals = subject.getPrincipals();
            if ((principals != null) && (principals.size() > 0)) {
                Principal p = principals.iterator().next();
                if (p instanceof X500Principal) {
                    X500Principal xp = (X500Principal) p;
                    dn = xp.getName();
                }
            }
        }

        try {
            createUser(adminName, dn, "foo123", true, _caid, eepid, cpid);
        } catch (AuthorizationDeniedException e1) {
            throw new IllegalStateException(e1.getLocalizedMessage(), e1);
        } catch (UserDoesntFullfillEndEntityProfile e1) {
            throw new IllegalStateException(e1.getLocalizedMessage(), e1);
        } catch (WaitingForApprovalException e1) {
            throw new IllegalStateException(e1.getLocalizedMessage(), e1);
        } catch (EjbcaException e1) {
            throw new IllegalStateException(e1.getLocalizedMessage(), e1);
        } catch (Exception e1) {
            throw new IllegalStateException(e1.getLocalizedMessage(), e1);
        }

        try {
            certificate = (X509Certificate) signSession.createCertificate(ADMIN, adminName, "foo123", new PublicKeyWrapper(keys.getPublic()));
        } catch (ObjectNotFoundException e) {
            throw new IllegalStateException(e.getLocalizedMessage(), e);
        } catch (CADoesntExistsException e) {
            throw new IllegalStateException(e.getLocalizedMessage(), e);
        } catch (EjbcaException e) {
            throw new IllegalStateException(e.getLocalizedMessage(), e);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e.getLocalizedMessage(), e);
        } catch (CesecoreException e) {
            throw new IllegalStateException(e.getLocalizedMessage(), e);
        }
        assertNotNull("Failed to create a test user certificate", certificate);
        // We cannot use the X509CertificateAuthenticationToken here, since it can only be used internally in a JVM.
        AuthenticationToken result = new TestX509CertificateAuthenticationToken(certificate);
        assertNotNull("Failed to create authentication token.", result);
        return result;
    }
    
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

}
