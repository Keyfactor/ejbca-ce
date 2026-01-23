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

package org.ejbca.core.ejb.keyrecovery;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.dto.RoleDataDto;
import org.cesecore.dto.RoleDataDtoBuilder;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Tests the key recovery modules.
 */

public class KeyRecoveryModifiableKeyEncryptKeySystemTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(KeyRecoveryModifiableKeyEncryptKeySystemTest.class);
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("KeyRecoverySystemTest"));
    private static final String user = genRandomUserName();

    private static final String KEYRECOVERY_ROLE = "KEYRECOVERYROLE";
    private static final String TEST_EMAIL = "test@test.se";

    private static final KeyRecoverySessionRemote keyRecoverySession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class);
    private static final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private static final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private static final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private AuthenticationToken admin;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUpWithoutKek();
        admin = createCaAuthenticatedToken();
        final var allowed = Arrays.asList(
                AccessRulesConstants.ENDENTITYPROFILEPREFIX + EndEntityConstants.EMPTY_END_ENTITY_PROFILE + AccessRulesConstants.KEYRECOVERY_RIGHTS,
                AccessRulesConstants.REGULAR_KEYRECOVERY,
                StandardRules.CAACCESS.resource() + getTestCAId(),
                StandardRules.CAEDIT.resource()
        );
        final Map<String, Boolean> accessRules = new HashMap<>();
        allowed.forEach(rule -> accessRules.put(rule, RoleDataDto.STATE_ALLOW));
        final RoleDataDto role = new RoleDataDtoBuilder().setName(KEYRECOVERY_ROLE).setAccessRules(accessRules).build();
        final RoleDataDto persistedRole = roleSession.persistRole(internalAdmin, role);
        final RoleMember roleMember = new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, getTestCAId(), RoleMember.NO_PROVIDER,
                X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                DnComponents.getPartFromDN(CertTools.getSubjectDN(getTestCACert()), "CN"), persistedRole.id(), null);
        roleMemberSession.persist(internalAdmin, roleMember);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        final RoleDataDto role = roleSession.getRole(internalAdmin, null, KEYRECOVERY_ROLE);
        if (role!=null) {
            roleSession.deleteRoleIdempotent(internalAdmin, role.id());
        }
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
    
    @Test
    public void testKeyRecoveryFailWithNoKek() throws Exception {
        doKeyRecoverOperation(false, false);
    }
    
    @Test
    public void testKeyRecoveryWithKekSetAfterCaCreate() throws Exception {
        doKeyRecoverOperation(true, false);
    }
    
    @Test
    public void testKeyRecoveryWithKekRemovedAfterCertEnroll() throws Exception {
        doKeyRecoverOperation(true, true);
    }
    
    private void doKeyRecoverOperation(boolean setKek, boolean removeKek) throws Exception {
        
        if (setKek) {
            CAInfo retrievedCaInfo = getCAInfo(internalAdmin, getTestCAName());
            retrievedCaInfo.getCAToken().setProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS );
            caAdminSession.editCA(admin, retrievedCaInfo);
        }
        
        X509Certificate cert1 = null;
        String fp1 = null;
        final String userrsa = genRandomUserName();
        try {
            KeyPair keypair1 = null;
            try {
                if (!endEntityManagementSession.existsUser(userrsa)) {
                    keypair1 = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
                    final EndEntityInformation ee = new EndEntityInformation(userrsa, "CN=TESTKEYRECRSA" + new Random().nextLong(), getTestCAId(), "rfc822name=" + TEST_EMAIL, TEST_EMAIL,
                            EndEntityTypes.ENDUSER.toEndEntityType(), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                            EndEntityConstants.TOKEN_SOFT_P12, null);
                    ee.setPassword("foo123");
                    endEntityManagementSession.addUser(internalAdmin, ee, false);
                    cert1 = (X509Certificate) signSession.createCertificate(internalAdmin, userrsa, "foo123", new PublicKeyWrapper(keypair1.getPublic()));
                    fp1 = CertTools.getFingerprintAsString(cert1);
                }
            } catch (Exception e) {
                log.error("Exception generating keys/cert: ", e);
                fail("Exception generating keys/cert");
            }
            // Save the keys as key recovery data in the database
            if (!setKek) {
               try {
                    keyRecoverySession.addKeyRecoveryData(internalAdmin, EJBTools.wrap(cert1), user, EJBTools.wrap(keypair1));
                    fail("Key recovery data persistences should have failed.");
               } catch (CertificateCreateException e) {
                   return;
               } catch (Exception e) {
                   fail("Key recovery data persistences should have failed with proper exception.");
               }
            }
            assertTrue("Key recovery data should persist.", keyRecoverySession.addKeyRecoveryData(internalAdmin, EJBTools.wrap(cert1), user, EJBTools.wrap(keypair1)));
            assertFalse("User should not be marked for recovery in database", keyRecoverySession.isUserMarked(user));
            endEntityManagementSession.prepareForKeyRecovery(internalAdmin, user, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, cert1);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(user));
            
            if (removeKek) {
                CAInfo retrievedCaInfo = getCAInfo(internalAdmin, getTestCAName());
                retrievedCaInfo.getCAToken().setProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, CATokenConstants.CAKEY_ANY_PURPOSE_NONE_INDICATOR );
                caAdminSession.editCA(admin, retrievedCaInfo);
            }
            KeyRecoveryInformation data = keyRecoverySession.recoverKeys(admin, user, EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            assertNotNull("Couldn't recover keys from database", data);
            assertTrue("Couldn't recover keys from database", Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair1.getPrivate().getEncoded()));
        } finally {
            // Only clean up left.
            if (cert1 != null) {
                keyRecoverySession.removeKeyRecoveryData(internalAdmin, EJBTools.wrap(cert1));
                assertTrue("Couldn't remove keys from database", !keyRecoverySession.existsKeys(EJBTools.wrap(cert1)));
            }
            internalCertStoreSession.removeCertificate(fp1);
            endEntityManagementSession.deleteUser(internalAdmin, userrsa);
        }
    }
    
}
