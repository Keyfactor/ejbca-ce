/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.keyrecovery.KeyRecoveryData;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the key recovery modules.
 * 
 * @version $Id$
 */
public class KeyRecoveryTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(KeyRecoveryTest.class);
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("KeyRecoveryTest"));
    private static final String user = genRandomUserName();
    private static KeyPair keypair = null;
    private static X509Certificate cert = null;

    private static final String KEYRECOVERY_ROLE = "KEYRECOVERYROLE";

    private KeyRecoverySessionRemote keyRecoverySession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private EndEntityManagementSessionRemote userAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);

    private AuthenticationToken admin;

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();

    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        admin = createCaAuthenticatedToken();

        RoleData role = roleManagementSession.create(internalAdmin, KEYRECOVERY_ROLE);
        Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
        subjects.add(new AccessUserAspectData(KEYRECOVERY_ROLE, getTestCAId(), X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE,
                CertTools.getPartFromDN(CertTools.getSubjectDN(getTestCACert()), "CN")));
        role = roleManagementSession.addSubjectsToRole(internalAdmin, role, subjects);
        Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(KEYRECOVERY_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + SecConst.EMPTY_ENDENTITYPROFILE
                + AccessRulesConstants.KEYRECOVERY_RIGHTS, AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(KEYRECOVERY_ROLE, AccessRulesConstants.REGULAR_KEYRECOVERY, AccessRuleState.RULE_ACCEPT, true));
        role = roleManagementSession.addAccessRulesToRole(internalAdmin, role, accessRules);
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        roleManagementSession.remove(internalAdmin, KEYRECOVERY_ROLE);

    }

    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    /**
     * tests adding a keypair and checks if it can be read again.
     * 
     * @throws Exception error
     */
    @Test
    public void testAddAndRemoveKeyPair() throws Exception {
        log.trace(">test01AddKeyPair()");
        // Generate test keypair and certificate.
        try {
            try {
                String email = "test@test.se";
                if (!userAdminSession.existsUser(user)) {
                    keypair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
                    userAdminSession.addUser(internalAdmin, user, "foo123", "CN=TESTKEYREC" + new Random().nextLong(), "rfc822name=" + email, email, false,
                            SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0,
                            getTestCAId());
                    cert = (X509Certificate) signSession.createCertificate(internalAdmin, user, "foo123", keypair.getPublic());
                    Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
                    accessRules.add(new AccessRuleData(KEYRECOVERY_ROLE, StandardRules.CAACCESS.resource() + CertTools.getIssuerDN(cert).hashCode(), AccessRuleState.RULE_ACCEPT, false));
                    roleManagementSession.addAccessRulesToRole(internalAdmin, roleAccessSession.findRole(KEYRECOVERY_ROLE), accessRules);
                }
            } catch (Exception e) {
                log.error("Exception generating keys/cert: ", e);
                fail("Exception generating keys/cert");
            }
            keyRecoverySession.addKeyRecoveryData(internalAdmin, cert, user, keypair);
            assertTrue("Couldn't save key's in database", keyRecoverySession.existsKeys(cert));
            log.trace("<test01AddKeyPair()");
            log.trace(">test02MarkAndRecoverKeyPair()");
            assertFalse("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(user));
            userAdminSession.prepareForKeyRecovery(internalAdmin, user, SecConst.EMPTY_ENDENTITYPROFILE, cert);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(user));
            KeyRecoveryData data = keyRecoverySession.keyRecovery(admin, user, SecConst.EMPTY_ENDENTITYPROFILE);

            assertTrue("Couldn't recover keys from database",
                    Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair.getPrivate().getEncoded()));
            log.trace("<test02MarkAndRecoverKeyPair()");
        } finally {
            log.trace(">test03RemoveKeyPair()");
            keyRecoverySession.removeKeyRecoveryData(internalAdmin, cert);
            assertTrue("Couldn't remove keys from database", !keyRecoverySession.existsKeys(cert));
            log.trace("<test03RemoveKeyPair()");
        }
    }
}
