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
package org.cesecore.roles.member;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.dto.RoleDataDto;
import org.cesecore.dto.RoleDataDtoBuilder;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationTokenMetaData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.certificate.SimpleCertGenerator;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * @version $Id$
 */
public class RoleMemberDataSessionSystemTest {

    private static final Logger log = Logger.getLogger(RoleMemberDataSessionSystemTest.class);
    
    private RoleMemberDataProxySessionRemote roleMemberProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberDataProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    
    private final AuthenticationToken alwaysAllowAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "RoleMemberDataSessionSystemTest"));
    private static final String TEST_ROLE_NAME = "RoleMemberDataSessionSystemTest";
    
    @BeforeClass
    public static void setUp() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    /**
     * Simple sanity test, meant to involve other session beans as little as possible.
     */
    @Test
    public void testCrudOperations() {
        log.debug(">testCrudOperations");
        assertNull("accessUserAspectManagerSession.find did not return null for a non existing object.",
                roleMemberProxySession.findRoleMember(0));
        final RoleMemberData roleMember = new RoleMemberData(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                RoleMember.NO_ISSUER, X500PrincipalAccessMatchValue.WITH_COUNTRY.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(), "SE",
                RoleMember.NO_ROLE, "Human readable comment");
        int roleMemberId = -1;
        try {
            roleMemberId = roleMemberProxySession.createOrEdit(roleMember);
            RoleMember createdRoleMember = roleMemberProxySession.findRoleMember(roleMemberId);
            assertNotNull("Role Member was not persisted sucessfully", createdRoleMember);
            createdRoleMember.setTokenMatchValue("DE");
            roleMemberProxySession.createOrEdit(createdRoleMember);
            RoleMember editedRoleMember = roleMemberProxySession.findRoleMember(roleMemberId);
            assertEquals("Role Member was not sucessfully edited.", "DE", editedRoleMember.getTokenMatchValue());

        } finally {
            roleMemberProxySession.remove(roleMemberId);
            assertNull("AccessUserAspectManagerSessionRemote did not properly remove an object.",  roleMemberProxySession.findRoleMember(roleMemberId));
        }
        log.debug("<testCrudOperations");
    }

    private RoleDataDto getRoleData(final String name) {
        return new RoleDataDtoBuilder()
                .setName(name)
                .build();
    }

    /**
     * Tests that optimized lookup of "preferred" match values is working (e.g. serial number for X.509 authentication tokens, and user name for CLI)
     */
    @Test
    public void testPreferredMatchValues() throws RoleExistsException, AuthorizationDeniedException, AuthenticationFailedException, InvalidAlgorithmParameterException, OperatorCreationException, CertificateException, CertIOException {
        log.debug(">testPreferredMatchValues");
        final RoleDataDto role1 = roleSession.persistRole(alwaysAllowAuthenticationToken, getRoleData(TEST_ROLE_NAME + "1"));
        final RoleDataDto role2 = roleSession.persistRole(alwaysAllowAuthenticationToken, getRoleData(TEST_ROLE_NAME + "2"));
        try {
            // Create certificates with the serial numbers
            KeyPair kp = KeyTools.genKeys("1024", "RSA");
            X509Certificate cert1 = SimpleCertGenerator.forTESTLeafCert()
                    .setSubjectDn("CN=TestPreferredMatchValues1")
                    .setIssuerDn("CN=TestPreferredMatchValues1")
                    .setValidityDays(10)
                    .setIssuerPrivKey(kp.getPrivate())
                    .setEntityPubKey(kp.getPublic())
                    .setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA)
                    .generateCertificate(); 
            X509Certificate cert2 = SimpleCertGenerator.forTESTLeafCert()
                    .setSubjectDn("CN=TestPreferredMatchValues2")
                    .setIssuerDn("CN=TestPreferredMatchValues2")
                    .setValidityDays(10)
                    .setIssuerPrivKey(kp.getPrivate())
                    .setEntityPubKey(kp.getPublic())
                    .setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA)
                    .generateCertificate(); 
            String serial1 = CertTools.getSerialNumberAsString(cert1);
            String serial2 = CertTools.getSerialNumberAsString(cert2);
            log.debug("Serial number for cert 1: "+ serial1);
            log.debug("Serial number for cert 2: "+ serial2);
            int caId1 = CertTools.getIssuerDN(cert1).hashCode();
            int caId2 = CertTools.getIssuerDN(cert2).hashCode();
            // Create test members
            createRoleMember(role1, X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, caId1,
                    X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue(), serial1);
            createRoleMember(role1, X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, caId2,
                    X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue(), serial2);
            createRoleMember(role2, X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, caId2,
                    X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue(), serial2); // serial number 2 matches both role 1 and 2
            createRoleMember(role1, UsernameBasedAuthenticationTokenMetaData.TOKEN_TYPE, RoleMember.NO_ISSUER, 0, "firstuser");
            createRoleMember(role1, UsernameBasedAuthenticationTokenMetaData.TOKEN_TYPE, RoleMember.NO_ISSUER, 0, "seconduser");
            createRoleMember(role2, UsernameBasedAuthenticationTokenMetaData.TOKEN_TYPE, RoleMember.NO_ISSUER, 0, "thirduser"); // "thirduser" matches role 2
            // Test
            final Set<Integer> role1IdSet = new HashSet<>(Arrays.asList(role1.id()));
            final Set<Integer> role2IdSet = new HashSet<>(Arrays.asList(role2.id()));
            final Set<Integer> role12IdSet = new HashSet<>(Arrays.asList(role1.id(), role2.id()));
            assertEquals(role1IdSet, roleMemberProxySession.getRoleIdsMatchingAuthenticationTokenOrFail(new UsernameBasedAuthenticationToken(new UsernamePrincipal("firstuser"))));
            assertEquals(role1IdSet, roleMemberProxySession.getRoleIdsMatchingAuthenticationTokenOrFail(new UsernameBasedAuthenticationToken(new UsernamePrincipal("seconduser"))));
            assertEquals(role2IdSet, roleMemberProxySession.getRoleIdsMatchingAuthenticationTokenOrFail(new UsernameBasedAuthenticationToken(new UsernamePrincipal("thirduser"))));
            assertEquals(role1IdSet, roleMemberProxySession.getRoleIdsMatchingAuthenticationTokenOrFail(new TestX509CertificateAuthenticationToken(cert1)));
            assertEquals(role12IdSet, roleMemberProxySession.getRoleIdsMatchingAuthenticationTokenOrFail(new TestX509CertificateAuthenticationToken(cert2)));
        } finally {
            roleSession.deleteRoleIdempotent(alwaysAllowAuthenticationToken, role1.id());
            roleSession.deleteRoleIdempotent(alwaysAllowAuthenticationToken, role2.id());
        }
        log.debug("<testPreferredMatchValues");
    }
    
    private int createRoleMember(final RoleDataDto role, final String tokenType, final int tokenIssuerId, final int matchKey, final String matchValue) {
        if (role.isIdUnassigned()) {
            throw new IllegalStateException("Missing RoleDataDto ID");
        }
        return roleMemberProxySession.createOrEdit(new RoleMember(tokenType, tokenIssuerId, RoleMember.NO_PROVIDER, matchKey, AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                matchValue, role.id(), null));
    }
}
