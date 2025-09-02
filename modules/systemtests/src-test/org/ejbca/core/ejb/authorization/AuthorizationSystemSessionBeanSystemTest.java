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
package org.ejbca.core.ejb.authorization;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Random;

import org.cesecore.WebTestUtils;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.db.DatabaseContentRule;
import org.ejbca.core.model.era.RaAuthorizationResult;
import org.ejbca.core.model.era.TestRaMasterApiProxySessionRemote;
import org.junit.ClassRule;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Test of AuthorizationSystemSessionBean functionality.
 * 
 * @version $Id$
 */
public class AuthorizationSystemSessionBeanSystemTest {

    private final TestRaMasterApiProxySessionRemote raMasterApiProxyBean = EjbRemoteHelper.INSTANCE
            .getRemoteSession(TestRaMasterApiProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = 
            EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @ClassRule
    public static DatabaseContentRule databaseContentRule = new DatabaseContentRule();

    
    private TestX509CertificateAuthenticationToken getNestedX509TestToken(String roleName) throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        final KeyPair keyPair = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate authCert = WebTestUtils.setUpClientCertificate(roleName, keyPair.getPublic());
        TestX509CertificateAuthenticationToken authToken = new TestX509CertificateAuthenticationToken(authCert);
        authToken.appendNestedAuthenticationToken(new TestAlwaysAllowLocalAuthenticationToken(roleName));
        return authToken;
    }
    
    @Test
    public void testAccessRevokedCert() throws Exception {
        final String roleName = "AuthSystemSesBeanTest.testAccessRevokedCert" + new Random().nextInt();
        // if cert is revoked then no access rule is set
        try {
            TestX509CertificateAuthenticationToken authToken = getNestedX509TestToken(roleName);
            // revoke first and then check access to skip cache population
            internalCertificateStoreSession.setRevokeStatus(
                    new TestAlwaysAllowLocalAuthenticationToken(roleName), authToken.getCertificate(), null, null, 0);
            RaAuthorizationResult accessRules = raMasterApiProxyBean.getAuthorization(authToken);
            assertNotNull("accessRules is not fetched.", accessRules);
            assertTrue("accessRules should be empty for revoked certs.", accessRules.getAccessRules().isEmpty());
        } finally {
            WebTestUtils.cleanUpClientCertificate(roleName);
        }
        
        // if cert is not revoked then root access rule is set as per test setup
        try {
            TestX509CertificateAuthenticationToken authToken = getNestedX509TestToken(roleName);
            RaAuthorizationResult accessRules = raMasterApiProxyBean.getAuthorization(authToken);
            assertNotNull("accessRules is not fetched.", accessRules);
            assertEquals("accessRules should have root access.", accessRules.getAccessRules().size(), 1);
        } finally {
            WebTestUtils.cleanUpClientCertificate(roleName);
        }
    }

}
