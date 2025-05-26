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
 
 
package org.ejbca.core.ejb.ws;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionBeanSystemTest;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.certificate.SimpleCertGenerator;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

public class EjbcaWSHelperSessionBeanSystemTest {
    private final EjbcaWSHelperProxySessionRemote ejbcaWSHelperProxySessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(EjbcaWSHelperProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final Logger log = Logger.getLogger(EjbcaWSHelperSessionBeanSystemTest.class);

    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static KeyPair keys;

    private final TestAlwaysAllowLocalAuthenticationToken internalToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            WebAuthenticationProviderSessionBeanSystemTest.class.getSimpleName()));

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }

    @Test
    public void getAdmin_CertOrOauthTokenRequired() throws AuthorizationDeniedException {
        log.trace(">getAdmin_CertOrOauthTokenRequired");
        Throwable throwable =  assertThrows(Throwable.class, () -> {
            ejbcaWSHelperProxySessionRemote.getAdmin(false, null, null);
        });
        assertEquals("Incorrect exception was thrown.", AuthorizationDeniedException.class, throwable.getClass());
        assertEquals("Incorrect error message in exception.", "Authorization failed. No certificates or OAuth token provided.", throwable.getMessage()); 
        log.trace("<getAdmin_CertOrOauthTokenRequired");
    }

    @Test
    public void getAdmin_OauthIsCalled() throws AuthorizationDeniedException {
        log.trace(">getAdmin_OauthIsCalled");
        Throwable throwable =  assertThrows(Throwable.class, () -> {
            ejbcaWSHelperProxySessionRemote.getAdmin(false, null, "BAD_TOKEN");
        });
        assertEquals("Incorrect exception was thrown.", AuthorizationDeniedException.class, throwable.getClass());
        assertEquals("Incorrect error message in exception.", "Authentication failed using OAuth Bearer Token.", throwable.getMessage()); 
        log.trace("<getAdmin_OauthIsCalled");
    }

    @Test
    public void getAdmin_certificateTokenIsCreated() throws IllegalStateException, OperatorCreationException, CertificateException, AuthorizationDeniedException, CertIOException  {
        log.trace(">getAdmin_certificateTokenIsCreated");
        X509Certificate certificate = SimpleCertGenerator.forTESTLeafCert()
                .setSubjectDn("CN=Foo")
                .setIssuerDn("CN=Foo")
                .setValidityDays(1)
                .setIssuerPrivKey(keys.getPrivate())
                .setEntityPubKey(keys.getPublic())
                .setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA)
                .setLdapOrder(true)
                .generateCertificate();

        try {
            certificateStoreSession.storeCertificateRemote(internalToken, EJBTools.wrap(certificate), "foo", "1234",
                    CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    EndEntityConstants.NO_END_ENTITY_PROFILE,
                    CertificateConstants.NO_CRL_PARTITION, "footag", new Date().getTime(), null);

            AuthenticationToken authenticationToken = ejbcaWSHelperProxySessionRemote.getAdmin(true, certificate, null);

            assertNotNull("Authentication was not returned for active (but soon to expire) cert", authenticationToken);
        } finally {
            internalCertificateStoreSession.removeCertificate(certificate);
        }
        log.trace("<getAdmin_certificateTokenIsCreated");
    }
}
