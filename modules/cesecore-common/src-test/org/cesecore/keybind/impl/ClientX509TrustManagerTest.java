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
package org.cesecore.keybind.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

/**
 * Test of ClientX509TrustManager.
 * 
 * @version $Id$
 */
public class ClientX509TrustManagerTest {

    private static final Logger log = Logger.getLogger(ClientX509TrustManagerTest.class);

    @Rule
    public final TestWatcher traceLogMethodsRule = new TestWatcher() {
        @Override
        protected void starting(final Description description) {
            log.trace(">" + description.getMethodName());
            super.starting(description);
        };
        @Override
        protected void finished(final Description description) {
            log.trace("<" + description.getMethodName());
            super.finished(description);
        }
    };

    @BeforeClass
    public static void beforeClass() throws Throwable {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void testFirstEncounteredServerCertificate() throws InvalidAlgorithmParameterException, OperatorCreationException, CertificateException {
        final KeyPair keyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate x509Certificate1 = CertTools.genSelfCert("CN=ClientX509TrustManagerTest1", 365, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false);
        final X509Certificate x509Certificate2 = CertTools.genSelfCert("CN=ClientX509TrustManagerTest2", 365, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false);
        final Collection<X509Certificate> trust1 = Arrays.asList(new X509Certificate[]{x509Certificate1});
        final List<Collection<X509Certificate>> trustedChains = new ArrayList<>();
        trustedChains.add(trust1);
        final ClientX509TrustManager clientX509TrustManager = new ClientX509TrustManager(trustedChains);
        assertNull("Validated server TLS certificate was encountered before validation.", clientX509TrustManager.getEncounteredServerCertificateChain());
        try {
            clientX509TrustManager.checkServerTrusted(new X509Certificate[] { x509Certificate2 }, null);
            fail("Untrusted certificate should not pass validation.");
        } catch (CertificateException e) {
            log.debug("Expected exception: " + e.getMessage());
        }
        // We should be able to see the remote TLS certificate even if it was not trusted
        assertNotNull("Validated server TLS certificate was not encountered.", clientX509TrustManager.getEncounteredServerCertificateChain());
        assertNotNull("Validated server TLS certificate was not encountered.", clientX509TrustManager.getEncounteredServerCertificateChain().get(0));
        assertEquals("Validated server TLS certificate was not encountered.", CertTools.getFingerprintAsString(x509Certificate2),
                CertTools.getFingerprintAsString(clientX509TrustManager.getEncounteredServerCertificateChain().get(0)));
        clientX509TrustManager.checkServerTrusted(new X509Certificate[] { x509Certificate1 }, null);
        // Check trusted validation as well
        final ClientX509TrustManager clientX509TrustManager2 = new ClientX509TrustManager(trustedChains);
        clientX509TrustManager2.checkServerTrusted(new X509Certificate[] { x509Certificate1 }, null);
        assertNotNull("Validated server TLS certificate was not encountered.", clientX509TrustManager2.getEncounteredServerCertificateChain());
        assertNotNull("Validated server TLS certificate was not encountered.", clientX509TrustManager2.getEncounteredServerCertificateChain().get(0));
        assertEquals("Validated server TLS certificate was not encountered.", CertTools.getFingerprintAsString(x509Certificate1),
                CertTools.getFingerprintAsString(clientX509TrustManager2.getEncounteredServerCertificateChain().get(0)));
        // Check that the "first" encountered will change if validation would be done with another cert
        try {
            clientX509TrustManager2.checkServerTrusted(new X509Certificate[] { x509Certificate2 }, null);
            fail("Untrusted certificate should not pass validation.");
        } catch (CertificateException e) {
            log.debug("Expected exception: " + e.getMessage());
        }
        assertEquals("Validated server TLS certificate was not encountered.", CertTools.getFingerprintAsString(x509Certificate2),
                CertTools.getFingerprintAsString(clientX509TrustManager2.getEncounteredServerCertificateChain().get(0)));
    }
}
