/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.proxyca;

import org.cesecore.util.EjbRemoteHelper;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class KeyFactorCommandSessionBeanSystemTest {

    private KeyFactorCommandSessionRemote keyFactorCommandSessionRemote;

    @Before
    public void setUp() throws Exception {
        keyFactorCommandSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyFactorCommandSessionRemote.class, EjbRemoteHelper.MODULE_EJBCA);
    }

    @Test
    public void testGetCertificates() throws Exception {
        // Given

        // When
        var actual = keyFactorCommandSessionRemote.getCertificates();

        // Then
        assertNotNull(actual);
        assertFalse("There are no certificates", actual.isEmpty());
    }

    @Test
    public void testGetExistingCertificate() throws Exception {
        // Given
        var certificates = keyFactorCommandSessionRemote.getCertificates();
        var entry = certificates.entrySet().iterator().next();
        int id = entry.getKey();
        X509Certificate expected = entry.getValue();

        // When
        var actual = keyFactorCommandSessionRemote.getCertificate(id);

        // Then
        assertNotNull(actual);
        assertEquals(expected, actual);
    }

    @Test
    public void testGetNonExistingCertificate() throws Exception {
        // Given
        var keys = keyFactorCommandSessionRemote.getCertificates().keySet();
        int nonExistingId = keys
                .stream()
                .max(Integer::compareTo)
                .orElse(0)+1;

        // When
        var actual = keyFactorCommandSessionRemote.getCertificate(nonExistingId);

        // Then
        assertNull(actual);
    }

}
