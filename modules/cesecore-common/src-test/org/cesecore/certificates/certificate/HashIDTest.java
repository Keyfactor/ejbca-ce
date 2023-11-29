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
package org.cesecore.certificates.certificate;

import static org.junit.Assert.assertEquals;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Unit tests for the HashID class
 * 
 * @version $Id$
 *
 */
public class HashIDTest {

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Test
    public void testSubjectDn() throws Exception {
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final String subjectDn = "CN=HashIDTest,O=Test,C=SE";
        X509Certificate testCertificate = CertTools.genSelfCert(subjectDn, 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        assertEquals(HashID.getFromSubjectDN(testCertificate).getKey(), HashID.getFromDNString(subjectDn).getKey());
        assertEquals(HashID.getFromSubjectDN(testCertificate).getKey(), HashID.getFromDNString(DnComponents.reverseDN(subjectDn)).getKey());
    }
}
