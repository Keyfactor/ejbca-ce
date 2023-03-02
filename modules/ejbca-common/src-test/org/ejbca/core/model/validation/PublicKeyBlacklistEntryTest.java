/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.validation;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import org.junit.Test;

import com.keyfactor.util.CertTools;

/**
 * Unit tests for {@link PublicKeyBlacklistEntry}.
 *
 * @version $Id$
 */
public class PublicKeyBlacklistEntryTest {

    /**
     * Test if the Debian fingerprint was created correctly.
     * 
     * Expected:
     * > openssl x509 -noout -pubkey -inform PEM -in cert.pem  | openssl rsa -pubin -noout -modulus | sha1sum | cut -d ' ' -f 1 | cut -c 21-
     * add2d8bc7fed9c871977
     */
    @Test
    public void testCreateDebianFingerprint() throws Exception {
        final List<X509Certificate> certificates = CertTools.getCertsFromPEM(
                new ByteArrayInputStream(new String("-----BEGIN CERTIFICATE-----\n"
                        + "MIIDlTCCAn2gAwIBAgIQWUf8WBdIUqmQdolvLQyYqDANBgkqhkiG9w0BAQsFADBW\n"
                        + "MSAwHgYDVQQDDBdTdG9ybWh1YiBSU0EgU3RhZ2luZyBHMTElMCMGA1UECgwcU3Rv\n"
                        + "cm1odWIgVHJ1c3QgU2VydmljZXMgTHRkLjELMAkGA1UEBhMCU0UwHhcNMjAwMzE3\n"
                        + "MTAyOTEzWhcNMjAwMzE4MTAyOTEzWjAVMRMwEQYDVQQDDApkZWJpYW4uY29tMIIB\n"
                        + "IDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAyW+DrDnwFuNwDShOUwjo2eCH\n"
                        + "O2MzNkvCiQZHfUk4uXVF+960kwoTS34sBvEpti3IfDPQFG6gSXkz+I9uTWkq38EG\n"
                        + "uo3qVyzyWthxGN7eooemofHmptS6+aGWK13gLsb2jMEnDIkIL0Bp7ZVT7qaX947d\n"
                        + "N8Xhctfcm0wBaSArE82/47+KqcJXqBIROtc64BG5U38r2js7QIYniHMJCcSuQ4KC\n"
                        + "RuuvO+12dmfcNEh3T9brrtQfRumM0nlFePzaCawIHnvrmmyUZ5iAkbI0I3ipTnDj\n"
                        + "ewlqp7PO5nFCfzJfbSIpZHKdlseLrbJU7gYs1Z59NDGDMbAj28DnB+R7b3CvJwIB\n"
                        + "I6OBoTCBnjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFAsTh1pz0ZssvmRJH7V9\n"
                        + "uJ9tL619MBUGA1UdEQQOMAyCCmRlYmlhbi5jb20wJwYDVR0lBCAwHgYIKwYBBQUH\n"
                        + "AwIGCCsGAQUFBwMEBggrBgEFBQcDATAdBgNVHQ4EFgQU+74y/VingyWv2uirnQku\n"
                        + "uAP6Fm4wDgYDVR0PAQH/BAQDAgWgMA0GCSqGSIb3DQEBCwUAA4IBAQAJeA8Zl8I6\n"
                        + "Ak3riymnogedaiz6xw3ugxw01Y5xtY85e3g0Bs8+VsLrX+kkqUBHL2O2PzJg7in6\n"
                        + "tpniV0IQtOxXxfQyDI+YZqGlOSST/0J2RySLAFOqC9nnzfKXU0m2z6fhaDxlL5b2\n"
                        + "w2BCcyeSf9vHVCw2icCKzijvPdjtfr9hOrYgmCnZNix3DM0X5mbAdPPm1AFgMy+0\n"
                        + "XV4vu3vzf8W/bREXJ9mYMqqTWHdgWBE3YFVChDTr7EXH91aiPBC/WoRcRf2D5tNs\n"
                        + "WSvSvX1yPtn0nQ40TpEUF8Lc4LjcxLc/lIethA1PxDxXpsJg6m2ZRVCxOEnVZ8rf\n" 
                        + "OcGbx3fu8aBe\n" 
                        + "-----END CERTIFICATE-----").getBytes()),
                X509Certificate.class);

        final X509Certificate certificate = certificates.get(0);
        final RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
        final String fingerprint = PublicKeyBlacklistEntry.createDebianFingerprint(publicKey);
        assertEquals("add2d8bc7fed9c871977", fingerprint);
    }
}
