/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.util.cert;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.cert.Certificate;
import java.util.Collection;

import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.junit.Test;

/**
 *
 */
public class QcStatementExtensionTest {

    /** The reference certificate from RFC3739 */
    private static byte[] qcRefCert = Base64.decode(("MIIDEDCCAnmgAwIBAgIESZYC0jANBgkqhkiG9w0BAQUFADBIMQswCQYDVQQGEwJE"
            + "RTE5MDcGA1UECgwwR01EIC0gRm9yc2NodW5nc3plbnRydW0gSW5mb3JtYXRpb25z" + "dGVjaG5payBHbWJIMB4XDTA0MDIwMTEwMDAwMFoXDTA4MDIwMTEwMDAwMFowZTEL"
            + "MAkGA1UEBhMCREUxNzA1BgNVBAoMLkdNRCBGb3JzY2h1bmdzemVudHJ1bSBJbmZv" + "cm1hdGlvbnN0ZWNobmlrIEdtYkgxHTAMBgNVBCoMBVBldHJhMA0GA1UEBAwGQmFy"
            + "emluMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDc50zVodVa6wHPXswg88P8" + "p4fPy1caIaqKIK1d/wFRMN5yTl7T+VOS57sWxKcdDzGzqZJqjwjqAP3DqPK7AW3s"
            + "o7lBG6JZmiqMtlXG3+olv+3cc7WU+qDv5ZXGEqauW4x/DKGc7E/nq2BUZ2hLsjh9" + "Xy9+vbw+8KYE9rQEARdpJQIDAQABo4HpMIHmMGQGA1UdCQRdMFswEAYIKwYBBQUH"
            + "CQQxBBMCREUwDwYIKwYBBQUHCQMxAxMBRjAdBggrBgEFBQcJATERGA8xOTcxMTAx" + "NDEyMDAwMFowFwYIKwYBBQUHCQIxCwwJRGFybXN0YWR0MA4GA1UdDwEB/wQEAwIG"
            + "QDASBgNVHSAECzAJMAcGBSskCAEBMB8GA1UdIwQYMBaAFAABAgMEBQYHCAkKCwwN" + "Dg/+3LqYMDkGCCsGAQUFBwEDBC0wKzApBggrBgEFBQcLAjAdMBuBGW11bmljaXBh"
            + "bGl0eUBkYXJtc3RhZHQuZGUwDQYJKoZIhvcNAQEFBQADgYEAj4yAu7LYa3X04h+C" + "7+DyD2xViJCm5zEYg1m5x4znHJIMZsYAU/vJJIJQkPKVsIgm6vP/H1kXyAu0g2Ep"
            + "z+VWPnhZK1uw+ay1KRXw8rw2mR8hQ2Ug6QZHYdky2HH3H/69rWSPp888G8CW8RLU" + "uIKzn+GhapCuGoC4qWdlGLWqfpc=").getBytes());

    private static byte[] qcPrimeCert = Base64.decode(("MIIDMDCCAhigAwIBAgIIUDIxBvlO2qcwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
            + "AxMIQWRtaW5DQTExFTATBgNVBAoTDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw" + "HhcNMDYwMTIyMDgxNTU0WhcNMDgwMTIyMDgyNTU0WjAOMQwwCgYDVQQDEwNxYzIw"
            + "gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKkuPOqOEWCJH9xb11sS++vfKb/z" + "gHf2clwyf2vSFWTSDzQHOa2j5rwZ/F23X/mZl96fFAIfTBmr5dCwt0xAXZvTcKfO"
            + "RAcKl7ZBXvsAYvwl1KIUpA8NqEbgjwA+OaTdND2vpAhII7PoU4CkoNajy44EuL3Y" + "xP6KNWTMiks9KP5vAgMBAAGjgewwgekwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8E"
            + "BAMCBPAwJwYDVR0lBCAwHgYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDBzAd" + "BgNVHQ4EFgQUZsj/dUVp1FmOJpYZ2j5fYKIdXYowHwYDVR0jBBgwFoAUs8UBsa9O"
            + "S1c8/I07DHYFJp0po0AwYAYIKwYBBQUHAQMEVDBSMCMGCCsGAQUFBwsBMBcGAykB" + "AjAQgQ5xY0BwcmltZWtleS5zZTAIBgYEAI5GAQEwFwYGBACORgECMA0TA1NFSwID"
            + "AMNQAgEAMAgGBgQAjkYBBDANBgkqhkiG9w0BAQUFAAOCAQEAjmL27XY5Wt0/axsI" + "PbtcfrJ6xEm5PlYabM+T3I6lksov6Rz1+/n/L1S5poGPG8iOdJCExcnR0HbNkeB+"
            + "2oPltqSaxyoSfGugVn/Oufz2BfFd7OCWe14dPsA181oC7/nq+mzhBpQ7App9JirA" + "aeJQrcRDNK7vVOmg2LZ2oSYno/TuRTFq0GxsEVjEdzAxpAxY7N8ff6gY7IHd7+hc"
            + "4GiFY+NnNp9Dvf6mOYTXLxsOc+093S7uK2ohhq99aYCkzJmrngtrImtKi0y/LMjq" + "oviMCQmzMLY2Ifcw+CsOyQZx7nxwafZ7BAzm6vIvSeiIe3VlskRGzYDM66NJJNNo"
            + "C2HsPA==").getBytes());
    
    @Test
    public void testQCStatement() throws Exception {
        Certificate cert = CertTools.getCertfromByteArray(qcRefCert, Certificate.class);
        // log.debug(cert);
        assertEquals("rfc822name=municipality@darmstadt.de", QCStatementExtension.getQcStatementAuthorities(cert));
        Collection<String> ids = QCStatementExtension.getQcStatementIds(cert);
        assertTrue(ids.contains(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2.getId()));
        Certificate cert2 = CertTools.getCertfromByteArray(qcPrimeCert, Certificate.class);
        assertEquals("rfc822name=qc@primekey.se", QCStatementExtension.getQcStatementAuthorities(cert2));
        ids = QCStatementExtension.getQcStatementIds(cert2);
        assertTrue(ids.contains(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1.getId()));
        assertTrue(ids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId()));
        assertTrue(ids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.getId()));
        assertTrue(ids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue.getId()));
        String limit = QCStatementExtension.getQcStatementValueLimit(cert2);
        assertEquals("50000 SEK", limit);
    }

}
