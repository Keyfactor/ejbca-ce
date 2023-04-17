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

package org.ejbca.ui.cli.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;

/**
 * System test for {@link CaImportMsCaCertificates}.
 * 
 * <p>Run these tests with:
 * 
 * <pre>ant test:runone -Dtest.runone=CaImportMsCaCertificatesTest</pre>.
 * 
 * @version $Id$
 */
public class CaImportMsCaCertificatesTest {
    private AuthenticationToken getAuthenticationToken() {
        return new TestAlwaysAllowLocalAuthenticationToken(CaImportMsCaCertificatesTest.class.getSimpleName());
    }

    @Before
    public void setUp() throws Exception {
        final String issuerCertificatePem = "-----BEGIN CERTIFICATE-----\n" + 
                "MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/\n" + 
                "MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n" + 
                "DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\n" + 
                "SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT\n" + 
                "GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" + 
                "AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF\n" + 
                "q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8\n" + 
                "SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0\n" + 
                "Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA\n" + 
                "a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj\n" + 
                "/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T\n" + 
                "AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG\n" + 
                "CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv\n" + 
                "bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k\n" + 
                "c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw\n" + 
                "VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC\n" + 
                "ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz\n" + 
                "MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu\n" + 
                "Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF\n" + 
                "AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo\n" + 
                "uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/\n" + 
                "wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu\n" + 
                "X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG\n" + 
                "PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6\n" + 
                "KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==\n" + 
                "-----END CERTIFICATE-----";
                
        EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).importCACertificate(
                getAuthenticationToken(),
                "Let's Encrypt Authority X3",
                Collections.singleton(EJBTools.wrap(CertTools.getCertfromByteArray(issuerCertificatePem.getBytes(), X509Certificate.class)))
        );
        
        final int certificateProfileId = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).addCertificateProfile(
                getAuthenticationToken(), 
                "MS_CA_CertificateTemplate", 
                new CertificateProfile()
        );
        
        final EndEntityProfile eeProfile = new EndEntityProfile(true /* add all standard fields */);
        eeProfile.setAvailableCertificateProfileIds(Collections.singleton(certificateProfileId));
        EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).addEndEntityProfile(
                getAuthenticationToken(),
                "MS_CA_CertificateTemplate", 
                eeProfile
        );
    }
    
    @After
    public void tearDown() throws Exception {
        EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).removeEndEntityProfile(
                getAuthenticationToken(), 
                "MS_CA_CertificateTemplate"
        );
        EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).removeCertificateProfile(
                getAuthenticationToken(), 
                "MS_CA_CertificateTemplate"
        );
        final Map<String, Integer> nameToId = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class)
                .getAuthorizedCaNamesToIds(getAuthenticationToken());
        final CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(
                getAuthenticationToken(), 
                nameToId.get("Let's Encrypt Authority X3")
        );
        CaTestUtils.removeCa(getAuthenticationToken(), cainfo);
    }

    @Test
    public void testImport3CertsWith1Duplicate() throws Exception {
        final File file = File.createTempFile("certutil_dump_", ".txt");
        try {
            final String testData = "\n" 
                    + "Schema:\n" 
                    + "  Column Name                   Localized Name                Type    MaxLength\n"
                    + "  ----------------------------  ----------------------------  ------  ---------\n"
                    + "  UPN                           User Principal Name           String  2048 -- Indexed\n"
                    + "  CertificateTemplate           Certificate Template          String  254 -- Indexed\n"
                    + "  Request.Disposition           Request Disposition           Long    4 -- Indexed\n"
                    + "  RawCertificate                Binary Certificate            Binary  16384\n" 
                    + "\n"
                    + "Row 1:\n"
                    + "  User Principal Name: admin1@signserver.org\n" 
                    + "  Certificate Template: \"1.2.3.4.5.6.7.8.9\" MS_CA_CertificateTemplate\n"
                    + "  Request Disposition: 0x14 (20) -- Issued\n" 
                    + "  Binary Certificate:\n" 
                    + "-----BEGIN CERTIFICATE-----\n"
                    + "MIIFbTCCBFWgAwIBAgISA44z8N0dF86ws/IQRS7LMHSnMA0GCSqGSIb3DQEBCwUA\n"
                    + "MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\n"
                    + "ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTA4MjYyMTA1MThaFw0x\n"
                    + "OTExMjQyMTA1MThaMB0xGzAZBgNVBAMTEnd3dy5zaWduc2VydmVyLm9yZzCCASIw\n"
                    + "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANQYaOfZ0Z7W3HhEAYC/gqAIjU6J\n"
                    + "DNfsJ/SBIcLjPbq7zVQ3f7sPBixfgpjZajKoeqx31h0xqNWZno9vvCxfmBf9WN26\n"
                    + "I+phECAedkkK3lDPKWNxQoLJ+9qd57gLthZJmcxPLsdIHOSRyKur8hr9+Nlx68d9\n"
                    + "TESIvW6HT2VYmcl1yBw+7dB5v6DZw0OSSdn3BCd2qC8pqYgS0JTtTGfqLrmJ6mNV\n"
                    + "hjnT34PpIjn/cmP1mgjZCxWT0oZNWBQZFAah8zHOQ33oiJUjvsYFbRp/RJIth/pE\n"
                    + "UddY7U2oP0lxxqmJoMJvAecPxPLx8rWT0F5BP/Al9slzwBAHmjXyOTMx1McCAwEA\n"
                    + "AaOCAngwggJ0MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI\n"
                    + "KwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUbMJRty6YPyTLZfg52Q49\n"
                    + "loJKc/QwHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwbwYIKwYBBQUH\n"
                    + "AQEEYzBhMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMubGV0c2VuY3J5\n"
                    + "cHQub3JnMC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMubGV0c2VuY3J5\n"
                    + "cHQub3JnLzAtBgNVHREEJjAkgg5zaWduc2VydmVyLm9yZ4ISd3d3LnNpZ25zZXJ2\n"
                    + "ZXIub3JnMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYI\n"
                    + "KwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBQYKKwYBBAHW\n"
                    + "eQIEAgSB9gSB8wDxAHcA4mlLribo6UAJ6IYbtjuD1D7n/nSI+6SPKJMBnd3x2/4A\n"
                    + "AAFsz/ZGsgAABAMASDBGAiEA6Ar9wrGOSXty5qOTZoHZ+T215P91Bwav78FyQSwn\n"
                    + "KlQCIQCkPik/K5J3p4buyNjKU4Z3tEMByoK58n77d9m6huc1rQB2ACk8UZZUyDll\n"
                    + "uqpQ/FgH1Ldvv1h6KXLcpMMM9OVFR/R4AAABbM/2RNUAAAQDAEcwRQIgPHQrwwOG\n"
                    + "d9NmDZvgNtMdxT4gyFTI4v07x3p5+o6HsywCIQCSUJ6fR6AEL2jphsLtb4FXO7Vf\n"
                    + "9Wu//lrAbdc+AIHHRzANBgkqhkiG9w0BAQsFAAOCAQEAJ0lKNjn1LmqpuugmCGl9\n"
                    + "tn3UUh/zkrHmt8nBv+YJcp/byD6IpY6X66vzrlI6EMqH5CVYQSjEXszJ2oC0+9Ml\n"
                    + "xftn0A1HS+/SCxHETPNAOcRqsS2/MrtDsO+dDU6eVpsrrbpyYhUWw9xR6RBVNl4F\n"
                    + "whBhV9LGooXwLFNMWaiUkqfRScS0hupAEWRAHbtZWKdiYV+vra9/zVrlAlS2ihDf\n"
                    + "Vtsu28nN/zDmHocoz2+d2CQaLjnaDYpuSztG6Tlj/e8FxcICxqvPE1wr/NFbKuro\n"
                    + "AxWnclrhKN+H7VscWR7ESoHT1ZcX5QhDABKKQNew1PEHNwGf1XrzL4uzNKtLypAW\n" 
                    + "/Q==\n" 
                    + "-----END CERTIFICATE-----\n"
                    + "Row 2:\n"
                    + "  User Principal Name: admin2@signserver.org\n" 
                    + "  Certificate Template: \"1.2.3.4.5.6.7.8.9\" MS_CA_CertificateTemplate\n"
                    + "  Request Disposition: 0x14 (20) -- Issued\n" 
                    + "  Binary Certificate:\n" 
                    + "-----BEGIN CERTIFICATE-----\n" + 
                    "MIIFbTCCBFWgAwIBAgISA44z8N0dF86ws/IQRS7LMHSnMA0GCSqGSIb3DQEBCwUA\n" + 
                    "MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\n" + 
                    "ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTA4MjYyMTA1MThaFw0x\n" + 
                    "OTExMjQyMTA1MThaMB0xGzAZBgNVBAMTEnd3dy5zaWduc2VydmVyLm9yZzCCASIw\n" + 
                    "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANQYaOfZ0Z7W3HhEAYC/gqAIjU6J\n" + 
                    "DNfsJ/SBIcLjPbq7zVQ3f7sPBixfgpjZajKoeqx31h0xqNWZno9vvCxfmBf9WN26\n" + 
                    "I+phECAedkkK3lDPKWNxQoLJ+9qd57gLthZJmcxPLsdIHOSRyKur8hr9+Nlx68d9\n" + 
                    "TESIvW6HT2VYmcl1yBw+7dB5v6DZw0OSSdn3BCd2qC8pqYgS0JTtTGfqLrmJ6mNV\n" + 
                    "hjnT34PpIjn/cmP1mgjZCxWT0oZNWBQZFAah8zHOQ33oiJUjvsYFbRp/RJIth/pE\n" + 
                    "UddY7U2oP0lxxqmJoMJvAecPxPLx8rWT0F5BP/Al9slzwBAHmjXyOTMx1McCAwEA\n" + 
                    "AaOCAngwggJ0MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI\n" + 
                    "KwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUbMJRty6YPyTLZfg52Q49\n" + 
                    "loJKc/QwHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwbwYIKwYBBQUH\n" + 
                    "AQEEYzBhMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMubGV0c2VuY3J5\n" + 
                    "cHQub3JnMC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMubGV0c2VuY3J5\n" + 
                    "cHQub3JnLzAtBgNVHREEJjAkgg5zaWduc2VydmVyLm9yZ4ISd3d3LnNpZ25zZXJ2\n" + 
                    "ZXIub3JnMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYI\n" + 
                    "KwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBQYKKwYBBAHW\n" + 
                    "eQIEAgSB9gSB8wDxAHcA4mlLribo6UAJ6IYbtjuD1D7n/nSI+6SPKJMBnd3x2/4A\n" + 
                    "AAFsz/ZGsgAABAMASDBGAiEA6Ar9wrGOSXty5qOTZoHZ+T215P91Bwav78FyQSwn\n" + 
                    "KlQCIQCkPik/K5J3p4buyNjKU4Z3tEMByoK58n77d9m6huc1rQB2ACk8UZZUyDll\n" + 
                    "uqpQ/FgH1Ldvv1h6KXLcpMMM9OVFR/R4AAABbM/2RNUAAAQDAEcwRQIgPHQrwwOG\n" + 
                    "d9NmDZvgNtMdxT4gyFTI4v07x3p5+o6HsywCIQCSUJ6fR6AEL2jphsLtb4FXO7Vf\n" + 
                    "9Wu//lrAbdc+AIHHRzANBgkqhkiG9w0BAQsFAAOCAQEAJ0lKNjn1LmqpuugmCGl9\n" + 
                    "tn3UUh/zkrHmt8nBv+YJcp/byD6IpY6X66vzrlI6EMqH5CVYQSjEXszJ2oC0+9Ml\n" + 
                    "xftn0A1HS+/SCxHETPNAOcRqsS2/MrtDsO+dDU6eVpsrrbpyYhUWw9xR6RBVNl4F\n" + 
                    "whBhV9LGooXwLFNMWaiUkqfRScS0hupAEWRAHbtZWKdiYV+vra9/zVrlAlS2ihDf\n" + 
                    "Vtsu28nN/zDmHocoz2+d2CQaLjnaDYpuSztG6Tlj/e8FxcICxqvPE1wr/NFbKuro\n" + 
                    "AxWnclrhKN+H7VscWR7ESoHT1ZcX5QhDABKKQNew1PEHNwGf1XrzL4uzNKtLypAW\n" + 
                    "/Q==\n" + 
                    "-----END CERTIFICATE-----\n"
                    + "Row 3:\n"
                    + "  User Principal Name: admin@ejbca.org\n" 
                    + "  Certificate Template: \"1.2.3.4.5.6.7.8.9\" MS_CA_CertificateTemplate\n"
                    + "  Request Disposition: 0x14 (20) -- Issued\n" 
                    + "  Binary Certificate:\n" 
                    + "-----BEGIN CERTIFICATE-----\n"
                    + "MIIFXzCCBEegAwIBAgISAynXG4dEDCZRWyqSA/CNv2O8MA0GCSqGSIb3DQEBCwUA\n"
                    + "MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\n"
                    + "ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTA4MjYyMTA0NTlaFw0x\n"
                    + "OTExMjQyMTA0NTlaMBgxFjAUBgNVBAMTDXd3dy5lamJjYS5vcmcwggEiMA0GCSqG\n"
                    + "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZnGWq/pCJHmCJUyYDd+z02I/wVTKTsGG3\n"
                    + "QMoRO8yvjYUSD2qwJ0riNiBBZamczQHMEi9lMIMLxQTFMdGbaU+aVfH1pR88AJsd\n"
                    + "cShS1edQxA4s4ZMlVC4ikUbtZ5tZZAuosSdko6sBAVOBSbFR1XDaNlYrG8+NVV4H\n"
                    + "fA0Pts5BWiltCGJRn7oL+yrOvnnD9a5b8uEM+cN5Yij7gezcmB42rc8VPcFmH/l4\n"
                    + "LD80z5m8KjzEDA2zC1CgV0YG6AIfkU3NjyEoiP6hhH/OTsHUQcS7h1jYQ4unWacV\n"
                    + "y+/uRW7MWtaR3WF5SZn8pZ0wJkZLkgRHoMN3C9Zg97R2Crkdadv/AgMBAAGjggJv\n"
                    + "MIICazAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF\n"
                    + "BwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFCTFE8MCzIVz9jQSg2zxgbvX9wL1\n"
                    + "MB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUFBwEBBGMw\n"
                    + "YTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0Lm9y\n"
                    + "ZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNyeXB0Lm9y\n"
                    + "Zy8wIwYDVR0RBBwwGoIJZWpiY2Eub3Jngg13d3cuZWpiY2Eub3JnMEwGA1UdIARF\n"
                    + "MEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6\n"
                    + "Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBgYKKwYBBAHWeQIEAgSB9wSB9ADyAHcA\n"
                    + "dH7agzGtMxCRIZzOJU9CcMK//V5CIAjGNzV55hB7zFYAAAFsz/X5oQAABAMASDBG\n"
                    + "AiEAxAPHY4W84eIE9sfK7vsyFlYW4eFTGQVUmXsLk5SPV0ICIQCoMmmAFII86M2q\n"
                    + "1/8d9/L5ZAGmD+dJgOLmbZOCeBa4UwB3ACk8UZZUyDlluqpQ/FgH1Ldvv1h6KXLc\n"
                    + "pMMM9OVFR/R4AAABbM/1+ZAAAAQDAEgwRgIhALVjgDJSRDZY8cBuh0uQgn86Ngxd\n"
                    + "NXvMsLrfe9W3U4CUAiEA6JoNJwVxhP/WtSgzeVNN6fMuj64uH/3/K8/mUvBDri4w\n"
                    + "DQYJKoZIhvcNAQELBQADggEBAGbVymSe/daYD0QSVrSQ1xP6AxXmcdQ7qMExBZtt\n"
                    + "UHZypLdUG+VWtydn0p5wrv4cvrwGs+Me8c7UUp5H0yEM/cvxmgLvyHxzMvts5HNB\n"
                    + "stK6bnKfO6XwoBCStaFLB6OdEAO+WxuTp3PxUq3xhfKUm8ylWtOUn5CbMDw+KTZq\n"
                    + "g/AJpJ7dVf/R2ZjZaJIYWBeQTBHbINpQwWO1eDMMHshVuSdVWTzYpnrAypkV+K1i\n"
                    + "zCdHIbia6zLD6CoWlClMTrP+qakFTCEt497zUn+4W7IRPB5WIotl7iY65aiIPrZH\n" 
                    + "qQVM8q8ClLXRWmzS+ohT8jDbnsSMa5sM4/HCxORE70WdYHc=\n"
                    + "-----END CERTIFICATE-----\n";

            FileUtils.writeStringToFile(file, testData, StandardCharsets.UTF_16, false);
            final String[] args = new String[] { 
                    "--caname", "Let's Encrypt Authority X3", 
                    "-f", file.getAbsolutePath(),
                    "--ee-username", "UPN",
            };
            assertEquals("Import should be successful.", CommandResult.SUCCESS, new CaImportMsCaCertificates().execute(args));
            assertTrue("User for the 1st cert should be created.",
                    EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).existsUser("admin1@signserver.org"));
            assertFalse("Second row should be skipped.",
                    EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).existsUser("admin2@signserver.org"));
            assertTrue("User for the 3rd cert is missing. Did the import stop prematurely?",
                    EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).existsUser("admin@ejbca.org"));

            assertNotNull("1st certificate is missing.", EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                    .findCertificateByFingerprint("c9e877ed59066011cf813ec2df270ac26c39840c"));

            assertNotNull("2nd certificate is missing.", EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                    .findCertificateByFingerprint("335bdc0a32f9e239e468fb79e1380e017fc5f8be"));
        } finally {
            FileUtils.deleteQuietly(file);

            if (EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).existsUser("admin1@signserver.org")) {
                EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).deleteUser(getAuthenticationToken(),
                        "admin1@signserver.org");
            }
            if (EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).existsUser("admin2@signserver.org")) {
                EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).deleteUser(getAuthenticationToken(),
                        "admin2@signserver.org");
            }
            if (EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).existsUser("admin@ejbca.org")) {
                EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).deleteUser(getAuthenticationToken(),
                        "admin@ejbca.org");
            }

            EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST)
                    .removeCertificate("c9e877ed59066011cf813ec2df270ac26c39840c");

            EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST)
                    .removeCertificate("335bdc0a32f9e239e468fb79e1380e017fc5f8be");
        }
    }
    
    @Test
    public void testImport1Unknown() throws Exception {
        final File file = File.createTempFile("certutil_dump_", ".txt");
        try {
            final String testData = "\n" 
                    + "Schema:\n" 
                    + "  Column Name                   Localized Name                Type    MaxLength\n"
                    + "  ----------------------------  ----------------------------  ------  ---------\n"
                    + "  UPN                           User Principal Name           String  2048 -- Indexed\n"
                    + "  CertificateTemplate           Certificate Template          String  254 -- Indexed\n"
                    + "  Request.Disposition           Request Disposition           Long    4 -- Indexed\n"
                    + "  RawCertificate                Binary Certificate            Binary  16384\n" 
                    + "\n" 
                    + "Row 1:\n"
                    + "  User Principal Name: DontCreateMe\n"
                    + "  Certificate Template: \"1.3.6.1.4.1.311.21.8.6486083.1737355.11158168.1694049.3365734.200.8197557.1333246\" MS_CA_CertificateTemplate\n"
                    + "  Request Disposition: 0x0 (0) -- Foobar\n" 
                    + "  Binary Certificate: EMPTY";

            FileUtils.writeStringToFile(file, testData, StandardCharsets.UTF_16, false);
            final String[] args = new String[] {
                    "--caname", "Let's Encrypt Authority X3",
                    "-f", file.getAbsolutePath()
            };
            assertEquals("Nothing imported should be successful.", CommandResult.SUCCESS, new CaImportMsCaCertificates().execute(args));
            assertFalse("User should not be created.",
                    EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).existsUser("DontCreateMe"));
        } finally {
            FileUtils.deleteQuietly(file);
        }
    }

    @Test
    public void testImport1Pending() throws Exception {
        final File file = File.createTempFile("certutil_dump_", ".txt");
        try {
            final String testData = "\n" 
                    + "Schema:\n" 
                    + "  Column Name                   Localized Name                Type    MaxLength\n"
                    + "  ----------------------------  ----------------------------  ------  ---------\n"
                    + "  UPN                           User Principal Name           String  2048 -- Indexed\n"
                    + "  CertificateTemplate           Certificate Template          String  254 -- Indexed\n"
                    + "  Request.Disposition           Request Disposition           Long    4 -- Indexed\n"
                    + "  RawCertificate                Binary Certificate            Binary  16384\n" 
                    + "\n" 
                    + "Row 1:\n"
                    + "  User Principal Name: DontCreateMe\n"
                    + "  Certificate Template: \"1.3.6.1.4.1.311.21.8.6486083.1737355.11158168.1694049.3365734.200.8197557.1333246\" MS_CA_CertificateTemplate\n"
                    + "  Request Disposition: 0x15 (21) -- Pending\n" 
                    + "  Binary Certificate:";

            FileUtils.writeStringToFile(file, testData, StandardCharsets.UTF_16, false);
            final String[] args = new String[] {
                    "--caname", "Let's Encrypt Authority X3",
                    "-f", file.getAbsolutePath(),
            };
            assertEquals("Nothing imported should be successful.", CommandResult.SUCCESS, new CaImportMsCaCertificates().execute(args));
            assertFalse("User should not be created.",
                    EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).existsUser("DontCreateMe"));
        } finally {
            FileUtils.deleteQuietly(file);
        }
    }

    @Test
    public void testImport1Denied() throws Exception {
        final File file = File.createTempFile("certutil_dump_", ".txt");
        try {
            final String testData = "\n" 
                    + "Schema:\n" 
                    + "  Column Name                   Localized Name                Type    MaxLength\n"
                    + "  ----------------------------  ----------------------------  ------  ---------\n"
                    + "  UPN                           User Principal Name           String  2048 -- Indexed\n"
                    + "  CertificateTemplate           Certificate Template          String  254 -- Indexed\n"
                    + "  Request.Disposition           Request Disposition           Long    4 -- Indexed\n"
                    + "  RawCertificate                Binary Certificate            Binary  16384\n" 
                    + "\n" 
                    + "Row 1:\n"
                    + "  User Principal Name: DontCreateMe\n"
                    + "  Certificate Template: \"1.3.6.1.4.1.311.21.8.6486083.1737355.11158168.1694049.3365734.200.15919450.11933782\"\n"
                    + "  Request Disposition: 0x1f (31) -- Denied\n" 
                    + "  Binary Certificate: EMPTY";

            FileUtils.writeStringToFile(file, testData, StandardCharsets.UTF_16, false);
            final String[] args = new String[] { 
                    "--caname", "Let's Encrypt Authority X3", 
                    "-f", file.getAbsolutePath(), 
            };
            assertEquals("Nothing imported should be successful.", CommandResult.SUCCESS, new CaImportMsCaCertificates().execute(args));
            assertFalse("User should not be created.",
                    EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).existsUser("DontCreateMe"));
        } finally {
            FileUtils.deleteQuietly(file);
        }
    }
    
    @Test
    public void testUpnInCertificate() throws Exception {
        final File file = File.createTempFile("certutil_dump_", ".txt");
        try {
            final String testData = "\n"
                    + "Schema:\n"
                    + "  Column Name                   Localized Name                Type    MaxLength\n"
                    + "  ----------------------------  ----------------------------  ------  ---------\n"
                    + "  UPN                           User Principal Name           String  2048 -- Indexed\n"
                    + "  CertificateTemplate           Certificate Template          String  254 -- Indexed\n"
                    + "  Request.Disposition           Request Disposition           Long    4 -- Indexed\n"
                    + "  RawCertificate                Binary Certificate            Binary  16384\n"
                    + "\n"
                    + "Row 1:\n"
                    + "  User Principal Name: EMPTY\n"
                    + "  Certificate Template: \"1.2.3.4.5.6.7.8.9\" MS_CA_CertificateTemplate\n"
                    + "  Request Disposition: 0x14 (20) -- Issued\n"
                    + "  Binary Certificate:\n"
                    + "-----BEGIN CERTIFICATE-----\n"
                    + "MIICOjCCAeGgAwIBAgIQMjxP77K4d3G9k/IVyh+0ezAKBggqhkjOPQQDAjBVMR8w\n"
                    + "HQYDVQQDDBZTdG9ybWh1YiBFQyBTdGFnaW5nIEcxMSUwIwYDVQQKDBxTdG9ybWh1\n"
                    + "YiBUcnVzdCBTZXJ2aWNlcyBMdGQuMQswCQYDVQQGEwJTRTAeFw0yMDAyMjExNDU3\n"
                    + "NDdaFw0yMDAyMjIxNDU3NDdaMB0xGzAZBgNVBAMMEmZvb2JhckBzdmVuc3Nvbi5z\n"
                    + "ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBrnq+8jE5+rg1vywRYZ1dnpctA7\n"
                    + "ivYt8L0FXRPIyLXXIvKe9z3bwd1rITNvlxMyea5HWxJ137HQkRxhK2DRPDejgcow\n"
                    + "gccwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSbbISVgg5QHpL1ho0a6w2wArM5\n"
                    + "XDA+BgNVHREENzA1gg9mb29iYXIuc3ZlbnNzb26gIgYKKwYBBAGCNxQCA6AUDBJm\n"
                    + "b29iYXJAc3ZlbnNzb24uc2UwJwYDVR0lBCAwHgYIKwYBBQUHAwIGCCsGAQUFBwME\n"
                    + "BggrBgEFBQcDATAdBgNVHQ4EFgQUg8u0psGW2GeoJIY9pkfoVGKYcBQwDgYDVR0P\n"
                    + "AQH/BAQDAgWgMAoGCCqGSM49BAMCA0cAMEQCIEi49/MuZ1nTLg5MTc1cSUC9pqhd\n"
                    + "4uq1xbgB7PCHq17lAiBlKCK7Y+/tG0TyIKDa36lel5iUlEUW8og4er3SRKqsmQ==\n" +
                    "-----END CERTIFICATE-----";

            FileUtils.writeStringToFile(file, testData, StandardCharsets.UTF_16, false);
            final String[] args = new String[]{
                    "--caname", "Let's Encrypt Authority X3",
                    "-f", file.getAbsolutePath(),
                    "--ee-username", "universalPrincipalName,UPN"
            };
            assertEquals("Import of certificate dump failed.", CommandResult.SUCCESS, new CaImportMsCaCertificates().execute(args));
            final X509Certificate certificate = (X509Certificate) EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                    .findCertificateByFingerprint("889dc476c010bc1e5ba243dc704ba6b0aaed7333");
            assertNotNull("Certificate should be imported.", certificate);
            assertTrue("User should be created.", EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class)
                    .existsUser("foobar@svensson.se"));
            final boolean revoked = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                    .isRevoked(CertTools.getIssuerDN(certificate), certificate.getSerialNumber());
            assertFalse("Certificate should be imported as active.", revoked);
        } finally {
            FileUtils.deleteQuietly(file);

            if (EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class)
                    .existsUser("foobar@svensson.se")) {
                EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).deleteUser(getAuthenticationToken(),
                        "foobar@svensson.se");
            }
            EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST)
                    .removeCertificate("889dc476c010bc1e5ba243dc704ba6b0aaed7333");
        }
    }

    @Test
    public void testImport1Issued() throws Exception {
        final File file = File.createTempFile("certutil_dump_", ".txt");
        try {
            final String testData = "\n" + "Schema:\n" + "  Column Name                   Localized Name                Type    MaxLength\n"
                    + "  ----------------------------  ----------------------------  ------  ---------\n"
                    + "  UPN                           User Principal Name           String  2048 -- Indexed\n"
                    + "  CertificateTemplate           Certificate Template          String  254 -- Indexed\n"
                    + "  Request.Disposition           Request Disposition           Long    4 -- Indexed\n"
                    + "  RawCertificate                Binary Certificate            Binary  16384\n" 
                    + "\n" 
                    + "Row 1:\n"
                    + "  User Principal Name: EMPTY\n" 
                    + "  Certificate Template: \"1.2.3.4.5.6.7.8.9\" MS_CA_CertificateTemplate\n"
                    + "  Request Disposition: 0x14 (20) -- Issued\n" 
                    + "  Binary Certificate:\n" 
                    + "-----BEGIN CERTIFICATE-----\n"
                    + "MIIFXzCCBEegAwIBAgISAynXG4dEDCZRWyqSA/CNv2O8MA0GCSqGSIb3DQEBCwUA\n"
                    + "MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\n"
                    + "ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTA4MjYyMTA0NTlaFw0x\n"
                    + "OTExMjQyMTA0NTlaMBgxFjAUBgNVBAMTDXd3dy5lamJjYS5vcmcwggEiMA0GCSqG\n"
                    + "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZnGWq/pCJHmCJUyYDd+z02I/wVTKTsGG3\n"
                    + "QMoRO8yvjYUSD2qwJ0riNiBBZamczQHMEi9lMIMLxQTFMdGbaU+aVfH1pR88AJsd\n"
                    + "cShS1edQxA4s4ZMlVC4ikUbtZ5tZZAuosSdko6sBAVOBSbFR1XDaNlYrG8+NVV4H\n"
                    + "fA0Pts5BWiltCGJRn7oL+yrOvnnD9a5b8uEM+cN5Yij7gezcmB42rc8VPcFmH/l4\n"
                    + "LD80z5m8KjzEDA2zC1CgV0YG6AIfkU3NjyEoiP6hhH/OTsHUQcS7h1jYQ4unWacV\n"
                    + "y+/uRW7MWtaR3WF5SZn8pZ0wJkZLkgRHoMN3C9Zg97R2Crkdadv/AgMBAAGjggJv\n"
                    + "MIICazAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF\n"
                    + "BwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFCTFE8MCzIVz9jQSg2zxgbvX9wL1\n"
                    + "MB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUFBwEBBGMw\n"
                    + "YTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0Lm9y\n"
                    + "ZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNyeXB0Lm9y\n"
                    + "Zy8wIwYDVR0RBBwwGoIJZWpiY2Eub3Jngg13d3cuZWpiY2Eub3JnMEwGA1UdIARF\n"
                    + "MEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6\n"
                    + "Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBgYKKwYBBAHWeQIEAgSB9wSB9ADyAHcA\n"
                    + "dH7agzGtMxCRIZzOJU9CcMK//V5CIAjGNzV55hB7zFYAAAFsz/X5oQAABAMASDBG\n"
                    + "AiEAxAPHY4W84eIE9sfK7vsyFlYW4eFTGQVUmXsLk5SPV0ICIQCoMmmAFII86M2q\n"
                    + "1/8d9/L5ZAGmD+dJgOLmbZOCeBa4UwB3ACk8UZZUyDlluqpQ/FgH1Ldvv1h6KXLc\n"
                    + "pMMM9OVFR/R4AAABbM/1+ZAAAAQDAEgwRgIhALVjgDJSRDZY8cBuh0uQgn86Ngxd\n"
                    + "NXvMsLrfe9W3U4CUAiEA6JoNJwVxhP/WtSgzeVNN6fMuj64uH/3/K8/mUvBDri4w\n"
                    + "DQYJKoZIhvcNAQELBQADggEBAGbVymSe/daYD0QSVrSQ1xP6AxXmcdQ7qMExBZtt\n"
                    + "UHZypLdUG+VWtydn0p5wrv4cvrwGs+Me8c7UUp5H0yEM/cvxmgLvyHxzMvts5HNB\n"
                    + "stK6bnKfO6XwoBCStaFLB6OdEAO+WxuTp3PxUq3xhfKUm8ylWtOUn5CbMDw+KTZq\n"
                    + "g/AJpJ7dVf/R2ZjZaJIYWBeQTBHbINpQwWO1eDMMHshVuSdVWTzYpnrAypkV+K1i\n"
                    + "zCdHIbia6zLD6CoWlClMTrP+qakFTCEt497zUn+4W7IRPB5WIotl7iY65aiIPrZH\n" 
                    + "qQVM8q8ClLXRWmzS+ohT8jDbnsSMa5sM4/HCxORE70WdYHc=\n"
                    + "-----END CERTIFICATE-----\n";

            FileUtils.writeStringToFile(file, testData, StandardCharsets.UTF_16, false);
            final String[] args = new String[] { 
                    "--caname", "Let's Encrypt Authority X3", 
                    "-f", file.getAbsolutePath(), 
            };
            assertEquals("Import of certificate dump failed.", CommandResult.SUCCESS, new CaImportMsCaCertificates().execute(args));
            final X509Certificate certificate = (X509Certificate) EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                    .findCertificateByFingerprint("335bdc0a32f9e239e468fb79e1380e017fc5f8be");
            assertNotNull("Certificate should be imported.", certificate);
            assertTrue("User should be created.", EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class)
                    .existsUser(certificate.getSerialNumber().toString()));
            final boolean revoked = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                    .isRevoked(CertTools.getIssuerDN(certificate), certificate.getSerialNumber());
            assertFalse("Certificate should be imported as active.", revoked);
        } finally {
            FileUtils.deleteQuietly(file);

            if (EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class)
                    .existsUser("275574361793664725982328236281411623936956")) {
                EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).deleteUser(getAuthenticationToken(),
                        "275574361793664725982328236281411623936956");
            }
            EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST)
                        .removeCertificate("335bdc0a32f9e239e468fb79e1380e017fc5f8be");
        }
    }
    
    @Test
    public void testEmptyUpnIsIgnored() throws Exception {
        final File file = File.createTempFile("certutil_dump_", ".txt");
        try {
            final String testData = "\n" + "Schema:\n" + "  Column Name                   Localized Name                Type    MaxLength\n"
                    + "  ----------------------------  ----------------------------  ------  ---------\n"
                    + "  UPN                           User Principal Name           String  2048 -- Indexed\n"
                    + "  CertificateTemplate           Certificate Template          String  254 -- Indexed\n"
                    + "  Request.Disposition           Request Disposition           Long    4 -- Indexed\n"
                    + "  RawCertificate                Binary Certificate            Binary  16384\n" 
                    + "\n" 
                    + "Row 1:\n"
                    + "  User Principal Name: EMPTY\n" 
                    + "  Certificate Template: \"1.2.3.4.5.6.7.8.9\" MS_CA_CertificateTemplate\n"
                    + "  Request Disposition: 0x14 (20) -- Issued\n" 
                    + "  Binary Certificate:\n" 
                    + "-----BEGIN CERTIFICATE-----\n"
                    + "MIIFXzCCBEegAwIBAgISAynXG4dEDCZRWyqSA/CNv2O8MA0GCSqGSIb3DQEBCwUA\n"
                    + "MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\n"
                    + "ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTA4MjYyMTA0NTlaFw0x\n"
                    + "OTExMjQyMTA0NTlaMBgxFjAUBgNVBAMTDXd3dy5lamJjYS5vcmcwggEiMA0GCSqG\n"
                    + "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZnGWq/pCJHmCJUyYDd+z02I/wVTKTsGG3\n"
                    + "QMoRO8yvjYUSD2qwJ0riNiBBZamczQHMEi9lMIMLxQTFMdGbaU+aVfH1pR88AJsd\n"
                    + "cShS1edQxA4s4ZMlVC4ikUbtZ5tZZAuosSdko6sBAVOBSbFR1XDaNlYrG8+NVV4H\n"
                    + "fA0Pts5BWiltCGJRn7oL+yrOvnnD9a5b8uEM+cN5Yij7gezcmB42rc8VPcFmH/l4\n"
                    + "LD80z5m8KjzEDA2zC1CgV0YG6AIfkU3NjyEoiP6hhH/OTsHUQcS7h1jYQ4unWacV\n"
                    + "y+/uRW7MWtaR3WF5SZn8pZ0wJkZLkgRHoMN3C9Zg97R2Crkdadv/AgMBAAGjggJv\n"
                    + "MIICazAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF\n"
                    + "BwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFCTFE8MCzIVz9jQSg2zxgbvX9wL1\n"
                    + "MB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUFBwEBBGMw\n"
                    + "YTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0Lm9y\n"
                    + "ZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNyeXB0Lm9y\n"
                    + "Zy8wIwYDVR0RBBwwGoIJZWpiY2Eub3Jngg13d3cuZWpiY2Eub3JnMEwGA1UdIARF\n"
                    + "MEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6\n"
                    + "Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBgYKKwYBBAHWeQIEAgSB9wSB9ADyAHcA\n"
                    + "dH7agzGtMxCRIZzOJU9CcMK//V5CIAjGNzV55hB7zFYAAAFsz/X5oQAABAMASDBG\n"
                    + "AiEAxAPHY4W84eIE9sfK7vsyFlYW4eFTGQVUmXsLk5SPV0ICIQCoMmmAFII86M2q\n"
                    + "1/8d9/L5ZAGmD+dJgOLmbZOCeBa4UwB3ACk8UZZUyDlluqpQ/FgH1Ldvv1h6KXLc\n"
                    + "pMMM9OVFR/R4AAABbM/1+ZAAAAQDAEgwRgIhALVjgDJSRDZY8cBuh0uQgn86Ngxd\n"
                    + "NXvMsLrfe9W3U4CUAiEA6JoNJwVxhP/WtSgzeVNN6fMuj64uH/3/K8/mUvBDri4w\n"
                    + "DQYJKoZIhvcNAQELBQADggEBAGbVymSe/daYD0QSVrSQ1xP6AxXmcdQ7qMExBZtt\n"
                    + "UHZypLdUG+VWtydn0p5wrv4cvrwGs+Me8c7UUp5H0yEM/cvxmgLvyHxzMvts5HNB\n"
                    + "stK6bnKfO6XwoBCStaFLB6OdEAO+WxuTp3PxUq3xhfKUm8ylWtOUn5CbMDw+KTZq\n"
                    + "g/AJpJ7dVf/R2ZjZaJIYWBeQTBHbINpQwWO1eDMMHshVuSdVWTzYpnrAypkV+K1i\n"
                    + "zCdHIbia6zLD6CoWlClMTrP+qakFTCEt497zUn+4W7IRPB5WIotl7iY65aiIPrZH\n" 
                    + "qQVM8q8ClLXRWmzS+ohT8jDbnsSMa5sM4/HCxORE70WdYHc=\n"
                    + "-----END CERTIFICATE-----\n";

            FileUtils.writeStringToFile(file, testData, StandardCharsets.UTF_16, false);
            final String[] args = new String[] { 
                    "--caname", "Let's Encrypt Authority X3",
                    "-f", file.getAbsolutePath(), 
                    "--ee-username", "UPN",
            };
            assertEquals("Import of certificate dump failed.", CommandResult.SUCCESS, new CaImportMsCaCertificates().execute(args));
            final X509Certificate certificate = (X509Certificate) EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                    .findCertificateByFingerprint("335bdc0a32f9e239e468fb79e1380e017fc5f8be");
            assertNotNull("Certificate should be imported.", certificate);
            assertTrue("User should be created.", EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class)
                    .existsUser(certificate.getSerialNumber().toString()));
            final boolean revoked = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                    .isRevoked(CertTools.getIssuerDN(certificate), certificate.getSerialNumber());
            assertFalse("Certificate should be imported as active.", revoked);
        } finally {
            FileUtils.deleteQuietly(file);

            if (EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class)
                    .existsUser("275574361793664725982328236281411623936956")) {
                EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).deleteUser(getAuthenticationToken(),
                        "275574361793664725982328236281411623936956");
            }
            EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST)
                        .removeCertificate("335bdc0a32f9e239e468fb79e1380e017fc5f8be");
        }
    }

    @Test
    public void testImport1Revoked() throws Exception {
        final File file = File.createTempFile("certutil_dump_", ".txt");
        try {
            final String testData = "\n"
                    + "Schema:\n"
                    + "  Column Name                   Localized Name                Type    MaxLength\n"
                    + "  ----------------------------  ----------------------------  ------  ---------\n" 
                    + "  UPN                           User Principal Name           String  2048 -- Indexed\n" 
                    + "  CertificateTemplate           Certificate Template          String  254 -- Indexed\n" 
                    + "  Request.Disposition           Request Disposition           Long    4 -- Indexed\n" 
                    + "  RawCertificate                Binary Certificate            Binary  16384\n"
                    + "\n" 
                    + "Row 1:\n" 
                    + "  User Principal Name: admin@ejbca.org\n"
                    + "  Certificate Template: \"1.2.3.4.5.6.7.8.9\" MS_CA_CertificateTemplate\n" 
                    + "  Request Disposition: 0x15 (21) -- Revoked\n" 
                    + "  Binary Certificate:\n" 
                    + "-----BEGIN CERTIFICATE-----\n" 
                    + "MIIFXzCCBEegAwIBAgISAynXG4dEDCZRWyqSA/CNv2O8MA0GCSqGSIb3DQEBCwUA\n"
                    + "MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\n"
                    + "ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTA4MjYyMTA0NTlaFw0x\n"
                    + "OTExMjQyMTA0NTlaMBgxFjAUBgNVBAMTDXd3dy5lamJjYS5vcmcwggEiMA0GCSqG\n"
                    + "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZnGWq/pCJHmCJUyYDd+z02I/wVTKTsGG3\n"
                    + "QMoRO8yvjYUSD2qwJ0riNiBBZamczQHMEi9lMIMLxQTFMdGbaU+aVfH1pR88AJsd\n"
                    + "cShS1edQxA4s4ZMlVC4ikUbtZ5tZZAuosSdko6sBAVOBSbFR1XDaNlYrG8+NVV4H\n"
                    + "fA0Pts5BWiltCGJRn7oL+yrOvnnD9a5b8uEM+cN5Yij7gezcmB42rc8VPcFmH/l4\n"
                    + "LD80z5m8KjzEDA2zC1CgV0YG6AIfkU3NjyEoiP6hhH/OTsHUQcS7h1jYQ4unWacV\n"
                    + "y+/uRW7MWtaR3WF5SZn8pZ0wJkZLkgRHoMN3C9Zg97R2Crkdadv/AgMBAAGjggJv\n"
                    + "MIICazAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF\n"
                    + "BwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFCTFE8MCzIVz9jQSg2zxgbvX9wL1\n"
                    + "MB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUFBwEBBGMw\n"
                    + "YTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0Lm9y\n"
                    + "ZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNyeXB0Lm9y\n"
                    + "Zy8wIwYDVR0RBBwwGoIJZWpiY2Eub3Jngg13d3cuZWpiY2Eub3JnMEwGA1UdIARF\n"
                    + "MEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6\n"
                    + "Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBgYKKwYBBAHWeQIEAgSB9wSB9ADyAHcA\n"
                    + "dH7agzGtMxCRIZzOJU9CcMK//V5CIAjGNzV55hB7zFYAAAFsz/X5oQAABAMASDBG\n"
                    + "AiEAxAPHY4W84eIE9sfK7vsyFlYW4eFTGQVUmXsLk5SPV0ICIQCoMmmAFII86M2q\n"
                    + "1/8d9/L5ZAGmD+dJgOLmbZOCeBa4UwB3ACk8UZZUyDlluqpQ/FgH1Ldvv1h6KXLc\n"
                    + "pMMM9OVFR/R4AAABbM/1+ZAAAAQDAEgwRgIhALVjgDJSRDZY8cBuh0uQgn86Ngxd\n"
                    + "NXvMsLrfe9W3U4CUAiEA6JoNJwVxhP/WtSgzeVNN6fMuj64uH/3/K8/mUvBDri4w\n"
                    + "DQYJKoZIhvcNAQELBQADggEBAGbVymSe/daYD0QSVrSQ1xP6AxXmcdQ7qMExBZtt\n"
                    + "UHZypLdUG+VWtydn0p5wrv4cvrwGs+Me8c7UUp5H0yEM/cvxmgLvyHxzMvts5HNB\n"
                    + "stK6bnKfO6XwoBCStaFLB6OdEAO+WxuTp3PxUq3xhfKUm8ylWtOUn5CbMDw+KTZq\n"
                    + "g/AJpJ7dVf/R2ZjZaJIYWBeQTBHbINpQwWO1eDMMHshVuSdVWTzYpnrAypkV+K1i\n"
                    + "zCdHIbia6zLD6CoWlClMTrP+qakFTCEt497zUn+4W7IRPB5WIotl7iY65aiIPrZH\n" 
                    + "qQVM8q8ClLXRWmzS+ohT8jDbnsSMa5sM4/HCxORE70WdYHc=\n"
                    + "-----END CERTIFICATE-----\n";
            
            FileUtils.writeStringToFile(file, testData, StandardCharsets.UTF_16, false);
            final String[] args = new String[] { 
                    "--caname", "Let's Encrypt Authority X3",
                    "-f", file.getAbsolutePath(),
                    "--ee-username", "UPN"
            };
            assertEquals("Import of certificate dump failed.", CommandResult.SUCCESS, new CaImportMsCaCertificates().execute(args));
            assertTrue("User should be created.", EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class)
                    .existsUser("admin@ejbca.org"));
            final X509Certificate certificate = (X509Certificate) EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                    .findCertificateByFingerprint("335bdc0a32f9e239e468fb79e1380e017fc5f8be");
            assertNotNull("Certificate should be imported.", certificate);
            final boolean revoked = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                    .isRevoked(CertTools.getSubjectDN(certificate), certificate.getSerialNumber());
            assertTrue("Certificate should be imported as revoked.", revoked);
        } finally {
            FileUtils.deleteQuietly(file);

            if (EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).existsUser("admin@ejbca.org")) {
                EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).deleteUser(getAuthenticationToken(),
                        "admin@ejbca.org");
            }
            EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST)
                        .removeCertificate("335bdc0a32f9e239e468fb79e1380e017fc5f8be");
        }
    }
}