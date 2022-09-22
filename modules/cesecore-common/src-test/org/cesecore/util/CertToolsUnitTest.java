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

package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.cert.SubjectDirAttrExtension;
import org.cesecore.keys.util.KeyTools;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.certificates.X509CertificateTools;

/**
 * Tests the CertTools class
 */
public class CertToolsUnitTest {
    private static Logger log = Logger.getLogger(CertToolsUnitTest.class);
   
    private static byte[] testcert = Base64.decode(("MIIDATCCAmqgAwIBAgIIczEoghAwc3EwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAzMDky" + "NDA2NDgwNFoXDTA1MDkyMzA2NTgwNFowMzEQMA4GA1UEAxMHcDEydGVzdDESMBAG"
            + "A1UEChMJUHJpbWVUZXN0MQswCQYDVQQGEwJTRTCBnTANBgkqhkiG9w0BAQEFAAOB" + "iwAwgYcCgYEAnPAtfpU63/0h6InBmesN8FYS47hMvq/sliSBOMU0VqzlNNXuhD8a"
            + "3FypGfnPXvjJP5YX9ORu1xAfTNao2sSHLtrkNJQBv6jCRIMYbjjo84UFab2qhhaJ" + "wqJgkQNKu2LHy5gFUztxD8JIuFPoayp1n9JL/gqFDv6k81UnDGmHeFcCARGjggEi"
            + "MIIBHjAPBgNVHRMBAf8EBTADAQEAMA8GA1UdDwEB/wQFAwMHoAAwOwYDVR0lBDQw" + "MgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDBAYIKwYBBQUHAwUGCCsGAQUF"
            + "BwMHMB0GA1UdDgQWBBTnT1aQ9I0Ud4OEfNJkSOgJSrsIoDAfBgNVHSMEGDAWgBRj" + "e/R2qFQkjqV0pXdEpvReD1eSUTAiBgNVHREEGzAZoBcGCisGAQQBgjcUAgOgCQwH"
            + "Zm9vQGZvbzASBgNVHSAECzAJMAcGBSkBAQEBMEUGA1UdHwQ+MDwwOqA4oDaGNGh0" + "dHA6Ly8xMjcuMC4wLjE6ODA4MC9lamJjYS93ZWJkaXN0L2NlcnRkaXN0P2NtZD1j"
            + "cmwwDQYJKoZIhvcNAQEFBQADgYEAU4CCcLoSUDGXJAOO9hGhvxQiwjGD2rVKCLR4" + "emox1mlQ5rgO9sSel6jHkwceaq4A55+qXAjQVsuy76UJnc8ncYX8f98uSYKcjxo/"
            + "ifn1eHMbL8dGLd5bc2GNBZkmhFIEoDvbfn9jo7phlS8iyvF2YhC4eso8Xb+T7+BZ" + "QUOBOvc=").getBytes());

    private static byte[] guidcert = Base64.decode(("MIIC+zCCAmSgAwIBAgIIBW0F4eGmH0YwDQYJKoZIhvcNAQEFBQAwMTERMA8GA1UE"
            + "AxMIQWRtaW5DQTExDzANBgNVBAoTBkFuYVRvbTELMAkGA1UEBhMCU0UwHhcNMDQw" + "OTE2MTc1NzQ1WhcNMDYwOTE2MTgwNzQ1WjAyMRQwEgYKCZImiZPyLGQBARMEZ3Vp"
            + "ZDENMAsGA1UEAxMER3VpZDELMAkGA1UEBhMCU0UwgZ8wDQYJKoZIhvcNAQEBBQAD" + "gY0AMIGJAoGBANdjsBcLJKUN4hzJU1p3cqaXhPgEjGul62/3xv+Gow+7oOYePcK8"
            + "bM5VO4zdQVWEhuGOZFaZ70YbXhei4F9kvqlN7xuG47g7DNZ0/fnRzvGY0BHmIR4Y" + "/U87oMEDa2Giy0WTjsmT14uzy4luFgqb2ZA3USGcyJ9hoT6j1WDyOxitAgMBAAGj"
            + "ggEZMIIBFTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDA7BgNVHSUENDAy" + "BggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDBQYIKwYBBQUH"
            + "AwcwHQYDVR0OBBYEFJlDddj88zI7tz3SPfdig0gw5IWvMB8GA1UdIwQYMBaAFI1k" + "9WhE1WXpeezZx/kM0qsoZyqVMHgGA1UdEQRxMG+BDGd1aWRAZm9vLmNvbYIMZ3Vp"
            + "ZC5mb28uY29thhRodHRwOi8vZ3VpZC5mb28uY29tL4cECgwNDqAcBgorBgEEAYI3" + "FAIDoA4MDGd1aWRAZm9vLmNvbaAXBgkrBgEEAYI3GQGgCgQIEjRWeJCrze8wDQYJ"
            + "KoZIhvcNAQEFBQADgYEAq39n6CZJgJnW0CH+QkcuU5F4RQveNPGiJzIJxUeOQ1yQ" + "gSkt3hvNwG4kLBmmwe9YLdS83dgNImMWL/DgID/47aENlBNai14CvtMceokik4IN"
            + "sacc7x/Vp3xezHLuBMcf3E3VSo4FwqcUYFmu7Obke3ebmB08nC6gnQHkzjNsmQw=").getBytes());
    
    
    private static byte[] altNameCert = Base64.decode(("MIIDDzCCAfegAwIBAgIIPiL0klmu1uIwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
            + "AxMIQWRtaW5DQTExFTATBgNVBAoTDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw" + "HhcNMDUwODAyMTAxOTQ5WhcNMDcwODAyMTAyOTQ5WjAsMQwwCgYDVQQDEwNmb28x"
            + "DzANBgNVBAoTBkFuYVRvbTELMAkGA1UEBhMCU0UwXDANBgkqhkiG9w0BAQEFAANL" + "ADBIAkEAmMVWkkEMLbDNoB/NG3kJ22eC18syXqaHWRWc4DldFeCMGeLzfB2NklNv"
            + "hmr2kgIJcK+wyFpMkYm46dSMOrvovQIDAQABo4HxMIHuMAwGA1UdEwEB/wQCMAAw" + "DgYDVR0PAQH/BAQDAgWgMDsGA1UdJQQ0MDIGCCsGAQUFBwMBBggrBgEFBQcDAgYI"
            + "KwYBBQUHAwQGCCsGAQUFBwMFBggrBgEFBQcDBzAdBgNVHQ4EFgQUIV/Fck/+UVnw" + "tJigtZIF5OuuhlIwHwYDVR0jBBgwFoAUB/2KRYNOZxRDkJ5oChjNeXgwtCcwUQYD"
            + "VR0RBEowSIEKdG9tYXNAYS5zZYIId3d3LmEuc2WGEGh0dHA6Ly93d3cuYS5zZS+H" + "BAoBAQGgGAYKKwYBBAGCNxQCA6AKDAhmb29AYS5zZTANBgkqhkiG9w0BAQUFAAOC"
            + "AQEAfAGJM0/s+Yi1Ewmvt9Z/9w8X/T/02bF8P8MJG2H2eiIMCs/tkNhnlFGYYGhD" + "Km8ynveQZbdYvKFioOr/D19gMis/HNy9UDfOMrJdeGWiwxUHvKKbtcSlOPH3Hm0t"
            + "LSKomWdKfjTksfj69Tf01S0oNonprvwGxIdsa1uA9BC/MjkkPt1qEWkt/FWCfq9u" + "8Xyj2tZEJKjLgAW6qJ3ye81pEVKHgMmapWTQU2uI1qyEPYxoT9WkQtSObGI1wCqO"
            + "YmKglnd5BIUBPO9LOryyHlSRTID5z0UgDlrTAaNYuN8QOYF+DZEQxm4bSXTDooGX" + "rHjSjn/7Urb31CXWAxq0Zhk3fg==").getBytes());
    
   



    private static byte[] subjDirAttrCert = Base64.decode(("MIIGmTCCBYGgAwIBAgIQGMYCpWmOBXXOL2ODrM8FHzANBgkqhkiG9w0BAQUFADBx"
            + "MQswCQYDVQQGEwJUUjEoMCYGA1UEChMfRWxla3Ryb25payBCaWxnaSBHdXZlbmxp" + "Z2kgQS5TLjE4MDYGA1UEAxMvZS1HdXZlbiBFbGVrdHJvbmlrIFNlcnRpZmlrYSBI"
            + "aXptZXQgU2FnbGF5aWNpc2kwHhcNMDYwMzI4MDAwMDAwWhcNMDcwMzI4MjM1OTU5" + "WjCCAR0xCzAJBgNVBAYTAlRSMSgwJgYDVQQKDB9FbGVrdHJvbmlrIEJpbGdpIEd1"
            + "dmVubGlnaSBBLlMuMQ8wDQYDVQQLDAZHS05FU0kxFDASBgNVBAUTCzIyOTI0NTQ1" + "MDkyMRswGQYDVQQLDBJEb2d1bSBZZXJpIC0gQlVSU0ExIjAgBgNVBAsMGURvZ3Vt"
            + "IFRhcmloaSAtIDAxLjA4LjE5NzcxPjA8BgNVBAsMNU1hZGRpIFPEsW7EsXIgLSA1" + "MC4wMDAgWVRMLTIuMTYuNzkyLjEuNjEuMC4xLjUwNzAuMS4yMRcwFQYDVQQDDA5Z"
            + "QVPEsE4gQkVDRU7EsDEjMCEGCSqGSIb3DQEJARYUeWFzaW5AdHVya2VrdWwuYXYu" + "dHIwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKaJXVLvXC7qyjiqTAlM582X"
            + "GPdQJxUfRxgTm6jlBZKtEhbWN5hbH4ASJTzmXWryGricejdKM+JBJECFdelyWPHs" + "UkEL/U0uft3KLIdYo72oTibaL3j4vkEhjyubikSdl9CywkY6WS8nV9JNc66QOYxE"
            + "5ZdE5CR19ScIYcOh7YpxAgMBAAGjggMBMIIC/TAJBgNVHRMEAjAAMAsGA1UdDwQE" + "AwIGwDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLmUtZ3V2ZW4uY29tL0Vs"
            + "ZWt0cm9uaWtCaWxnaUd1dmVubGlnaUFTR0tORVNJL0xhdGVzdENSTC5jcmwwHwYD" + "VR0jBBgwFoAUyT6jfNNisqvczhIzwmTXZTTyfrowggEcBgNVHSAEggETMIIBDzCB"
            + "/wYJYIYYAwABAQECMIHxMDYGCCsGAQUFBwIBFipodHRwczovL3d3dy5lLWd1dmVu" + "LmNvbS9lLWltemEvYmlsZ2lkZXBvc3UwgbYGCCsGAQUFBwICMIGpGoGmQnUgc2Vy"
            + "dGlmaWthLCA1MDcwIHNhef1s/SBFbGVrdHJvbmlrIN1temEgS2FudW51bmEgZ/Zy" + "ZSBuaXRlbGlrbGkgZWxla3Ryb25payBzZXJ0aWZpa2Fk/XIuIE9JRDogMi4xNi43"
            + "OTIuMS42MS4wLjEuNTA3MC4xLjEgLSBPSUQ6IDAuNC4wLjE0NTYuMS4yIC0gT0lE" + "OiAwLjQuMC4xODYyLjEuMTALBglghhgDAAEBBQQwgaEGCCsGAQUFBwEDBIGUMIGR"
            + "MHYGCCsGAQUFBwsBMGoGC2CGGAE9AAGnTgEBMFuGWUJ1IFNlcnRpZmlrYSA1MDcw" + "IHNhef1s/SBFbGVrdHJvbmlrIN1temEgS2FudW51bmEgZ/ZyZSBuaXRlbGlrbGkg"
            + "ZWxla3Ryb25payBzZXJ0aWZpa2Fk/XIuMBcGBgQAjkYBAjANEwNZVEwCAwDDUAIB" + "ADB2BggrBgEFBQcBAQRqMGgwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmUtZ3V2"
            + "ZW4uY29tMCIGCCsGAQUFBzAChhZodHRwOi8vd3d3LmUtZ3V2ZW4uY29tMB0GAytv" + "DoYWaHR0cDovL3d3dy5lLWd1dmVuLmNvbTAbBgNVHQkEFDASMBAGCCsGAQUFBwkE"
            + "MQQTAlRSMBEGCWCGSAGG+EIBAQQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEA3yVY" + "rURakBcrfv1hJjhDg7+ylCjXf9q6yP2E03kG4t606TLIyqWoqGkrndMtanp+a440"
            + "rLPIe456XfRJBilj99H0NjzKACAVfLMTL8h/JBGLDYJJYA1S8PzBnMLHA8dhfBJ7" + "StYEPM9BKW/WuBfOOdBNrRZtYKCHwGK2JANfM/JlfzOyG4A+XDQcgjiNoosjes1P"
            + "qUHsaccIy0MM7FLMVV0HJNNQ84N9CuKIrBSSWopOudkajVqNtI3+FCcy+yXiH6LX" + "fmpHZ346zprcafcjQmAiKfzPSljruvGDIVI3WN7S7WOMrx6MDq54626cZzQl9GFT"
            + "D1gNo3fjOFhK33DY1Q==").getBytes());

    private static byte[] subjDirAttrCert2 = Base64.decode(("MIIEsjCCA5qgAwIBAgIIFsYK/Jx7XEEwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
            + "AxMIQWRtaW5DQTExFTATBgNVBAoTDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw" + "HhcNMDYwNTMwMDcxNjU2WhcNMDgwNTI5MDcyNjU2WjA5MRkwFwYDVQQDExBUb21h"
            + "cyBHdXN0YXZzc29uMQ8wDQYDVQQKEwZGb29PcmcxCzAJBgNVBAYTAlNFMIGfMA0G" + "CSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvhUYzNVW6iG5TpYi2Dr9VX37g05jcGEyP"
            + "Lix05oxs3FnzPUf6ykxGy4nUYO12PfC6u9Gh+zelFfg6nKNQqYI48D4ufJc928Nx" + "dZQZi41UmnFT5UXn3JcG4DQe0wZp+BKCch/UbtRjuE6iNxH24R//8W4wXc1R++FG"
            + "5V6CQzHxXwIDAQABo4ICQjCCAj4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMC" + "BPAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQ54I1p"
            + "TGNwAeQEdnmcjNT+XMMjsjAfBgNVHSMEGDAWgBRzBo+b/XQZqq0DU6J10x17GoKS" + "sDBMBgNVHSAERTBDMEEGAykBATA6MB4GCCsGAQUFBwICMBIeEABGAPYA9gBCAGEA"
            + "cgDkAOQwGAYIKwYBBQUHAgEWDGh0dHA6LzExMS5zZTBuBgNVHR8EZzBlMGOgYaBf" + "hl1odHRwOi8vbG9jYWxob3N0OjgwODAvZWpiY2EvcHVibGljd2ViL3dlYmRpc3Qv"
            + "Y2VydGRpc3Q/Y21kPWNybCZpc3N1ZXI9Q049VGVzdENBLE89QW5hVG9tLEM9U0Uw" + "TQYIKwYBBQUHAQEEQTA/MD0GCCsGAQUFBzABhjFodHRwOi8vbG9jYWxob3N0Ojgw"
            + "ODAvZWpiY2EvcHVibGljd2ViL3N0YXR1cy9vY3NwMDoGCCsGAQUFBwEDBC4wLDAg" + "BggrBgEFBQcLAjAUMBKBEHJhQGNvbW1maWRlcy5jb20wCAYGBACORgEBMHYGA1Ud"
            + "CQRvMG0wEAYIKwYBBQUHCQUxBBMCU0UwEAYIKwYBBQUHCQQxBBMCU0UwDwYIKwYB" + "BQUHCQMxAxMBTTAXBggrBgEFBQcJAjELEwlTdG9ja2hvbG0wHQYIKwYBBQUHCQEx"
            + "ERgPMTk3MTA0MjUxMjAwMDBaMA0GCSqGSIb3DQEBBQUAA4IBAQA+vgNnGjw29xEs" + "cnJi7wInUBvtTzQ4+SVSBPTzNA/ZEk+CJVsr/2xbPl+SShZ0SHObj9un1kwKst4n"
            + "zcNqsnBorrluM92Z5gYwDN3mRGF0szbYEshr/KezMhY2MdXkE+i3nEx6awdemuCG" + "g+LAfL4ODLAzAJJI4MfF+fz0IK7Zeobo1aVGS6Ii9sEnDdQOsLbdfHBNccrT353d"
            + "NAwxPGnfunGBQ+Los6vjDApy/szMT32NFJDe4WTmkDxqYJQqQjhdrHTxpFEr0VQB" + "s7KRRCYjga/Z52XytwwDBLFM9CPZJfyKxZTV9I9i6e0xSn2xEW8NRplY1HOKa/2B"
            + "VzvWW9G5").getBytes());


    private static byte[] cvccert = Base64.decode(("fyGCAWF/ToHZXykBAEIKU0VSUFMxMDExMH9JgZUGCgQAfwAHAgICAQGBgYEAk4Aq"
            + "LqYXchIouF9yBv/2hFnf5N65hdpvQPUdfH1k2qnHAlOL5DYYlKCBh8YFCC2RZD+K" + "nJ99cHxh8oxh28U23Z/MqTOKv5tR8JIUUm3G3Hjj2erVVTEJ49MqLzsyVGfw4yCu"
            + "YRdwBYFWJu2t6PcS5KPnpNtbNdBzrDJAqxPAsO2CAwEAAV8gClNFUlBTMTAxMTB/" + "TA4GCQQAfwAHAwECAVMBw18lBgAIAAUABV8kBgEAAAUABV83gYB88jfXZ3njYpuD"
            + "4fpS6BV53y9+iz3KAQM/74LPMI49elGtcAVyMn1EMn/bU4MeMARfv3Njd2Go4ZhM" + "j5xuY2Pvktz3Dq4ogjkgqAJqqIvG+M9KXh9XAv2m2wjmsueKbXUJ8TpJR87k4o97"
            + "buZXbuStDOb5FibhxyVgWIxuCn8quQ==").getBytes());

    private static byte[] cvcreqrenew = Base64.decode(("Z4IBtn8hggFmf06CASZfKQEAQg5TRUlTQlBPT0wwMDAwNn9Jgf0GCgQAfwAHAgIC"
            + "AgKBHNfBNKomQ2aGKhgwJXXR14ewnwdXl9qJ9X7IwP+CHGil5iypzmwcKZgDpsFT" + "C1FOGCrYsAQqWcrSn0ODHCWA9jzP5EE4hwcTsakjaeM+ITXSZtuzcjhsQAuEOQQN"
            + "kCmtLH5c9DQII7KofcaMnkzjF0webv3uEsB9WKpW93LAcm8kxrieTs2sJDVLnpnK" + "o/bTdhQCzYUc18E0qiZDZoYqGDAlddD7mNEWvEtt3ryjpaeTn4Y5BBQte2aU3YOQ"
            + "Ykf73/UluNQOpMlnHt9PXplomqhuAZ0QxwXb6TCG3rZJhVwe0wx0R1mqz3U+fJnU" + "hwEBXyAOU0VJU0JQT09MMDAwMDZfNzgErOAjPCoQ+WN8K6pzztZp+Mt6YGNkJzkk"
            + "WdLnvfPGZkEF0oUjcw+NjexaNCLOA0mCfu4oQwsjrUIOU0VJU0JQT09MMDAwMDVf" + "NzhSmH1c7YJhbLTRzwuSozUd9hlBHKEIfFqSUE9/FrbWXEtR+rHRYKAGu/nw8PAH"
            + "oM+HPMzMVVLDVg==").getBytes());

    private static byte[] cvcreq = Base64.decode(("fyGCAWZ/ToIBJl8pAQBCDlNFSVNCUE9PTDAwMDA1f0mB/QYKBAB/AAcCAgICAoEc"
            + "18E0qiZDZoYqGDAlddHXh7CfB1eX2on1fsjA/4IcaKXmLKnObBwpmAOmwVMLUU4Y" + "KtiwBCpZytKfQ4McJYD2PM/kQTiHBxOxqSNp4z4hNdJm27NyOGxAC4Q5BA2QKa0s"
            + "flz0NAgjsqh9xoyeTOMXTB5u/e4SwH1Yqlb3csBybyTGuJ5OzawkNUuemcqj9tN2" + "FALNhRzXwTSqJkNmhioYMCV10PuY0Ra8S23evKOlp5OfhjkEOwPDLflRVBj2iayW"
            + "VzpO2BICGO+PqFeuce1EZM4o1EIfLzoackPowabEMANfNltZvt5bWyzkZleHAQFf" + "IA5TRUlTQlBPT0wwMDAwNV83OEnwL+XYDhXqK/0fBuZ6lZV0HncoZyn3oo8MmaUL"
            + "2mNzpezLAoZMux0l5aYperrSDsuHw0zrf0yo").getBytes());

    private static byte[] cvccertchainroot = Base64.decode(("fyGCAmx/ToIBYl8pAQBCDlNFSFNNQ1ZDQTAwMDAxf0mCARUGCgQAfwAHAgICAQKB"
            + "ggEAyGju6NHTACB+pl2x27/VJVKuGBTgf98j3gQOyW5vDzXI7PkiwR1/ObPjFiuW" + "iBRH0WsPzHX7A3jysZr7IohLjy4oQMdP5z282/ZT4mBwlVu5pAEcHt2eHbpILwIJ"
            + "Hbv6130T+RoG/3bI/eHk9HWi3/ipVnwRX1CsylczFfdyPTMyGOJmmElT0GQgV8Rt" + "b5Us/Hz66qiUX67eRBrahJfwiVwawYzmZ5Rn9u/vXHQYeUh+lLja+H+kXof9ARuw"
            + "p5S09DO2VZWbbR2BZHk0IaNgo54Xoih+5c/nIA/2+j9Afdf+wuqmxqib5aPOMHO3" + "WOVmVMF84Xo2V+duIZ4b7KkRXYIDAQABXyAOU0VIU01DVkNBMDAwMDF/TA4GCQQA"
            + "fwAHAwECAVMBw18lBgAIAAUCBl8kBgEAAAUCBl83ggEAMiiqI+HF8DyhPfH8dTeU" + "4/0/DNnjZ2/Qy1a5GATWU04da+L2iWI8QclN64cw0l/zroBGyeq+flDKzVWnqril"
            + "HX/PD3/xoCEhZSfZ/1AQZBP39/t1lYZLJ36VeFwrsmvN8rq6RnNtR2CrDYDFkFRq" + "A6v9dNYMbnEDN7m8wD/DWM2fZr+loqznT1/egx+SBqUY+KnU6ntxQyw7gzL1DV9Z"
            + "OlyxjDaWY8i2Q/tcdDxdZYBBMgFhxivXV5ou2YiBZKKIlP2ots6P8TlSVwdyaHTI" + "8z8Hpvx1QcB2maOVn6IFAyq/X71p9Zb626YLhjaFO6v80SYnlefVu5Uir5n/HzpW"
            + "kg==").getBytes());

    private static byte[] cvccertchainsub = Base64.decode(("fyGCAeV/ToHcXykBAEIOU0VIU01DVkNBMDAwMDF/SYGUBgoEAH8ABwICAgECgYGA"
            + "rdRouw7ksS6M5kw28YkWAD350vbDlnPCmqsKPfKiNvDxowviWDUTn9Ai3xpTIzGO" + "cl40DqxYPA2X4XO52+r5ZUazsVyyx6F6XwznHdjUpDff4QFyG74Vjq7DDrCCKOzH"
            + "b0H6rNJFC5YEKI4wpEPou+3bq2jhLWkzU35EfydJHXWCAwEAAV8gClNFUlBTRFZF" + "WDJ/TA4GCQQAfwAHAwECAVMBgl8lBgAIAAYABV8kBgEAAAUCBl83ggEAbawFepay"
            + "gX+VrBOsGzbQCpG2mR1NrJbaNdBJcouWYTNzlDP/hRssU9/lTzHulRPupkarepAI" + "GMIDMOo3lNImlYlU8ZlaV6mbKRgWZVjtZmVgq+wLARS4dXNlHRJvS2AustfseGVr"
            + "kqJ0+UYo8x8UL13fB7VCSVqADnOnbemtvE1cIdFcIAqP1JLh91ACJ4lpoaAn10+g" + "5coIGGa01BYEDtiA++SFnRl7kYFykAZrs3eXq+zuPmOo9hr4JxLZuiN5DnIrZdLA"
            + "DWq7GeCFr6wCMg2jPuK9Kqvl06tqylVy4ravVHv58WvAxWFgyuezdRbyV7YAfVF3" + "tlcVDXa3R+mfYg==").getBytes());

    private static byte[] x509certchainsubsub = Base64
            .decode(("MIICAzCCAWygAwIBAgIINrHHHchdmfMwDQYJKoZIhvcNAQEFBQAwEDEOMAwGA1UE"
                    + "AwwFU3ViQ0EwHhcNMTAwNjA1MTIwNzMxWhcNMzAwNjA1MTIwNjUyWjATMREwDwYD"
                    + "VQQDDAhTdWJTdWJDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAiySbgP2A"
                    + "QuZXWZk9C1pOrpVhzWNDAFc4ttVGgh5TS1/wA6Y6nf2ci8gfxkQx1rhR784QUap4"
                    + "id6mwGV/af3WFj34YsTXdozsO/SFi7vvOGA/jU6ZUuQPYpmsSDQ3ZNLcx/MkgkrP"
                    + "WDlFhD7b079oVva5zZsF8w91KlX+KG9usXECAwEAAaNjMGEwHQYDVR0OBBYEFJ9y"
                    + "tRy1CFwUavq8OP25jRybKyElMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU"
                    + "2GDNoIpTVxc9y953THJoWkS5wjAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEB"
                    + "BQUAA4GBAE0vHf3iyJ0EqOyN+LUfBkCBTPHl6sEV1bwdgkdVwj9cBbmSEDCOlmYA"
                    + "K0bvAY/1qbgEjkn+Sc32PP/3dmHX5EUKliAodguAu8vK/Rp7kefdUQHnJHwRUMF5" + "9YJDdGtDZx+WLBihYhnTzGVzuP6Qaff3aNyY69O+rwSDm06Au8Zc")
                    .getBytes());

    private static byte[] x509certchainsub = Base64
            .decode(("MIICATCCAWqgAwIBAgIIRzc+cItydm0wDQYJKoZIhvcNAQEFBQAwETEPMA0GA1UE"
                    + "AwwGUm9vdENBMB4XDTEwMDYwNTEyMDcxMVoXDTMwMDYwNTEyMDY1MlowEDEOMAwG"
                    + "A1UEAwwFU3ViQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMl3EN+V1M39"
                    + "OVrmHp7PncZ16AkffAtgLk+gIgk+cHZYIGPPN1V/AtCmzteYRrPwGM9Vs2nJ4OZ7"
                    + "F8cJ1MDpyjRdjKC6sVlhkdNq+s1Q/yNtG0AxvlH2KyIZkHU02UNnJGARMaRpZipe"
                    + "VonnAD8D+FkhTt8BM2T7/Grck5QYgJUhAgMBAAGjYzBhMB0GA1UdDgQWBBTYYM2g"
                    + "ilNXFz3L3ndMcmhaRLnCMDAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFCua"
                    + "Xc8f/BC8CeBLOVaC5N0Zb4BqMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQUF"
                    + "AAOBgQBM2lvlZmEJdFXsfoHSt2h4XN6q8Z+sIHDXyuyanNCoQx+9lM2liY+tXAUq"
                    + "Sj1fZAzqjdptIgvG5APnFrnWHeEYjYpYsROs//xF6CUKo8iJEIyRpmx9pSmwA8Rb" + "U0RmY/62tBLr758ZzRGKKoX7znxsXZ5/bouT6g+IxmNuM2EiyA==")
                    .getBytes());

    private static byte[] x509certchainroot = Base64
            .decode(("MIICAjCCAWugAwIBAgIIPXgH6TfNMlYwDQYJKoZIhvcNAQEFBQAwETEPMA0GA1UE"
                    + "AwwGUm9vdENBMB4XDTEwMDYwNTEyMDY1MloXDTMwMDYwNTEyMDY1MlowETEPMA0G"
                    + "A1UEAwwGUm9vdENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCK+F3eOoGI"
                    + "Kwa1g68vD6aZlkTCMbbEyoa9Wr4baapdCHvO8YHwVC9UDh8snDtEQT9yZKLlU4nM"
                    + "n05O7yL8FfvgB2j3xN6In1fLq8JizrYVpL49C3ewTwaKMTFjde3BtWDZ4ufJdFuZ"
                    + "+LSw98dM2zhQWme7LnrJQou85LbNt2v6XQIDAQABo2MwYTAdBgNVHQ4EFgQUK5pd"
                    + "zx/8ELwJ4Es5VoLk3RlvgGowDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBQr"
                    + "ml3PH/wQvAngSzlWguTdGW+AajAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQEF"
                    + "BQADgYEAYB5munksWVndUxStBZmsg5uwryu8bf/esxYLlxkO8rG/UnJ9DNw4tJsh"
                    + "YxwGeslPeG9+y8O8MsXKSjdNw3I3avMpj+QqzmqD/MVlHX6+CSyUbhFGPR2TRQCp" + "m+VsfwOl8/INVAySpBf3Uk2rUYhvdUqhCOcE67d0tYdJAqiIDvc=")
                    .getBytes());

    private static byte[] pemcert = ("-----BEGIN CERTIFICATE-----\n" + "MIIDUzCCAjugAwIBAgIIMK64QB5XErowDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE\n"
            + "AwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw\n"
            + "HhcNMTAwMTI5MTI0NDIwWhcNMjAwMTI3MTI0NDIwWjA3MREwDwYDVQQDDAhBZG1p\n"
            + "bkNBMTEVMBMGA1UECgwMRUpCQ0EgU2FtcGxlMQswCQYDVQQGEwJTRTCCASIwDQYJ\n"
            + "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJQNal//KwRHhBg7BLsuclOpH7xyb1AP\n"
            + "Mc5RsEQANOtCBoRlgEDh7tQUfRnPxvmHM+HH9osEV2c+9L23K2l8EVjZRlo2vltJ\n"
            + "duzbBGIo7swdCWGvFxE6W0lkv/YsGVmmt/dL2lO4V4YTuu5CX3PU2LrBR6mxtEsM\n"
            + "mM/YgHo/QWN4/YDWfnXkNpDDjRxLzdsSqvcoLrZavqrMS1Avv2utY6ECyl6PTBG+\n"
            + "qPpozenPRi2QKbiKOpeCgT+2Y4JbMqm+d7go0KKu6wxKE16R/tX9OwT4ObJaKJ/W\n"
            + "j0mm5deJHNDEvgWi2beTVcc16LVZUiyKmZXlYLEdV+CH0NrRc4ck6WsCAwEAAaNj\n"
            + "MGEwHQYDVR0OBBYEFLGsC1OtcOyAklW2b3eN678a6wsZMA8GA1UdEwEB/wQFMAMB\n"
            + "Af8wHwYDVR0jBBgwFoAUsawLU61w7ICSVbZvd43rvxrrCxkwDgYDVR0PAQH/BAQD\n"
            + "AgGGMA0GCSqGSIb3DQEBBQUAA4IBAQBHCJ3ZQEtpfYBHnrwKuNzMykH+yKIkO2mj\n"
            + "c/65e8r7tMjV/9YEb2pAYaix7WAdJ46KcE2ldKl+MHJx8Ev1ZbLPbLYcwPkP+8Ll\n"
            + "pCrhc6riSTaUBZrIA2uuXPPREKj+e8CnnMdCfLy4x6uIMDVAa4mb0akEmLvqFR2X\n"
            + "J4Z8eEhwf6EPRniie6GKcBOWSP0podlWkn8SCLzd+eJZ9H0YMTN7nfLfUdENznuO\n"
            + "5DKfkfT4rOyAGFs+KVwigq1kbSNZJC4Kjo7diMBtWRiXSXTQKE+JgrQbFCdVYQos\n" + "VvSwSiSMW5Rs5ZCtRXMmXz2HdxpbTayCAYPBh6XKfvq4x06gxfll\n"
            + "-----END CERTIFICATE-----").getBytes();





    
    static byte[] chainRootCA = Base64.decode( ("MIIFIzCCAwugAwIBAgIIDZIKPU4lBGQwDQYJKoZIhvcNAQELBQAwHzEQMA4GA1UE" +
            "AwwHM0dQUENBMjELMAkGA1UEBhMCU0UwHhcNMTcwNjE0MjIyODU0WhcNMzcwNjA5" +
            "MjIyODU0WjAfMRAwDgYDVQQDDAczR1BQQ0EyMQswCQYDVQQGEwJTRTCCAiIwDQYJ" +
            "KoZIhvcNAQEBBQADggIPADCCAgoCggIBAK4TMjlaF5KzT+AcIjjFOYusNsghhmew" +
            "SnoH/SOCmCucZ/8mMFlMc/BwRNLIiWt1nJOyoiHTqtzKl8F0SF5/suBQoKvBLsc5" +
            "jFHgz6gRWqBYNlE3yvkgKr/7vIosEcgX7MVTKsD6+G5FrD7vqluCOSGLZ9S4wP9P" +
            "VycgXBlZUS1X9uxaymgJhLWr9R7VRJ4uB0r5RFyY5t9GQ0JiuDxkWZ2TXLFZpxGi" +
            "DH/tO0S3G82fN/expdSVYiWHUbEzFe5kDqaSky/MRWiJ6gMlQEec8UwEAfPBuOPX" +
            "LjQxuoCktG9oBaqkGxEyUdsEcsZyg2eCbfKDXzXoQ23wGal6Ij6Wrx7OY0SIOZ1J" +
            "rN4Hgrl7NDl0102a/agvhh83asWry3lNl5YaD2qdlis/kA/6n6jIe5Vk2XlwwpSk" +
            "jafZAkDMjIMBIcEIqDxpViGdHX69rLW8z1k535+zk/Y2pdFiyHiAxebe7KZ2bJyT" +
            "Haiboi3o1DmnY4hXYSCxap0IN+XBmwch3n/l+zQQfqiQ8i3z9QaoCOedUWGngVAF" +
            "HK2Cs0lrb0bZeCR0eWtafIVuYu/zFIevkhzBumQxg1kYO6OZSfIzfvMUBC8RSzMQ" +
            "B5WUl2UJVe7Vzwmy91fueIPg1RKyf6tdhfvFWIKuT1p0KAMo1ViE34yBCYJEekeb" +
            "09UnKlFX2vvpAgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU" +
            "GKnJ8nXKgOeSVZ5RKAiURZ0LPEUwHQYDVR0OBBYEFBipyfJ1yoDnklWeUSgIlEWd" +
            "CzxFMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAJEen5M10vA/r" +
            "rZl0vASo1godPFRPt0N6CFFM/XL+u2FEM6DkeOyu0J7v9nAy8JfsoKFHSmMPX55W" +
            "7IQkEA0otceT/0qcQOnta5+5q5+frkiCfEbvVknuQrNjlUbKn+EPfQtd+ecpTjKU" +
            "8/FoxEbHXKLxyMPgK1BH4iTVjis9DRNoTH829escKmtmVtj5CYUmPYnRiKaTdF2T" +
            "wwq+kxNtW6ccoVUTKpYsrwSQW6BN9lsebxA40zwms5JNx/aINRvFb/khTN4Z9tV3" +
            "Fnwa7em5UZwtRZQp9g5X8d0S58ICxQI9FOc/VK5o8Iy4wdfvgi0I569oruTCTuQv" +
            "gqqfeVwij3JVerDnEWzj1iz22vcGzKk5j1wJnIAT4Yj9P+mLMBBRWe/ke6d8bEPT" +
            "hjvDEwkTZ4YAsD8giLXZnyCqB0O6RqhG3tb39iqKaEo0GDLsF2qlVQy0VvxjWLpN" +
            "qBRsLTu5TPH3fauyo9M0QwWNAHv6/dRTgF0fkJ2dgc3KF4abmH0+H926+hkuXmlU" +
            "F+jjyc6IaL7VpBbUAk+qoP70k/jzGc1Gd1f1koE1pKht0X0ZNZGiZiPF2IYri8SN" +
            "8vM0NtE0uolskMTrDe8VRz/0t3m2DXTi7CmixVTrTNZhflHYvxRb4yfgaNZFbd+L" +
            "ubcUqhe3yYmNuweQi5vXRKznjnRTL7s=").getBytes() );

    static byte[] chainSubCA = Base64.decode( ("MIIEJjCCAg6gAwIBAgIIHpPgIA6dEIcwDQYJKoZIhvcNAQELBQAwHzEQMA4GA1UE" +
            "AwwHM0dQUENBMjELMAkGA1UEBhMCU0UwHhcNMTcwNjE0MjIyOTMxWhcNMzYwNjA5" +
            "MjIyOTMxWjAiMRMwEQYDVQQDDAozR1BQU1VCQ0EyMQswCQYDVQQGEwJTRTCCASIw" +
            "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKCOJBpTjU2uUHFRC6kAYoKLOBIE" +
            "x0x+qXzQYAyKeFeqbuTlNheZSPO3xqDXlTBB+CejV2MKfpIrELAr40ECrx2aUOqj" +
            "El1QQagD9z3frVYLG3xBAtHWMyJjfIaPg5Ld+z6ljJFOoTkEFZhVp9njjeDL/DC0" +
            "a8guhTfjT2DWBdCYiF9+RejrbBlBR0QW9qVS4r7sk/U18KWeS9hsPhJJaI5i/mRa" +
            "l1eEVcQFWVMmsMKk643uxSEknJoHrvrK2kn/J9L33PrWTztCB/lAFi5PTZaFmqSq" +
            "6+NsEXj1ru+6lR+uX9vvxciakelwEv4HmE+Ujku4PPWTpBZlRP6OBOXUnJMCAwEA" +
            "AaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBQYqcnydcqA55JVnlEo" +
            "CJRFnQs8RTAdBgNVHQ4EFgQUioUuaOpLowYD5+e0o0LgnPUFmqswDgYDVR0PAQH/" +
            "BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQCTMRx+QaNPn0pOh4XB5lqBoryUXbqH" +
            "l25WcQMtPSX82q7Lt+EFTjUXyNJQvpHhvsSrNMrS2PZkegaOn65hw+rky5b5FO7x" +
            "+NZDpCxkTULqRnpTmN0YGLw9mFFz0i1O/Bmg2OmdlDjO6j+fp233BeUO0sRKmuE9" +
            "cvhAqhsxnYLuZqU0Bkb0DxgIK7J9SDFghKFB9ms1QLo+/pw4poN0AOgEeJ45mzJF" +
            "pA20OZUAxgAtaH5EHpjzBAzf2FPuBNkhLGnCOIxRGSnHsKwDHXWxZah2T64n25uB" +
            "nlo6L4tqg2RxeWm7uaimu7tf7eNL4qC/VW6rAGQHQelZJBgBTu/j5PhfHO1YpoDS" +
            "/zZIDU05TCKXLlJOZq+GbVR359O6ol8j7tHos6Z+Iug9gPUwxmMDNA41FSz5ZiNF" +
            "JQh3hzh2BPQNfDIbv3/vFMRRyu5HGTXV/sKObI/cPLeegsFWSqlzOkLa+PU6frMS" +
            "S32C2zkry2tMkIVuJjYv8o9n90mGUlNAkD+/3PfhEgmYIsua06osuoi+F8Q/fFEH" +
            "ZMsczaWz7nE/ibitZ1IGrpqvJRupRKhvLmH2iBGroZHlVrIBmP14EZ/wQXEmvaPx" +
            "JZ9RM9SFGZsTUS5ZCoJP67HazjfKGycKBVVyB2NkWVnPhunQRN3EI3h/fKNbSg0o" +
            "O/i54l/6VggwBg==").getBytes() );

    static byte[] chainUser = Base64.decode( ("MIIDWjCCAkKgAwIBAgIIMWDq/ezmwr4wDQYJKoZIhvcNAQELBQAwIjETMBEGA1UE" +
            "AwwKM0dQUFNVQkNBMjELMAkGA1UEBhMCU0UwHhcNMTcwNjE2MTE0OTE5WhcNMzIw" +
            "NjEyMTE0OTE5WjBBMRswGQYKCZImiZPyLGQBAQwLdWlkdXNlcm5hbWUxFTATBgNV" +
            "BAMMDDNncHB0ZXN0dXNlcjELMAkGA1UEBhMCU0UwggEiMA0GCSqGSIb3DQEBAQUA" +
            "A4IBDwAwggEKAoIBAQDJjMHWJri8VwP/1fs/W5kOQ/672qZu5mEVKmPxX5sVIJKE" +
            "HddJaQ1ZxvfxXiiMReJ4a8oOg8VZaP3vA2bn4IkA7fGgJfDG0kYhgmwnL5nGfTTd" +
            "HN5fH3mSyrD7LTh1hwOopgipw2xZzU6DI+n8MF2eZUpWxbmQFTJGHdtm7u9YrhMO" +
            "hHxgDBWs2cPDvGQMGGYdAdHmaWJcDDb7WWWvmFarsPk9NL/29XjV/n8tgCE7Rnst" +
            "xR0QeQ4537twdFTJBAhpwsohxKW3kvYe1EP3Fe1x5+TPXDCiUSRonlfSA+J62Ciy" +
            "dWZMrU5NcLVlolznuDbC7kt/EFskiUXOq44I4D9NAgMBAAGjdTBzMAwGA1UdEwEB" +
            "/wQCMAAwHwYDVR0jBBgwFoAUioUuaOpLowYD5+e0o0LgnPUFmqswEwYDVR0lBAww" +
            "CgYIKwYBBQUHAwIwHQYDVR0OBBYEFOL4g1io11Levn8yyJRce+x8+rFYMA4GA1Ud" +
            "DwEB/wQEAwIF4DANBgkqhkiG9w0BAQsFAAOCAQEAkqKBgenaxO58KaNJo/xYJr7I" +
            "M0P6MMK3DmjrHkOH76nruHWKI4rZZJuOVw+2djjAfChWiH+SfGUcRmEML/NRn0tQ" +
            "nth3AE522Kn1bF7nbM2P22aWDkaOEVXA1BnhFY8D4/TKUipMYuK9V8ttXxYrrkXU" +
            "3rxzQ/qjMUxZhl/Emlb/B6mOml+nDC2gXTCFeg6u0Nn/JpUfkErM+E/LlqOqQs3a" +
            "S9/8DHADVZaSC8+G1P1iDJVeHnJ9UHYlxWBsXoo1dOyMqSPMv1b90afYUlWN1gSj" +
            "ecSvxm0H1m1PvttZNdEJTDB63Iug5FwvoBbn3RUphhpaawBYFzmK7XHfEAchJw==").getBytes() );

    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProvider();
    }
  
    @Test
    public void testSubjectDirectoryAttributes() throws Exception {
        log.trace(">test17SubjectDirectoryAttributes()");
        Certificate cer = CertTools.getCertfromByteArray(subjDirAttrCert, Certificate.class);
        String ret = SubjectDirAttrExtension.getSubjectDirectoryAttributes(cer);
        assertEquals("countryOfCitizenship=TR", ret);
        cer = CertTools.getCertfromByteArray(subjDirAttrCert2, Certificate.class);
        ret = SubjectDirAttrExtension.getSubjectDirectoryAttributes(cer);
        assertEquals("countryOfResidence=SE, countryOfCitizenship=SE, gender=M, placeOfBirth=Stockholm, dateOfBirth=19710425", ret);
        log.trace("<test17SubjectDirectoryAttributes()");
    }

    @Test
    public void testcvcCert() throws Exception {
        Certificate cert = CertTools.getCertfromByteArray(cvccert, Certificate.class);
        assertNotNull(cert);
        PublicKey pk = cert.getPublicKey();
        assertNotNull(pk);
        assertEquals("RSA", pk.getAlgorithm());
        if (pk instanceof RSAPublicKey) {
            BigInteger modulus = ((RSAPublicKey) pk).getModulus();
            int len = modulus.bitLength();
            assertEquals(1024, len);
        } else {
            fail();
        }
        String subjectdn = CertTools.getSubjectDN(cert);
        assertEquals("CN=RPS,C=SE", subjectdn);
        String issuerdn = CertTools.getIssuerDN(cert);
        assertEquals("CN=RPS,C=SE", issuerdn);
        assertEquals("10110", CertTools.getSerialNumberAsString(cert));
        assertEquals("10110", CertTools.getSerialNumber(cert).toString());
        // Get signature field
        byte[] sign = CertTools.getSignature(cert);
        assertEquals(128, sign.length);
        // Check validity dates
        final long MAY5_0000_2008_GMT = 1209945600000L; 
        final long MAY5_0000_2008_GMT_MINUS1MS = 1209945599999L; 
        final long MAY5_2359_2010_GMT = 1273103999000L; 
        final long MAY5_2359_2010_GMT_PLUS1MS = 1273103999001L;
        
    	assertEquals(MAY5_0000_2008_GMT, CertTools.getNotBefore(cert).getTime());
    	assertEquals(MAY5_2359_2010_GMT, CertTools.getNotAfter(cert).getTime());
    	assertTrue(CertTools.isCA(cert));
        CardVerifiableCertificate cvcert = (CardVerifiableCertificate) cert;
        assertEquals("CVCA", cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAuthRole().name());
    	CertTools.checkValidity(cert, new Date(MAY5_0000_2008_GMT));
    	CertTools.checkValidity(cert, new Date(MAY5_2359_2010_GMT));
    	try {
    		CertTools.checkValidity(cert, new Date(MAY5_0000_2008_GMT_MINUS1MS));
    		fail("Should throw");
    	} catch (CertificateNotYetValidException e) {
    		// NOPMD
    	}
    	try {
    		CertTools.checkValidity(cert, new Date(MAY5_2359_2010_GMT_PLUS1MS));
    		fail("Should throw");
    	} catch (CertificateExpiredException e) {
    		// NOPMD
    	}    	

        // Serialization, CVC provider is installed by CryptoProviderTools.installBCProvider
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(cert);
        oos.close();
        baos.close();
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        Object o = ois.readObject();
        Certificate ocert = (Certificate) o;
        assertEquals("CVC", ocert.getType());

        // Test CVC certificate request encoding
        CVCObject parsedObject = CertificateParser.parseCVCObject(cvcreq);
        CVCertificate req = (CVCertificate) parsedObject;
        PublicKey pubKey = req.getCertificateBody().getPublicKey();
        assertNotNull(pubKey);
        assertEquals("CVC", pubKey.getFormat());
        BigInteger modulus = ((RSAPublicKey) pk).getModulus();
        int len = modulus.bitLength();
        assertEquals(1024, len);

        // Test verification of an authenticated request
        parsedObject = CertificateParser.parseCVCObject(cvcreqrenew);
        CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest) parsedObject;
        try {
            authreq.verify(pubKey);
        } catch (Exception e) {
            fail("Exception verifying authenticated request: " + e.getMessage());
        }
        // Test verification of an authenticated request that fails
        parsedObject = CertificateParser.parseCVCObject(cvcreqrenew);
        authreq = (CVCAuthenticatedRequest) parsedObject;
        req = authreq.getRequest();
        try {
            authreq.verify(req.getCertificateBody().getPublicKey());
            fail("verifying authenticated request should have failed");
        } catch (Exception e) { // NOPMD:
        }
        
        // IS cert
    	KeyPair keyPair = KeyTools.genKeys("prime192v1", "ECDSA");
        CAReferenceField caRef = new CAReferenceField("SE", "CAREF001", "00000");
        HolderReferenceField holderRef = new HolderReferenceField("SE", "HOLDERRE", "00000");
        CVCertificate cv = CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithECDSA", AuthorizationRoleEnum.IS);
        CardVerifiableCertificate cvsha1 = new CardVerifiableCertificate(cv);
        assertFalse(CertTools.isCA(cvsha1));
    }

    @Test
    public void testCreateCertChain() throws Exception {
        // Test creating a certificate chain for CVC CAs
        Certificate cvccertroot = CertTools.getCertfromByteArray(cvccertchainroot, Certificate.class);
        Certificate cvccertsub = CertTools.getCertfromByteArray(cvccertchainsub, Certificate.class);
        assertTrue(CertTools.isCA(cvccertsub)); // DV is a CA also
        assertTrue(CertTools.isCA(cvccertroot));

        ArrayList<Certificate> certlist = new ArrayList<>();
        certlist.add(cvccertsub);
        certlist.add(cvccertroot);
        Collection<Certificate> col = CertTools.createCertChain(certlist);
        assertEquals(2, col.size());
        Iterator<Certificate> iter = col.iterator();
        Certificate certsub = iter.next();
        assertEquals("CN=RPS,C=SE", CertTools.getSubjectDN(certsub));
        Certificate certroot = iter.next();
        assertEquals("CN=HSMCVCA,C=SE", CertTools.getSubjectDN(certroot));

        // Test creating a certificate chain for X509CAs
        Certificate x509certsubsub = CertTools.getCertfromByteArray(x509certchainsubsub, Certificate.class);
        assertTrue(CertTools.isCA(x509certsubsub));
        Certificate x509certsub = CertTools.getCertfromByteArray(x509certchainsub, Certificate.class);
        assertTrue(CertTools.isCA(x509certsub));
        Certificate x509certroot = CertTools.getCertfromByteArray(x509certchainroot, Certificate.class);
        assertTrue(CertTools.isCA(x509certroot));
        certlist = new ArrayList<>();
        certlist.add(x509certsub);
        certlist.add(x509certroot);
        certlist.add(x509certsubsub);
        col = CertTools.createCertChain(certlist);
        assertEquals(3, col.size());
        iter = col.iterator();
        Certificate certsubsub = iter.next();
        assertEquals("CN=SubSubCA", CertTools.getSubjectDN(certsubsub));
        certsub = iter.next();
        assertEquals("CN=SubCA", CertTools.getSubjectDN(certsub));
        certroot = iter.next();
        assertEquals("CN=RootCA", CertTools.getSubjectDN(certroot));

    }

    @Test
    public void testReadPEMCertificate() throws Exception {
        X509Certificate cert = CertTools.getCertfromByteArray(pemcert, X509Certificate.class);
        assertNotNull(cert);
        assertEquals("CN=AdminCA1,O=EJBCA Sample,C=SE", cert.getSubjectDN().toString());
    }

    @Test
    public void testCheckValidity() throws Exception {
    	// NotBefore: Wed Sep 24 08:48:04 CEST 2003 (1064386084000)
    	// NotAfter: Fri Sep 23 08:58:04 CEST 2005 (1127458684000)
    	//
    	Certificate cert = CertTools.getCertfromByteArray(testcert, Certificate.class);
    	assertEquals(1064386084000L, CertTools.getNotBefore(cert).getTime());
    	assertEquals(1127458684000L, CertTools.getNotAfter(cert).getTime());
    	CertTools.checkValidity(cert, new Date(1064386084001L));
    	CertTools.checkValidity(cert, new Date(1127458683999L));
    	try {
    		CertTools.checkValidity(cert, new Date(1064386083999L));
    		assertTrue("Should throw", false);
    	} catch (CertificateNotYetValidException e) {
    		// NOPMD
    	}
    	try {
    		CertTools.checkValidity(cert, new Date(1127458684001L));
    		assertTrue("Should throw", false);
    	} catch (CertificateExpiredException e) {
    		// NOPMD
    	}    	
    }
  

    /**
     * Tests encoding DN attributes as UTF-8 or printable string
     */
    @Test
    public void testPrintableStringDN() throws Exception {
        log.trace(">testPrintableStringDN()");
        
        final String dnstr = "C=SE,O=Test,CN=Test";
        
        final X500Name xn1 = CertTools.stringToBcX500Name(dnstr, new CeSecoreNameStyle(), false);
        assertTrue("When using CeSecoreNameStyle, C was not of PrintableString type", xn1.getRDNs()[0].getFirst().getValue() instanceof DERPrintableString);
        assertTrue("When using CeSecoreNameStyle, O was not of UTF8String type", xn1.getRDNs()[1].getFirst().getValue() instanceof DERUTF8String);
        assertTrue("When using CeSecoreNameStyle, CN was not of UTF8String type", xn1.getRDNs()[2].getFirst().getValue() instanceof DERUTF8String);
        
        final X500Name xn2 = CertTools.stringToBcX500Name(dnstr, new PrintableStringNameStyle(), false);
        assertTrue("When using PrintableStringNameStyle, C was not of PrintableString type", xn2.getRDNs()[0].getFirst().getValue() instanceof DERPrintableString);
        assertTrue("When using PrintableStringNameStyle, O was not of PrintableString type", xn2.getRDNs()[1].getFirst().getValue() instanceof DERPrintableString);
        assertTrue("When using PrintableStringNameStyle, CN was not of PrintableString type", xn2.getRDNs()[2].getFirst().getValue() instanceof DERPrintableString);
        
        log.trace("<testPrintableStringDN()");
    }

    @Test
    public void testCertificateWithEmptyOU() throws CertificateParsingException {
        byte[] customerCertificate = ("-----BEGIN CERTIFICATE-----\n"
                +"MIIG6jCCBdKgAwIBAgISESF6Y6b1UsT6yhdJZ1npIcsFMA0GCSqGSIb3DQEBBQUA"
                +"MFkxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS8wLQYD"
                +"VQQDEyZHbG9iYWxTaWduIEV4dGVuZGVkIFZhbGlkYXRpb24gQ0EgLSBHMjAeFw0x"
                +"MjA4MDExNDA5MTBaFw0xNDA4MDIxNDA5MTBaMIHiMR0wGwYDVQQPDBRQcml2YXRl"
                +"IE9yZ2FuaXphdGlvbjERMA8GA1UEBRMIMDgxNDgzMTAxEzARBgsrBgEEAYI3PAIB"
                +"AxMCTkwxCzAJBgNVBAYTAk5MMRMwEQYDVQQIEwpPdmVyaWpzc2VsMRAwDgYDVQQH"
                +"EwdEZW4gSGFtMRcwFQYDVQQJEw5Lcm9lemVuaG9layAgODEJMAcGA1UECxMAMR8w"
                +"HQYDVQQKExZGb3RvIEtvbmlqbmVuYmVyZyBCLlYuMSAwHgYDVQQDExd3d3cuZm90"
                +"b2tvbmlqbmVuYmVyZy5ubDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB"
                +"AN1kecyhfcJh7P33Sn5V4ThAneF9CehadDpAwm6u/o0htocYhQAxioXhUMXO6hcV"
                +"NpyEeMBhEVKOSWuTunMhCUB1pgp/yY7/ul2xoXVYkEhBwuRo0ttg1XcQG6zoC1VC"
                +"JTBTBgLWjeTxaEf10e2jALvuHAaPWKOLWykBaVbbMF6rAPHbV0t+GwQjGPkCOKoJ"
                +"JvJhAm+8PTYfNZnYvHByBjg0g8axANTNmTutEnGxfqhzcnMj4dS0jZfSfN7JQn/o"
                +"ul032uVfjlU6gDay/9vUzd67wb+0S/XZH1d8CGXZCYUlGoG5vIbkffOoqoN2+mac"
                +"Vqco354CSjV5rO+M/qY2nZMUoCTRGPiWIahSQbAbuLssRozWAbk5tW1h4LqlwV1r"
                +"OgRmxC0B3pfoouQuEdV52XMgiWyI8VKsKJL5K/oZCObyPszxfBhvl+jWhEa/xYxv"
                +"sB9VdIBn8FWlXrMf3a27knjAlgVIM5AfZForfMkRVcUaRCrhYSn6n+w4wrDc0Fvr"
                +"tC3iimvHztOQOcsA4dRc9oLDJ73v6ONLLwhUg/UEid80qc8fFFeBX6xLy4dCmVJP"
                +"6Kr6A1u/QssrAIYzCJsF90bXy1r4lifhqJWG+qmst6CUl+CeVVFkRDyi0M8W+P16"
                +"vslOgg8ut8w3JjMQnu0pnDCbsDFmC44c5Smh0CSoELPBAgMBAAGjggIgMIICHDAO"
                +"BgNVHQ8BAf8EBAMCBaAwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAQEwNDAyBggrBgEF"
                +"BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wgYUG"
                +"A1UdEQR+MHyCF3d3dy5mb3Rva29uaWpuZW5iZXJnLm5sghp3d3cuZm90b2tvbmlq"
                +"bmVuYmVyZy5jby51a4IXd3d3LmZvdG9rb25pam5lbmJlcmcuZGWCF3d3dy5mb3Rv"
                +"a29uaWpuZW5iZXJnLmJlghNmb3Rva29uaWpuZW5iZXJnLm5sMAkGA1UdEwQCMAAw"
                +"HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD8GA1UdHwQ4MDYwNKAyoDCG"
                +"Lmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3NleHRlbmR2YWxnMi5jcmww"
                +"gYgGCCsGAQUFBwEBBHwwejBBBggrBgEFBQcwAoY1aHR0cDovL3NlY3VyZS5nbG9i"
                +"YWxzaWduLmNvbS9jYWNlcnQvZ3NleHRlbmR2YWxnMi5jcnQwNQYIKwYBBQUHMAGG"
                +"KWh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2V4dGVuZHZhbGcyMB0GA1Ud"
                +"DgQWBBRcEvciiy8aP7yBrHIrhdDs9Y+LfjAfBgNVHSMEGDAWgBSwsEr9HHUo+Bxh"
                +"qhP2+sGQPWsWozANBgkqhkiG9w0BAQUFAAOCAQEAeBPW1Mz9NaeMGvjBNPOntkMw"
                +"k32sSlZ7fu/zTPLDiV4CHOom67amngXZWK/WGsVr862EHoWOXoFfIeKIKMZslmM5"
                +"HvPevKBg3IHKBp1BLUTr2b5/yvy5TijeojraOtXipKtRWXyRM4E6YEX1YqwL5nF5"
                +"lr53G4ikW+RSdugCOLbio7vfj7bSK34E4EBQE8jU2+RqiXyMgO8Ni0NitNZxmc8K"
                +"JDlbioUjBIRX/xElQjdKqYJjUERgZxmk0+zmeF4bAN0nVJtAv6N/JOw7VOsUAea7"
                +"uICq887NuvFm3bo5s6vFsGlPLbNDgresVimkvhmliuUuA5Q8U38QHZ33oZI1XA=="
                +"\n-----END CERTIFICATE-----").getBytes();
        X509Certificate cert = CertTools.getCertfromByteArray(customerCertificate, BouncyCastleProvider.PROVIDER_NAME, X509Certificate.class);
        String dn = CertTools.getSubjectDN(cert);
        assertEquals("JurisdictionCountry=NL,STREET=Kroezenhoek  8,BusinessCategory=Private Organization,CN=www.fotokonijnenberg.nl,SN=08148310,OU=,O=Foto Konijnenberg B.V.,L=Den Ham,ST=Overijssel,C=NL", dn);
    }

    @Test
    public void testCertificateWithHashInSN() throws CertificateParsingException {
        byte[] customerCertificate = ("-----BEGIN CERTIFICATE-----\n" + "MIIGHzCCBQegAwIBAgISESGJvLFqytscBE3/U/YSjVZtMA0GCSqGSIb3DQEBBQUA"
                + "MFkxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS8wLQYD"
                + "VQQDEyZHbG9iYWxTaWduIEV4dGVuZGVkIFZhbGlkYXRpb24gQ0EgLSBHMjAeFw0x"
                + "MzEyMTkyMTIxMjFaFw0xNTEyMjAyMTIxMjFaMIIBGjEdMBsGA1UEDwwUUHJpdmF0"
                + "ZSBPcmdhbml6YXRpb24xITAfBgNVBAUMGCNDTlBKOjE1LjA5NS4yNzEvMDAwMS00"
                + "NTETMBEGCysGAQQBgjc8AgEDEwJCUjELMAkGA1UEBhMCQlIxDzANBgNVBAgMBlBh"
                + "cmFuYTERMA8GA1UEBwwIQ2lhbm9ydGUxGDAWBgNVBAkTD0F2ZW5pZGEgUGFyYWli"
                + "YTEaMBgGA1UECwwRTW9yZW5hIFJvc2EgR3JvdXAxPDA6BgNVBAoMM01vcmVuYSBS"
                + "b3NhIEluZHVzdHJpYSBlIENvbWVyY2lvIGRlIENvbmZlY2NvZXMgUy5BLjEcMBoG"
                + "A1UEAwwTbW9yZW5hcm9zYWdyb3VwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP"
                + "ADCCAQoCggEBAJjIbr8WUwjRkiRLzjRXZwZFzxKX0/MT7T8037vg2XcxqoCN3e0D"
                + "GMigxgDYisbmzUJB5uZdCAApYvK0T047JFzYY0pyb70wxebCTR/YrXlgVJzt6MzI"
                + "GXL3B/cHBz2qkHFS3PqFT0N9PfBnLPT5fQ1Ri6yLIk5zgP0HfJVS4W+WE4YgbM/c"
                + "fIJtWLxwTKcWQbI9FBmkx8XTUuKOxYs7LGIku40cCD6cTL8qN6StoPx6xNL8cfu8"
                + "ImhIFv9ITIG5XQv4sfb34a2GpFiBrFWgrXWA3ZhBzdw1Hw4OCPn++ydVip6BvPhT"
                + "KXelYMKrwvXFVYVWCEPJST6yZIVWbvfWysUCAwEAAaOCAhwwggIYMA4GA1UdDwEB"
                + "/wQEAwIFoDBMBgNVHSAERTBDMEEGCSsGAQQBoDIBATA0MDIGCCsGAQUFBwIBFiZo"
                + "dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzCBgQYDVR0RBHow"
                + "eIITbW9yZW5hcm9zYWdyb3VwLmNvbYIdZXh0cmFvcmRpbmFyaW9tdW5kb2pveS5j"
                + "b20uYnKCCmpveS5jb20uYnKCFW1hcmlhdmFsZW50aW5hLmNvbS5icoIRbW9yZW5h"
                + "cm9zYS5jb20uYnKCDHppbmNvLmNvbS5icjAJBgNVHRMEAjAAMB0GA1UdJQQWMBQG"
                + "CCsGAQUFBwMBBggrBgEFBQcDAjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js"
                + "Lmdsb2JhbHNpZ24uY29tL2dzL2dzZXh0ZW5kdmFsZzIuY3JsMIGIBggrBgEFBQcB"
                + "AQR8MHowQQYIKwYBBQUHMAKGNWh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20v"
                + "Y2FjZXJ0L2dzZXh0ZW5kdmFsZzIuY3J0MDUGCCsGAQUFBzABhilodHRwOi8vb2Nz"
                + "cDIuZ2xvYmFsc2lnbi5jb20vZ3NleHRlbmR2YWxnMjAdBgNVHQ4EFgQU2uc6NRKH"
                + "l1c9JEs648L0s5R1zgIwHwYDVR0jBBgwFoAUsLBK/Rx1KPgcYaoT9vrBkD1rFqMw"
                + "DQYJKoZIhvcNAQEFBQADggEBAJNa16vT304p0DVGUX9K50JjGD3rcruBHO+uENMP"
                + "6SkqFVCVxx+jha2Z7IX4kv1IsRn2ZYNoxYHkefGPJD4qk1X+MTvEgN2nKUxJQGrJ"
                + "n/vDnGCJjNWwmcoBmp7n3//S4S4CtNMhGXJ61mcx1tK7sIK14xC+MD/33Q675OhO"
                + "84bjb9kdIpqDaYl6x8JuaLlKim9249IAiYm/0IH+aLMyE9LO1+ohUSq4nCoZ30dV"
                + "5OkLGTRxw1vYfHKgf1BHMOki/PKVxxE5qas5p43xFcdp8r94LeErvlm5NtgJFHA0" + "zSNkEEEgGMdf2/MyB49NTuqyJWtz94Ox0HKvHPCfLtG/Ib4="
                + "\n-----END CERTIFICATE-----").getBytes();
        X509Certificate cert = CertTools.getCertfromByteArray(customerCertificate, BouncyCastleProvider.PROVIDER_NAME, X509Certificate.class);
        String dn = CertTools.getSubjectDN(cert);
        assertEquals("JurisdictionCountry=BR,STREET=Avenida Paraiba,BusinessCategory=Private Organization,CN=morenarosagroup.com,SN=\\#CNPJ:15.095.271/0001-45,OU=Morena Rosa Group,O=Morena Rosa Industria e Comercio de Confeccoes S.A.,L=Cianorte,ST=Parana,C=BR", dn);
    }
    
    /**
     * Tests preventing heap overflow during getCertsFromPEM()
     */
    @Test
    public void testPreventingHeapOverflowDuringGetCertsFromPEM() throws Exception {
        log.trace(">testPreventingHeapOverflowDuringGetCertsFromPEM()");
        
        ByteArrayOutputStream byteArrayOutputStream = null;
        try {
            byteArrayOutputStream = new ByteArrayOutputStream();
            SecurityFilterInputStreamTest.prepareExploitStream(byteArrayOutputStream, 0x1FFFFF);  // 0x1FFFFF just simulates exploit stream

            CertTools.getCertsFromPEM(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()), X509Certificate.class);
            fail("No Java heap error happened for StringBuilder exploit (MaxHeap = " + Runtime.getRuntime().maxMemory()/(1024*1024) + "MB) and"
                    + " SecurityFilterInputStream hasn't limited the size of input stream during testPreventingHeapOverflowDuringGetCertsFromPEM");
        } catch (SecurityException e) {
            //Good
        } catch (Exception e){
            fail("Unexpected exception: " + e.getMessage() + " during testPreventingHeapOverflowDuringGetCertsFromPEM");
        }finally {
            if (byteArrayOutputStream != null) {
                byteArrayOutputStream.close();
            }
        }
        
        log.trace("<testPreventingHeapOverflowDuringGetCertsFromPEM()");
    }
    
    /**
     * Tests preventing heap overflow during getCertsFromByteArray for X509Certificate.class
     */
    @Test
    public void testPreventingHeapOverflowDuringGetCertsFromByteArray() throws Exception {
        log.trace(">testPreventingHeapOverflowDuringgetCertsFromByteArray()");

        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            SecurityFilterInputStreamTest.prepareExploitStream(byteArrayOutputStream, 0x1FFFFF); // 0x1FFFFF just simulates exploit stream

            CertTools.getCertfromByteArray(byteArrayOutputStream.toByteArray(), X509Certificate.class);
            fail("No Java heap error happened for StringBuilder exploit (MaxHeap = " + Runtime.getRuntime().maxMemory() / (1024 * 1024) + "MB) and"
                    + " SecurityFilterInputStream hasn't limited the size of input stream during testPreventingHeapOverflowDuringgetCertsFromByteArray");
        } catch (CertificateParsingException e) { //It seems that BC provider while generating certificate wraps RuntimeException into CertificateException (which CertTools wraps into CertificateParsingException...)
            //Good
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getMessage() + " during testPreventingHeapOverflowDuringgetCertsFromByteArray");
        }
        log.trace("<testPreventingHeapOverflowDuringgetCertsFromByteArray()");
    }

    @Test
    public void testCertCollectionFromArray() throws Exception {
        Certificate[] certarray = new Certificate[3];
        certarray[0] = CertTools.getCertfromByteArray(testcert, Certificate.class);
        certarray[1] = CertTools.getCertfromByteArray(guidcert, Certificate.class);
        certarray[2] = CertTools.getCertfromByteArray(altNameCert, Certificate.class);
        Collection<Certificate> certs = CertTools.getCertCollectionFromArray(certarray, BouncyCastleProvider.PROVIDER_NAME);
        assertEquals(3, certs.size());
        Iterator<Certificate> iter = certs.iterator();
        assertEquals("CN=p12test,O=PrimeTest,C=SE", CertTools.getSubjectDN(iter.next()));
        assertEquals("UID=guid,CN=Guid,C=SE", CertTools.getSubjectDN(iter.next()));
        assertEquals("CN=foo,O=AnaTom,C=SE", CertTools.getSubjectDN(iter.next()));
        byte[] bytes = CertTools.getPemFromCertificateChain(certs);
        String str = new String(bytes);
        assertTrue(str.contains("BEGIN CERTIFICATE"));
    }
    
    /**
     * Tests the following methods:
     * <ul>
     * <li>{@link X509CertificateTools#checkNameConstraints}</li>
     * <li>{@link NameConstraint#parseNameConstraintsList}</li>
     * <li>{@link NameConstraint#toGeneralSubtrees}</li>
     * </ul>
     */
    @Test
    public void testNameConstraints() throws Exception {
        final String permitted = "C=SE,O=PrimeKey,CN=example.com\n" +
                                 "example.com\n" +
                                 "@mail.example\n" +
                                 "user@host.com\n" +
                                 "uri:example.com\n" +
                                 "uri:.example.com\n" +
                                 "10.0.0.0/8\n" +
                                 "www.example.com\n" +
                                 "   C=SE,  CN=spacing    \n";
        final String excluded = "forbidden.example.com\n" +
                                "postmaster@mail.example\n" +
                                "uri:def123.test.com\n" +
                                "10.1.0.0/16\n" +
                                "::/0"; // IPv6
        
        final List<Extension> extensions = new ArrayList<>();
        GeneralSubtree[] permittedSubtrees = NameConstraint.toGeneralSubtrees(NameConstraint.parseNameConstraintsList(permitted));
        GeneralSubtree[] excludedSubtrees = NameConstraint.toGeneralSubtrees(NameConstraint.parseNameConstraintsList(excluded));
        byte[] extdata = new NameConstraints(permittedSubtrees, excludedSubtrees).toASN1Primitive().getEncoded();
        extensions.add(new Extension(Extension.nameConstraints, false, extdata));
               
        final KeyPair testkeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate cacert = X509CertificateTools.genSelfCertForPurpose("C=SE,CN=Test Name Constraints CA", 365, null,
                testkeys.getPrivate(), testkeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true,
                X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, "BC", true, extensions);
        log.info(X509CertificateTools.getPemFromCertificate(cacert));

        // Allowed subject DNs
        final X500Name validDN = new X500Name("C=SE,O=PrimeKey,CN=example.com"); // re-used below
        CertTools.checkNameConstraints(cacert, validDN, null);
        CertTools.checkNameConstraints(cacert, new X500Name("C=SE,CN=spacing"), null);
        // When importing certificates issued by Name Constrained CAs we may run into issues with DN encoding and DN order
        // In EndEntityManagementSessionBean.addUser we use something like:
        // X500Name subjectDNName1 = X509CertificateTools.stringToBcX500Name(X509CertificateTools.getSubjectDN(subjectCert), nameStyle, useLdapDnOrder);
        // Where nameStyle and dnOrder can have different values
        X500Name validDN2 = X509CertificateTools.stringToBcX500Name("C=SE,O=PrimeKey,CN=example.com", CeSecoreNameStyle.INSTANCE, false);
        CertTools.checkNameConstraints(cacert, validDN2, null);
        X500Name invalidDN1 = X509CertificateTools.stringToBcX500Name("C=SE,O=PrimeKey,CN=example.com", CeSecoreNameStyle.INSTANCE, true);
        checkNCException(cacert, invalidDN1, null, "ldapDnOrder true was accepted");
        X500Name validDN3 = X509CertificateTools.stringToBcX500Name("C=SE,O=PrimeKey,CN=example.com", PrintableStringNameStyle.INSTANCE, false);
        // This should be accepted according to RFC5280, section 4.2.1.10
        // "CAs issuing certificates with a restriction of the form directoryName
        // SHOULD NOT rely on implementation of the full ISO DN name comparison
        // algorithm. This implies name restrictions MUST be stated identically to
        // the encoding used in the subject field or subjectAltName extension."
        // ISO DN matching makes string conversion of various formats, UTF-8, PrintableString etc and compares the result.
        // But, there might be clients who do a binary check, which will likely fail if the encodings differ, so as a CA it's important to encode the NC right
        CertTools.checkNameConstraints(cacert, validDN3, null);
        // Before up to BC 1.61, encoding was checked and this was rejected. See ECA-9035
        // checkNCException(cacert, invalidDN2, null, "PrintableStringNameStyle was accepted");


        // Allowed subject alternative names
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, "example.com")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, "x.sub.example.com")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "someuser@mail.example")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "user@host.com")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("10.0.0.1").getAddress()))));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("10.255.255.255").getAddress()))));
        
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, "example.com/")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, "host.example.com")));


        // Disallowed subject DN
        checkNCException(cacert, new X500Name("C=DK,CN=example.com"), null, "Disallowed DN (wrong field value) was accepted");
        checkNCException(cacert, new X500Name("C=SE,O=Company,CN=example.com"), null, "Disallowed DN (extra field) was accepted");
        
        // Disallowed SAN
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "bad.com"), "Disallowed SAN (wrong DNS name) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "forbidden.example.com"), "Disallowed SAN (excluded DNS subdomain) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.rfc822Name, "wronguser@host.com"), "Disallowed SAN (wrong e-mail) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("10.1.0.1").getAddress())), "Disallowed SAN (excluded IPv4 address) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("192.0.2.1").getAddress())), "Disallowed SAN (wrong IPv4 address) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("2001:DB8::").getAddress())), "Disallowed SAN (IPv6 address) was accepted");
        
        checkNCException(cacert, validDN, new GeneralName(GeneralName.uniformResourceIdentifier, "ldap://def123.test.com:8080"), "Disallowed SAN (wrong URI) was accepted");

    }

    @Test
    public void testNameConstraintsEmptyDNS() throws Exception {
        final String excluded = ".";
                                
        final List<Extension> extensions = new ArrayList<>();
        
        List<String> ncList = NameConstraint.parseNameConstraintsList(excluded);
        
        GeneralSubtree[] excludedSubtrees = NameConstraint.toGeneralSubtrees(ncList);
        byte[] extdata = new NameConstraints(null, excludedSubtrees).toASN1Primitive().getEncoded();
        extensions.add(new Extension(Extension.nameConstraints, false, extdata));
        
        final KeyPair testkeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate cacert = X509CertificateTools.genSelfCertForPurpose("C=SE,CN=Test Name Constraints CA", 365, null,
                testkeys.getPrivate(), testkeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true,
                X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, "BC", true, extensions);
        
        // Allowed subject DNs
        final X500Name validDN = new X500Name("C=SE,O=PrimeKey,CN=example.com");
        
        // Disallowed SAN
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "test.email.com"), "Disallowed SAN (excluded test.email.com DNS name) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "example.com"), "Disallowed SAN (excluded example.com DNS name) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "com"), "Disallowed SAN (excluded com DNS name) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, ".com"), "Disallowed SAN (excluded .com DNS name) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, ".example.com"), "Disallowed SAN (excluded .example.com DNS name) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "."), "Disallowed SAN (excluded . DNS name) was accepted");

    }
    
    /** Check Name Constraints that are expected to fail NC validation, and fail the JUnit test of the NC validation 
     * does not fail with an IllegalNameException
     */
    private static void checkNCException(X509Certificate cacert, X500Name subjectDNName, GeneralName subjectAltName, String message) {
        try {
            CertTools.checkNameConstraints(cacert, subjectDNName, subjectAltName != null ? new GeneralNames(subjectAltName) : null);
            fail(message);
        } catch (IllegalNameException e) { 
            /* NOPMD expected */ 
        }
    }  

    @Test
    public void testNameConstraintsNonDNS() throws Exception {
        final String excluded = "test@host.com";                              
        final List<Extension> extensions = new ArrayList<>();
        List<String> ncList = NameConstraint.parseNameConstraintsList(excluded);
        GeneralSubtree[] excludedSubtrees = NameConstraint.toGeneralSubtrees(ncList);
        byte[] extdata = new NameConstraints(null, excludedSubtrees).toASN1Primitive().getEncoded();
        extensions.add(new Extension(Extension.nameConstraints, false, extdata));
        final KeyPair testkeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate cacert = X509CertificateTools.genSelfCertForPurpose("C=SE,CN=Test Name Constraints CA", 365, null,
                testkeys.getPrivate(), testkeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true,
                X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, "BC", true, extensions);
        // Allowed subject DNs
        final X500Name validDN = new X500Name("C=SE,O=PrimeKey,CN=example.com");       
        // Disallowed SAN
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, "test.email.com")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, "example.com")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, "com")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, ".com")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, ".example.com")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, ".")));
    }

    @Test
    public void testGetOidFromString() {
        assertEquals("1.2.3.4", CertTools.getOidFromString("1.2.3.4.value"));
        assertEquals("1.2.3.4", CertTools.getOidFromString("1.2.3.4.value2"));
        assertEquals("1.12.123.1234", CertTools.getOidFromString("1.12.123.1234.value3"));
        assertEquals("1.2.3.4", CertTools.getOidFromString("1.2.3.4.foobar"));
        assertEquals("1.2.3.4", CertTools.getOidFromString("1.2.3.4"));
        assertEquals(null, CertTools.getOidFromString("aaaaaaaaaaaaaa"));
    }
    
    @Test
    public void testGetOidWildcardPattern() {
        // Base cases
        assertTrue("1.2.3.4".matches(CertTools.getOidWildcardPattern("1.2.3.4")));
        assertTrue("1.2.3.4".matches(CertTools.getOidWildcardPattern("*.2.3.4")));
        assertTrue("1.23.3.4".matches(CertTools.getOidWildcardPattern("1.*.3.4")));
        assertTrue("1.2.3.4".matches(CertTools.getOidWildcardPattern("1.2.3.*")));
        // Multiple wild cards
        assertTrue("1.2.3.4".matches(CertTools.getOidWildcardPattern("*.2.3.*")));
        // Only allow numeric wild card matches
        assertFalse("1.a.3.4".matches(CertTools.getOidWildcardPattern("1.*.3.4")));
        // Verify that dots aren't interpreted as regex wild cards
        assertFalse("1.2.3.4".matches(CertTools.getOidWildcardPattern("1.2a3.4")));
    }


}
