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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URL;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.certificates.util.cert.QCStatementExtension;
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

import com.novell.ldap.LDAPDN;

/**
 * Tests the CertTools class .
 * 
 * @version $Id$
 */
public class CertToolsTest {
    private static Logger log = Logger.getLogger(CertToolsTest.class);
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

    private static byte[] altNameCertWithDirectoryName = Base64
            .decode(("MIIFkjCCBPugAwIBAgIIBzGqGNsLMqwwDQYJKoZIhvcNAQEFBQAwWTEYMBYGA1UEAwwPU1VCX0NBX1dJTkRPV1MzMQ8wDQYDVQQLEwZQS0lHVkExHzAdBgNVBAoTFkdlbmVyYWxpdGF0IFZhbGVuY2lhbmExCzAJBgNVBAYTAkVTMB4XDTA2MDQyMTA5NDQ0OVoXDTA4MDQyMDA5NTQ0OVowcTEbMBkGCgmSJomT8ixkAQETC3Rlc3REaXJOYW1lMRQwEgYDVQQDEwt0ZXN0RGlyTmFtZTEOMAwGA1UECxMFbG9nb24xHzAdBgNVBAoTFkdlbmVyYWxpdGF0IFZhbGVuY2lhbmExCzAJBgNVBAYTAkVTMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCDLxMhz40RxCm21HoCBNa9x1UyPmhVkPdtt2V7dixgjOYz+ffKeebjn/jSd4nfXgd7fxpzezB8t673F2OtC3ENl1zek5Msj2KoinVu8vvZ78KMRq/H1rDFguhjSL0o19Cpob0qQFB/ukPZMNoKBNnMVnR1C4juB1eJVXWmHyJxIwIDAQABo4IDSTCCA0UwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwMwYDVR0lBCwwKgYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDBwYKKwYBBAGCNxQCAjAdBgNVHQ4EFgQUZz4hrh3dr6VWvEbAPe8pg7szNi4wHwYDVR0jBBgwFoAUTuOaap9UBpQ8dqwOufYoOQucfUowXAYDVR0RBFUwU6QhMB8xHTAbBgNVBAMMFHRlc3REaXJOYW1lfGRpcnxuYW1loC4GCisGAQQBgjcUAgOgIAwedGVzdERpck5hbWVAamFtYWRvci5wa2kuZ3ZhLmVzMIIBtgYDVR0gBIIBrTCCAakwggGlBgsrBgEEAb9VAwoBADCCAZQwggFeBggrBgEFBQcCAjCCAVAeggFMAEMAZQByAHQAaQBmAGkAYwBhAGQAbwAgAHIAZQBjAG8AbgBvAGMAaQBkAG8AIABkAGUAIABFAG4AdABpAGQAYQBkACAAZQB4AHAAZQBkAGkAZABvACAAcABvAHIAIABsAGEAIABBAHUAdABvAHIAaQBkAGEAZAAgAGQAZQAgAEMAZQByAHQAaQBmAGkAYwBhAGMAaQDzAG4AIABkAGUAIABsAGEAIABDAG8AbQB1AG4AaQB0AGEAdAAgAFYAYQBsAGUAbgBjAGkAYQBuAGEAIAAoAFAAbAAuACAATQBhAG4AaQBzAGUAcwAgADEALgAgAEMASQBGACAAUwA0ADYAMQAxADAAMAAxAEEAKQAuACAAQwBQAFMAIAB5ACAAQwBQACAAZQBuACAAaAB0AHQAcAA6AC8ALwB3AHcAdwAuAGEAYwBjAHYALgBlAHMwMAYIKwYBBQUHAgEWJGh0dHA6Ly93d3cuYWNjdi5lcy9sZWdpc2xhY2lvbl9jLmh0bTBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vemFyYXRob3MuamFtYWRvci5ndmEuZXMvU1VCX0NBX1dJTkRPV1MzLmNybDBTBggrBgEFBQcBAQRHMEUwQwYIKwYBBQUHMAGGN2h0dHA6Ly91bGlrLnBraS5ndmEuZXM6ODA4MC9lamJjYS9wdWJsaWN3ZWIvc3RhdHVzL29jc3AwDQYJKoZIhvcNAQEFBQADgYEASofgaj06BOE847RTEgVba52lmPWADgeWxKHZAk1t9LdNzuFJ8B/SC3gi0rsAA/lQGSd4WzPbkmJKkVZ6Q9ybpqg4AJRaIZBkoQw1KNXPYAcgt5XLeIhUACdKIPhfPQr+vQtaC1wi5xV8EBCLpLmpzN9bpZdze/724UB4Y94KhII=")
                    .getBytes());

    private static byte[] altNameCertWithXmppAddr = Base64
            .decode(("MIIFRTCCBC2gAwIBAgIQH4vuCeSeadpH3oWlr9q7wTANBgkqhkiG9w0BAQsFADA1"
                    +"MRYwFAYDVQQDDA1NYW5hZ2VtZW50IENBMQ4wDAYDVQQKDAVQSy1ETTELMAkGA1UE"
                    +"BhMCQUUwHhcNMTcxMjAxMTI0MTQ5WhcNMTgxMjAxMTI0MTQ5WjAVMRMwEQYDVQQD"
                    +"DApUb21hcyBUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbJum3Yilo2fD"
                    +"DOWj5+1G/qxhOWf5sViiad0aSOBE/8laiEGoYHaz7IwA/cj81tUDTvQ48G9O6uhb"
                    +"R6QZ9UJOxaOCAzowggM2MBkGB2eBCAEBBgIEDjAMAgEAMQcTAVATAklEMAwGA1Ud"
                    +"EwEB/wQCMAAwHwYDVR0jBBgwFoAUu2ifcFjWKrS4wThm+sPPj8GYatowfwYIKwYB"
                    +"BQUHAQEEczBxMCYGCCsGAQUFBzAChhpodHRwOi8vY2Fpc3N1ZXJwcm9maWxlLmNv"
                    +"bTAnBggrBgEFBQcwAoYbaHR0cDovL2NhaXNzdWVycHJvZmlsZTEuY29tMB4GCCsG"
                    +"AQUFBzABhhJodHRwOi8vY2FvY3NwLmNvbS8wgcYGA1UdEQSBvjCBu4YtdXJuOnV1"
                    +"aWQ6ZjgxZDRmYWUtN2RlYy0xMWQwLWE3NjUtMDBhMGM5MWU2YmY2iAMpAQKgGAYK"
                    +"KwYBBAGCNxQCA6AKDAhmb29AYS5zZaAjBggrBgEFBQcIBaAXDBV0b21hc0B4bXBw"
                    +"LmRvbWFpbi5jb22gGwYIKwYBBQUHCAegDxYNX1NlcnZpY2UuTmFtZaApBghghkgB"
                    +"ZQMGBqAdBBsEGdIyENghDCwahDCFoWhYMAhCEIYIgjIQw+Ewgc0GA1UdIASBxTCB"
                    +"wjCBtAYLKwYBBAGC8DMBAQIwgaQwKAYIKwYBBQUHAgEWHGh0dHBzOi8vcG9saWN5"
                    +"LnZpbmNhc2lnbi5uZXQweAYIKwYBBQUHAgIwbAxqQ2VydGlmaWNhZG8gY3VhbGlm"
                    +"aWNhZG8gZGUgcGVyc29uYSBmw61zaWNhIHZpbmN1bGFkYSBlbWl0aWRvIGVuIFNv"
                    +"ZnR3YXJlLiBWZXIgaHR0cHM6Ly9wb2xpY3kudmluY2FzaWduLm5ldDAJBgcEAIvs"
                    +"QAEAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAjBggrBgEFBQcBAwQX"
                    +"MBUwEwYGBACORgEGMAkGBwQAjkYBBgEwHQYDVR0OBBYEFEVR44we5Nr5M5L/PtJ5"
                    +"gh/Z9or+MBoGA1UdEAQTMBGBDzIwMTcxMjMxMTI0MTQ5WjAOBgNVHQ8BAf8EBAMC"
                    +"BeAwCgYDVR02BAMCAQAwDwYDVR0kBAgwBoABAIEBADAkBgNVHSEEHTAbMBkGCisG"
                    +"AQQBgbR9ASQGCysGAQQBgrgdBAEBMA0GCSqGSIb3DQEBCwUAA4IBAQDhXY41HX9c"
                    +"bugosrg4qnF39OecZkeo43ElCEwCBGeiwk36BJdB5xjfHsYtxN2HA6wxs+CyRwSZ"
                    +"elt0bGpVxAHGIcHd7bTyrE5c9kMBssce+MvJPbM4w9RLhKxqX1/sV1xvcaF2JY0B"
                    +"JNu838tbtiDgFRUefoouQ03/mhEwuiAjokBrlVZmRQhZi6a6DaPV8YUw5liEdRYU"
                    +"KIiZxSHfOuSL3wVAwjCuqTRDw+i1lJcHBzZ5m4Tx8JWndzqVw+wfR0IgEgkgNjB0"
                    +"wb6l8y54W4iC90DG7u6XJKY/k6Ei6lLi1EJP+w0A9HtZyNUVKqotNc+1E8yXv17N"
                    +"Rw0pP1f3jhdJ").getBytes());

    private static byte[] altNameCertWithSpecialCharacters = Base64.decode(
                    ("MIIElDCCA3ygAwIBAgIIPQiMRNUtIDwwDQYJKoZIhvcNAQELBQAwNzEVMBMGA1UE"
                    +"AwwMTWFuYWdlbWVudENBMREwDwYDVQQKDAhEZXYgQ0EgMTELMAkGA1UEBhMCU0Uw"
                    +"HhcNMTcwOTEyMDk0ODI2WhcNMTkwOTEyMDk0ODI2WjCB3zEtMCsGCysGAQQBgjc8"
                    +"AgECDBx0ZXN0LHdpdGhcc3BlY2lhbD1jaGFyYWN0ZXJzMSUwIwYDVQQJDBx0ZXN0"
                    +"LHdpdGhcc3BlY2lhbD1jaGFyYWN0ZXJzMSUwIwYDVQRBDBx0ZXN0LHdpdGhcc3Bl"
                    +"Y2lhbD1jaGFyYWN0ZXJzMRMwEQYDVQQUEwoxMiwzNDUsNjc4MSUwIwYDVQQPDBx0"
                    +"ZXN0LHdpdGhcc3BlY2lhbD1jaGFyYWN0ZXJzMSQwIgYDVQQRDBt0ZXN0LHdpdGhc"
                    +"c3BlY2lhbD1jaGFyYWN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB"
                    +"AQDJ2t2JMeWPzM8uh5UBA3LofGFFgcdQKI/VGZ8pzgM6O8LmZ/H8IVVCtY/92oHp"
                    +"Szw/9kn7HbCUXshYv+NmzNnFFtnz95fT++79OWHWp90IxuY+yHcwy2fQYJNGSncU"
                    +"csMHtU7voIydTGwYnSTCwvwClw10UMuTsIY+8FAT7NDg9m3HWybCCERck06aYBR6"
                    +"htH0t4fx1yG2q6F6pArKgqR8+ddVyRVfw4Wa0uQCnbxNwaCFlmADogHF7+9BC3j3"
                    +"D1cK2y72nJEYQCi1dUHbTCMs/HhJo6xSL36EuZsbiq0Y4iRbaO2Nwx63TDNatQyi"
                    +"VJ8YP0Nu+auHfsgWOCJ+ZIDPAgMBAAGjgfowgfcwDAYDVR0TAQH/BAIwADAfBgNV"
                    +"HSMEGDAWgBTM2eQQAXey4PApuOauspuJcEKByTB4BgNVHREEcTBvhg9odHRwOi8v"
                    +"eC9BXCxCXFygLAYIKwYBBQUHCAegIBYedGVzdFwsd2l0aFxcc3BlY2lhbD1jaGFy"
                    +"YWN0ZXJzoC4GCCsGAQUFBwgDoCIwIAwedGVzdFwsd2l0aFxcc3BlY2lhbD1jaGFy"
                    +"YWN0ZXJzMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAdBgNVHQ4EFgQU"
                    +"tj6OychSszO4oMe9NViDMsY42mYwDgYDVR0PAQH/BAQDAgXgMA0GCSqGSIb3DQEB"
                    +"CwUAA4IBAQBMojz+Ckh1+HgIbNaNJZWw5PxfpgWwfRijz7UsU4ERKjb66llrp4n9"
                    +"b6PHwLHYbwvU4wXosKiywoNuX6Migs97kG9ocRMdwQT90TaM4zPpDRBlMGHn4sVI"
                    +"gUsqJs+jJO9uoRRfQnH3iu0244tQgipyVAef3YT0Aai6J7eQbMbQnPIulReagBA7"
                    +"otClag9bfSQrFqFStQkzrdMcT2RMQFXz/TNSUkHREBDM+gFoaar6+O5I0+pDrWya"
                    +"6Q5uP6jRra4WeOWt3ylEYl9R8AGm2gEnGPyEGV7CDeM3+QHa8dFnBcMpXfXkjT6X"
                    +"DAJPWF9uCqBxkH/fhnJTs64qn0zVB8zs").getBytes());
    
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

    private static byte[] aiaCert = Base64.decode(("MIIDYDCCAkigAwIBAgIIFlJveCmyW4owDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
            + "AwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw" + "HhcNMDgxMDIwMDkxOTM0WhcNMDkxMDIwMDkxOTM0WjA9MQwwCgYDVQQDDANhaWEx"
            + "DDAKBgNVBAoMA0ZvbzESMBAGA1UEBwwJU3RvY2tob2xtMQswCQYDVQQGEwJTRTCB" + "nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAlYyB3bj/Tmf1FGoPWXCJneWYd9Th"
            + "gPi4ET5pL0JNGwOsuH6cPngIIN33fn2JiiBnBkNm7AKHx8Qt9BH4VPJRs/GdsVGO" + "ECmpGmtY6WMYmxMC99KNiXSrRQjPGZeemMj6T1KyxhKljZr8Q92tmc9YA1VFMeqA"
            + "zNzjEGBDj/h2gBcCAwEAAaOB7TCB6jB5BggrBgEFBQcBAQRtMGswKgYIKwYBBQUH" + "MAKGHmh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9jYUlzc3VlcjA9BggrBgEFBQcwAYYx"
            + "aHR0cDovL2xvY2FsaG9zdDo4MDgwL2VqYmNhL3B1YmxpY3dlYi9zdGF0dXMvb2Nz" + "cDAdBgNVHQ4EFgQUF4YFO3HJordNZlJ/7T1L1KfqgTMwDAYDVR0TAQH/BAIwADAf"
            + "BgNVHSMEGDAWgBSSeB41+0/rZ+2/qiX7X4bvrVKjWDAPBgkrBgEFBQcwAQUEAgUA" + "MA4GA1UdDwEB/wQEAwIGwDANBgkqhkiG9w0BAQUFAAOCAQEAU1BHlD6TpSnmblU4"
            + "jhECKZfU7P5JBvZMkUQH54U+lubhM4yeymaF1NJylOusLKxZzEd6+iLXkvVCBKPT" + "3aVWUI5DO4D0RW9Lia6QFiRuI8d7a39f1663ODuwpjiccuehrmF3e+P7uCyjqhhT"
            + "g3uXQh2dXcv3DbvU2lfSVXRnuOz+K0ZUMAW96nsCeT41viM6w4x18zZeb+Px8RL9" + "swtcYdObNK0qmjZ4X+DcbdGRRrh8kr9GPLHYqtVLRM6z6hH3n54WJzojeIebKCsY"
            + "MoHGmOJkaIcFRXfneXrId1/k7b1QdOagGjvLkgw3pi/7k6vOJn+DrudNMFmsNpVY" + "fkrayw==").getBytes());

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

    private static byte[] krb5principalcert = Base64
            .decode(("MIIDIzCCAgugAwIBAgIIdSCEXyq32cIwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
                    + "AwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw"
                    + "HhcNMDgxMDIzMTEyMzAzWhcNMTgwODE2MTQ1MzA2WjAqMQ0wCwYDVQQDDARrcmIx"
                    + "MQwwCgYDVQQKDANGb28xCzAJBgNVBAYTAlNFMIGfMA0GCSqGSIb3DQEBAQUAA4GN"
                    + "ADCBiQKBgQCYkX8BcUXezxG8eKsQT0+lxjUZLeg7EQk0hdiKGsKxhS6BmLpeBOGs"
                    + "HwZgn70zhJj9XLtCQ/o8RJatL/lFtHpVX+RnRdckKDOooLUguxSiO5TK7HlQpsFG"
                    + "8AB7m/jCkIGarh5x6LSL5t1VAMyPh9DFBMXPuC5xAb5SGa6LRXoZ/QIDAQABo4HD"
                    + "MIHAMB0GA1UdDgQWBBTUIo6ZQUrVKoI5GPifVn3KbUGAljAMBgNVHRMBAf8EAjAA"
                    + "MB8GA1UdIwQYMBaAFJJ4HjX7T+tn7b+qJftfhu+tUqNYMA4GA1UdDwEB/wQEAwIF"
                    + "oDAnBgNVHSUEIDAeBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMEMDcGA1Ud"
                    + "EQQwMC6gLAYGKwYBBQICoCIwIKAHGwVQLkNPTaEVMBOgAwIBAKEMMAobA2ZvbxsD"
                    + "YmFyMA0GCSqGSIb3DQEBBQUAA4IBAQBgQpzPpCUDY6P0XePJSFJ2MGBhgMOVB4SL"
                    + "iHP9biEmqcqELWQcUL5Ylf+/JYxg1kBnk2ZtALgt0adi0ZiZPbM2F5Oq9ZxxB2nY"
                    + "Alat0RwZIY8wAR0DRNXiEs4TMu5LqzvD1U6+vaHYraePBLExo2oxG9TI7gQjj2X+"
                    + "KSxEzOf3+npWo/G7ooDvKpN+w3J//kF4vdM3SQtHQaBkIuCU05Jy16AhvIkLQzq5"
                    + "+a1UI5lIKun3C6NWCSZrE5fFuoax7D+Ofw1Bdxkhvk7DUlHVPdmxb/0hpx8aO64D" 
                    + "J626d8c1b25g9hSYslbo2geP2ohV40WW/R1ZjwX6Pd/ip5KuSSzv")
                    .getBytes());

    private static byte[] certPoliciesCert = Base64
            .decode(("MIIEvTCCA6WgAwIBAgIIL0ff1huXgEkwDQYJKoZIhvcNAQELBQAwNTEWMBQGA1UE"
                    + "AwwNTWFuYWdlbWVudCBDQTEOMAwGA1UECgwFUEstRE0xCzAJBgNVBAYTAkFFMB4X"
                    + "DTE2MDkwMzEyMTMwMFoXDTE2MDkwNTEyMTMwMFowMjEQMA4GA1UEAwwHcG9saWN5"
                    + "MTERMA8GA1UECgwIUHJpbWVLZXkxCzAJBgNVBAYTAkFFMIIBIjANBgkqhkiG9w0B"
                    + "AQEFAAOCAQ8AMIIBCgKCAQEA1JrKfYKf6srX68i26ib4SJ+YL3LZOm8kNThIesZI"
                    + "CjLVWInqSEtlT4fW691kHQlXmbPENecaq9N8JXhaYt4YP5gxSCijOjOBHGn0dHA4"
                    + "1/LotgqcdH81qeVbfeEygfU2zYnXIxKzJSwglyC4PRhA119ddFtKvelCvTtqmfel"
                    + "ZKvotT2nykl8oiioM8XG4p1o5NGEwQq3v5/vjulkM3N7oiyZkB4m0EqQh3+p+8lb"
                    + "NRZw887xWj91ZSwNKpi48ONfyR3thV3BcRXMcvKMlgThE02VhKvpVaioFLcoLI0B"
                    + "BWJnEWoRHA4wJOCXytyelPRwKv+q/3y/vEpSngf4bTJaJQIDAQABo4IB0jCCAc4w"
                    + "DAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBS7aJ9wWNYqtLjBOGb6w8+PwZhq2jCC"
                    + "AQMGA1UdIASB+zCB+DAoBgMpAQIwITAfBggrBgEFBQcCARYTaHR0cHM6Ly9lamJj"
                    + "YS5vcmcvMjAoBgMpAQMwITAfBggrBgEFBQcCARYTaHR0cHM6Ly9lamJjYS5vcmcv"
                    + "MzAFBgMpAQEwPQYDKQEEMDYwNAYIKwYBBQUHAgIwKB4mAE0AeQAgAFUAcwBlAHIA"
                    + "IABOAG8AdABpAGMAZQAgAFQAZQB4AHQwXAYDKQEFMFUwMAYIKwYBBQUHAgIwJB4i"
                    + "AEUASgBCAEMAQQAgAFUAcwBlAHIAIABOAG8AdABpAGMAZTAhBggrBgEFBQcCARYV"
                    + "aHR0cHM6Ly9lamJjYS5vcmcvQ1BTMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEF"
                    + "BQcDBDBIBggrBgEFBQcBAwQ8MDowEwYGBACORgEGMAkGBwQAjkYBBgMwIwYGBACO"
                    + "RgEFMBkwFxYRaHR0cHM6Ly9lamJjYS5vcmcTAmVuMB0GA1UdDgQWBBSMdaliHI83"
                    + "KXEkFC4I3rvvQabY8jAOBgNVHQ8BAf8EBAMCBeAwDQYJKoZIhvcNAQELBQADggEB"
                    + "AI7D2w7h+O4mbhaQZqshJdRhG48Ho5lpQjpnG1NalnwOFoKmWmSeie/ym+FPuA1d"
                    + "SQjcJal4CK3f0/T5EW+zU9sdRwKPg/zH88LUmkkZCosXZozscjMHNVkWhVtId2Nf"
                    + "212XQBujg3Bg7FI1YUBVLrANquE5nVuk3DvagArflkzIr+PO6u5yQa9LMkHr/9jL"
                    + "dIf17U2vh0X7iyRcFa5iz/J1aQIwdOg17SwBTuNXkpYPfKfy6V92eXiJPRT1jdqK"
                    + "tBXe5/Oz8tPpphzbGKRqu/iwKafgpK/zB3eYuCuJPlnT7oN0x8NVbC/nfVcuQqR3"
                    + "O+1Z36NfmAcO5PMgsY4CXT8=").getBytes());

    /**
     * Certificate with two subject alternative names:
     * <pre>
     *            SEQUENCE {
     *              OBJECT IDENTIFIER subjectAltName (2 5 29 17)
     *              OCTET STRING, encapsulates {
     *                SEQUENCE {
     *                  [0] {
     *                    OBJECT IDENTIFIER
     *                      universalPrincipalName (1 3 6 1 4 1 311 20 2 3)
     *                    [0] {
     *                      UTF8String 'upn1@example.com'
     *                      }
     *                    }
     *                  [0] {
     *                    OBJECT IDENTIFIER
     *                      permanentIdentifier (1 3 6 1 5 5 7 8 3)
     *                    [0] {
     *                      SEQUENCE {
     *                        UTF8String 'identifier 10003'
     *                        OBJECT IDENTIFIER '1 2 3 4 5 6'
     *                        }
     *                      }
     *                    }
     *                  }
     *                }
     *              }
     *            }
     * </pre>
     */
    private static byte[] permanentIdentifierCert = Base64
        .decode(("MIIDpjCCAo6gAwIBAgIIR+ghrp5GOgEwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
                + "AwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw"
                + "HhcNMTExMTI2MTkyMzU5WhcNMTMxMTI1MTkyMzU5WjAWMRQwEgYDVQQDDAtQZXJt"
                + "IHRlc3QgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZsjgEEXS09"
                + "98tJAiEJVj/Jjw0TUoyrzkvwwHF6Zny41aMLKSVYqynNOJurEapp+EdSGqu2ajYj"
                + "BQG0+RWjyhhBQuGQa1sv99y2sYHu5BL6Wep+eQJGuWR9rCMGaVrXkNgkCrghxj/A"
                + "U8ag5aDn6H5xgqK9OFQ6q5SFp6PJKFUZHppEdU+YSJGLrNMYRc4hegrH+tqnXLIY"
                + "BW4vrME0eaRlWNVlSVb3E6EwAwgYMads5EQrKuZosnIPqhGHWUoelK7LSg4PG6AY"
                + "JRSHI8EpM7a08Q4haxPbmX5FgTYhCnwsz3ZswB0pflMbNGso7hmqlpelzr2CKZla"
                + "DOFgKFrEiYcCAwEAAaOB1jCB0zAdBgNVHQ4EFgQU8oFZJcr7pYNHOvpTPNyZmDb/"
                + "ZOowDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBRpi5L9rci0UKa3/vvJGyr2nhdS"
                + "qDAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwME"
                + "MFQGA1UdEQRNMEugIAYKKwYBBAGCNxQCA6ASDBB1cG4xQGV4YW1wbGUuY29toCcG"
                + "CCsGAQUFBwgDoBswGQwQaWRlbnRpZmllciAxMDAwMwYFKgMEBQYwDQYJKoZIhvcN"
                + "AQEFBQADggEBAD6uWly6kndApp4L7cuDeRy3w2dLn0JhwETXPWX1yAOtzClPWZeb"
                + "SbZdDW5zChSd3DgoL5lUiDA+bBDUBIgstkg/4CnlaTeZbIXsxxHvLA0489PiDuEE"
                + "qpX4zJcJUDCMW5OSwUynm6kgkV6IZWn33gwxqBnHKHi2PuqpCSB4iC/XhGYTfC7H"
                + "Jcj5w+sqMgKWR2+Kem2BCufBEy6tlq75Unjm2IE0tvYv6myM5yYW9qxPyjXtrtLi"
                + "fOX1lzhtH1LUCzXPLPYTk6aJ08zsMZxbBe2cHXQibpcwvo3NyaTPlhsZL63e22Ru"
                + "KoAwF60lmxnqTzGP8w0HNHvm+Ybj1Qor3lQ=").getBytes());

    private static byte[] p10ReqWithAltNames = Base64.decode(("MIICtDCCAZwCAQAwNDELMAkGA1UEBhMCU0UxDDAKBgNVBAoTA1JQUzEXMBUGA1UE"
            + "AxMOMTAuMjUyLjI1NS4yMzcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB" + "AQC45+Dh1dO/qaZR2TLnWB44wmYXvBuZ5sGXotlLvuRR09DGlSyPrTG/OVg4xVZa"
            + "AzNMpWCyk1OAl4qJkmzrnQa/Tq6Hv6Y8QrZNSAJooL+kHmFSD9h8tyM9nBkpb90l" + "o+qbXeFmB3II0KJjGXiXZVSKwUsjYRSzf9hfVz4U7ZwwmH9vMFNwuOIsAR9O5CTr"
            + "8ofsshze9bxJpKY6/iyaEhQDoNl9jyxsZ1NuyNme3w1yoeGP5OXYcSVVY9cW4ze8" + "o5ZE4jTy1Q8U41OHiG3TevMvJ7l+/Ps+xyu3Qi68Lajeimemf118M0eqAY26Xiw2"
            + "wS8CCbj6UmUjcem3XOZhSfkZAgMBAAGgOzA5BgkqhkiG9w0BCQ4xLDAqMCgGA1Ud" + "EQQhMB+CF29ydDMta3J1Lm5ldC5wb2xpc2VuLnNlhwQK/P/tMA0GCSqGSIb3DQEB"
            + "BQUAA4IBAQCzAPsZdMqhPwCGpnq/Eywm5KQ4zYLuP8dQVdgvo4Wca2w4QxxjPlVI" + "X/yyXLhA1CpiKq4PtkpTBpJiByowj8g/7Q/pLY/EQcfYOrut7CMx1FzmwghZ2lUn"
            + "DDhFw2hD7TcmoAZpr4neXYR4HbaFpBc39nlqDa4XGi8J7d9AU4iaQE53LC3WzIq1" + "/3ZCXboQAoeLMoPCDvzAiXKDBApMMzrBwhgdsiOe5k1e6jlpURsbuhiKs+0FxtMp"
            + "snKPO0WbwXFyFTSWoKRH5rHrpD6lybn7c0uPkaQzrLoIRMld4osqeaImfZuJztZy" + "C0elzlLYWFbX6zHEqvsUAZy/8Khgyw5Q").getBytes());

    private static byte[] p10ReqWithAltNames2 = Base64.decode(("MIIBMzCB3gIBADAzMREwDwYDVQQDDAhzY2VwdGVzdDERMA8GA1UECgwIUHJpbWVL"
            + "ZXkxCzAJBgNVBAYTAlNFMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIMasNAoxA9N" + "6UknbjigXz5tJWWydLoVSQFUxcJM8cR4Kfb2bRLh3RDqCVyJQ0XITFUnmIJFU9Z8"
            + "1W+nw1Gx8b0CAwEAAaBGMBUGCSqGSIb3DQEJBzEIDAZmb28xMjMwLQYJKoZIhvcN" + "AQkOMSAwHjAcBgNVHREEFTATggtmb28uYmFyLmNvbYcECgAAATANBgkqhkiG9w0B"
            + "AQUFAANBADUO2tpAkxaeB/2zY9wsfcwE5hGvcuA0oJwXlcMq1wm32MJFV1G9JJQI" + "Exz4OC1eT1LH/6i5SU8Op3VOKVLpTTo=").getBytes());

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

    /** Cert with CDP with URI */
    /*
     * Cert with CDP with URI. <pre> Certificate: Data: Version: 3 (0x2) Serial Number: 52:32:6f:be:9d:3c:4d:d7 Signature Algorithm:
     * sha1WithRSAEncryption Issuer: CN=DemoSubCA11, O=Demo Organization 10, C=SE Validity Not Before: Apr 3 22:17:41 2010 GMT Not After : Apr 2
     * 22:17:41 2012 GMT Subject: CN=pdfsigner12-2testcrl-with-subca Subject Public Key Info: Public Key Algorithm: rsaEncryption RSA Public Key:
     * (1024 bit) Modulus (1024 bit): 00:de:99:da:80:ad:03:21:3c:18:cc:41:1f:ad:4a: fc:2d:69:21:3d:34:52:7c:a4:9c:33:df:a8:36:5a:
     * ee:bd:74:f6:0b:b1:93:79:3c:e7:66:a1:72:d4:1f: 08:b6:43:a3:0a:1a:94:8c:64:e4:10:71:32:be:4b: 00:08:a3:25:11:85:2a:d3:af:fa:dc:d4:ac:7a:48:
     * e8:d3:63:d0:06:4a:cf:ce:84:0e:a5:88:6e:1f:44: c1:9f:ad:89:1e:8b:d0:17:53:20:40:b5:e9:b3:7d: 16:74:e0:22:a7:43:44:99:6a:ba:5c:26:ed:f8:c7:
     * 8c:a5:14:a2:40:83:d6:52:75 Exponent: 65537 (0x10001) X509v3 extensions: X509v3 Subject Key Identifier:
     * 8F:23:26:05:9D:03:57:4F:66:08:F5:E3:34:D3:AA:70:76:9C:99:B2 X509v3 Basic Constraints: critical CA:FALSE X509v3 Authority Key Identifier:
     * keyid:90:FD:A7:F6:EC:98:47:56:4C:10:96:C2:AD:85:2F:50:EB:26:E9:34
     * 
     * X509v3 CRL Distribution Points:
     * URI:http://vmserver1:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN=DemoSubCA11,O=Demo%20Organization%2010,C=SE
     * 
     * X509v3 Key Usage: critical Digital Signature Signature Algorithm: sha1WithRSAEncryption 6e:f0:b9:26:b8:7d:eb:b2:ab:ec:e7:1b:a5:97:5c:5b:88:fe:
     * 8a:ec:bb:3d:7a:f5:00:4c:72:38:36:19:53:d4:47:21:30:4c: 62:7c:02:69:00:8c:ac:57:3c:f2:bf:38:57:13:0b:4b:7e:92:
     * 74:56:4c:1b:9c:04:9d:08:e8:8e:20:4d:bc:ec:bc:13:c7:55: 80:da:1a:01:9f:9f:be:96:11:d4:7c:64:f2:37:91:01:9f:c0:
     * 91:af:b6:8a:62:80:71:75:e6:34:f5:57:85:79:d8:7d:e3:71: 71:fa:7c:ca:c8:03:13:d5:0c:12:f5:f6:27:29:36:99:e4:ec: 8b:b1 </pre>
     */
    private static final String CERT_WITH_URI = "-----BEGIN CERTIFICATE-----\n" + "MIIC0zCCAjygAwIBAgIIUjJvvp08TdcwDQYJKoZIhvcNAQEFBQAwQjEUMBIGA1UE"
            + "AwwLRGVtb1N1YkNBMTExHTAbBgNVBAoMFERlbW8gT3JnYW5pemF0aW9uIDEwMQsw" + "CQYDVQQGEwJTRTAeFw0xMDA0MDMyMjE3NDFaFw0xMjA0MDIyMjE3NDFaMCoxKDAm"
            + "BgNVBAMMH3BkZnNpZ25lcjEyLTJ0ZXN0Y3JsLXdpdGgtc3ViY2EwgZ8wDQYJKoZI" + "hvcNAQEBBQADgY0AMIGJAoGBAN6Z2oCtAyE8GMxBH61K/C1pIT00UnyknDPfqDZa"
            + "7r109guxk3k852ahctQfCLZDowoalIxk5BBxMr5LAAijJRGFKtOv+tzUrHpI6NNj" + "0AZKz86EDqWIbh9EwZ+tiR6L0BdTIEC16bN9FnTgIqdDRJlqulwm7fjHjKUUokCD"
            + "1lJ1AgMBAAGjgekwgeYwHQYDVR0OBBYEFI8jJgWdA1dPZgj14zTTqnB2nJmyMAwG" + "A1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUkP2n9uyYR1ZMEJbCrYUvUOsm6TQwgYUG"
            + "A1UdHwR+MHwweqB4oHaGdGh0dHA6Ly92bXNlcnZlcjE6ODA4MC9lamJjYS9wdWJs" + "aWN3ZWIvd2ViZGlzdC9jZXJ0ZGlzdD9jbWQ9Y3JsJmlzc3Vlcj1DTj1EZW1vU3Vi"
            + "Q0ExMSxPPURlbW8lMjBPcmdhbml6YXRpb24lMjAxMCxDPVNFMA4GA1UdDwEB/wQE" + "AwIHgDANBgkqhkiG9w0BAQUFAAOBgQBu8LkmuH3rsqvs5xull1xbiP6K7Ls9evUA"
            + "THI4NhlT1EchMExifAJpAIysVzzyvzhXEwtLfpJ0VkwbnASdCOiOIE287LwTx1WA" + "2hoBn5++lhHUfGTyN5EBn8CRr7aKYoBxdeY09VeFedh943Fx+nzKyAMT1QwS9fYn"
            + "KTaZ5OyLsQ==" + "\n-----END CERTIFICATE-----";

    /** Cert with CDP without URI. */
    /*
     * Cert with CDP without URI. <pre> Certificate: Data: Version: 3 (0x2) Serial Number: 1042070824 (0x3e1cbd28) Signature Algorithm:
     * sha1WithRSAEncryption Issuer: C=US, O=Adobe Systems Incorporated, OU=Adobe Trust Services, CN=Adobe Root CA Validity Not Before: Jan 8 23:37:23
     * 2003 GMT Not After : Jan 9 00:07:23 2023 GMT Subject: C=US, O=Adobe Systems Incorporated, OU=Adobe Trust Services, CN=Adobe Root CA Subject
     * Public Key Info: Public Key Algorithm: rsaEncryption RSA Public Key: (2048 bit) Modulus (2048 bit):
     * 00:cc:4f:54:84:f7:a7:a2:e7:33:53:7f:3f:9c:12: 88:6b:2c:99:47:67:7e:0f:1e:b9:ad:14:88:f9:c3: 10:d8:1d:f0:f0:d5:9f:69:0a:2f:59:35:b0:cc:6c:
     * a9:4c:9c:15:a0:9f:ce:20:bf:a0:cf:54:e2:e0:20: 66:45:3f:39:86:38:7e:9c:c4:8e:07:22:c6:24:f6: 01:12:b0:35:df:55:ea:69:90:b0:db:85:37:1e:e2:
     * 4e:07:b2:42:a1:6a:13:69:a0:66:ea:80:91:11:59: 2a:9b:08:79:5a:20:44:2d:c9:bd:73:38:8b:3c:2f: e0:43:1b:5d:b3:0b:f0:af:35:1a:29:fe:ef:a6:92:
     * dd:81:4c:9d:3d:59:8e:ad:31:3c:40:7e:9b:91:36: 06:fc:e2:5c:8d:d1:8d:26:d5:5c:45:cf:af:65:3f: b1:aa:d2:62:96:f4:a8:38:ea:ba:60:42:f4:f4:1c:
     * 4a:35:15:ce:f8:4e:22:56:0f:95:18:c5:f8:96:9f: 9f:fb:b0:b7:78:25:e9:80:6b:bd:d6:0a:f0:c6:74: 94:9d:f3:0f:50:db:9a:77:ce:4b:70:83:23:8d:a0:
     * ca:78:20:44:5c:3c:54:64:f1:ea:a2:30:19:9f:ea: 4c:06:4d:06:78:4b:5e:92:df:22:d2:c9:67:b3:7a: d2:01 Exponent: 65537 (0x10001) X509v3 extensions:
     * Netscape Cert Type: SSL CA, S/MIME CA, Object Signing CA X509v3 CRL Distribution Points: DirName:/C=US/O=Adobe Systems Incorporated/OU=Adobe
     * Trust Services/CN=Adobe Root CA/CN=CRL1
     * 
     * X509v3 Private Key Usage Period: Not Before: Jan 8 23:37:23 2003 GMT, Not After: Jan 9 00:07:23 2023 GMT X509v3 Key Usage: Certificate Sign,
     * CRL Sign X509v3 Authority Key Identifier: keyid:82:B7:38:4A:93:AA:9B:10:EF:80:BB:D9:54:E2:F1:0F:FB:80:9C:DE
     * 
     * X509v3 Subject Key Identifier: 82:B7:38:4A:93:AA:9B:10:EF:80:BB:D9:54:E2:F1:0F:FB:80:9C:DE X509v3 Basic Constraints: CA:TRUE
     * 1.2.840.113533.7.65.0: 0...V6.0:4.0.... Signature Algorithm: sha1WithRSAEncryption 32:da:9f:43:75:c1:fa:6f:c9:6f:db:ab:1d:36:37:3e:bc:61:
     * 19:36:b7:02:3c:1d:23:59:98:6c:9e:ee:4d:85:e7:54:c8:20: 1f:a7:d4:bb:e2:bf:00:77:7d:24:6b:70:2f:5c:c1:3a:76:49:
     * b5:d3:e0:23:84:2a:71:6a:22:f3:c1:27:29:98:15:f6:35:90: e4:04:4c:c3:8d:bc:9f:61:1c:e7:fd:24:8c:d1:44:43:8c:16:
     * ba:9b:4d:a5:d4:35:2f:bc:11:ce:bd:f7:51:37:8d:9f:90:e4: 14:f1:18:3f:be:e9:59:12:35:f9:33:92:f3:9e:e0:d5:6b:9a:
     * 71:9b:99:4b:c8:71:c3:e1:b1:61:09:c4:e5:fa:91:f0:42:3a: 37:7d:34:f9:72:e8:cd:aa:62:1c:21:e9:d5:f4:82:10:e3:7b:
     * 05:b6:2d:68:56:0b:7e:7e:92:2c:6f:4d:72:82:0c:ed:56:74: b2:9d:b9:ab:2d:2b:1d:10:5f:db:27:75:70:8f:fd:1d:d7:e2:
     * 02:a0:79:e5:1c:e5:ff:af:64:40:51:2d:9e:9b:47:db:42:a5: 7c:1f:c2:a6:48:b0:d7:be:92:69:4d:a4:f6:29:57:c5:78:11:
     * 18:dc:87:51:ca:13:b2:62:9d:4f:2b:32:bd:31:a5:c1:fa:52: ab:05:88:c8 </pre>
     */
    private static final String CERT_WITHOUT_URI = "-----BEGIN CERTIFICATE-----\n"
            + "MIIEoTCCA4mgAwIBAgIEPhy9KDANBgkqhkiG9w0BAQUFADBpMQswCQYDVQQGEwJV" + "UzEjMCEGA1UEChMaQWRvYmUgU3lzdGVtcyBJbmNvcnBvcmF0ZWQxHTAbBgNVBAsT"
            + "FEFkb2JlIFRydXN0IFNlcnZpY2VzMRYwFAYDVQQDEw1BZG9iZSBSb290IENBMB4X" + "DTAzMDEwODIzMzcyM1oXDTIzMDEwOTAwMDcyM1owaTELMAkGA1UEBhMCVVMxIzAh"
            + "BgNVBAoTGkFkb2JlIFN5c3RlbXMgSW5jb3Jwb3JhdGVkMR0wGwYDVQQLExRBZG9i" + "ZSBUcnVzdCBTZXJ2aWNlczEWMBQGA1UEAxMNQWRvYmUgUm9vdCBDQTCCASIwDQYJ"
            + "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMxPVIT3p6LnM1N/P5wSiGssmUdnfg8e" + "ua0UiPnDENgd8PDVn2kKL1k1sMxsqUycFaCfziC/oM9U4uAgZkU/OYY4fpzEjgci"
            + "xiT2ARKwNd9V6mmQsNuFNx7iTgeyQqFqE2mgZuqAkRFZKpsIeVogRC3JvXM4izwv" + "4EMbXbML8K81Gin+76aS3YFMnT1Zjq0xPEB+m5E2BvziXI3RjSbVXEXPr2U/sarS"
            + "Ypb0qDjqumBC9PQcSjUVzvhOIlYPlRjF+Jafn/uwt3gl6YBrvdYK8MZ0lJ3zD1Db" + "mnfOS3CDI42gynggRFw8VGTx6qIwGZ/qTAZNBnhLXpLfItLJZ7N60gECAwEAAaOC"
            + "AU8wggFLMBEGCWCGSAGG+EIBAQQEAwIABzCBjgYDVR0fBIGGMIGDMIGAoH6gfKR6" + "MHgxCzAJBgNVBAYTAlVTMSMwIQYDVQQKExpBZG9iZSBTeXN0ZW1zIEluY29ycG9y"
            + "YXRlZDEdMBsGA1UECxMUQWRvYmUgVHJ1c3QgU2VydmljZXMxFjAUBgNVBAMTDUFk" + "b2JlIFJvb3QgQ0ExDTALBgNVBAMTBENSTDEwKwYDVR0QBCQwIoAPMjAwMzAxMDgy"
            + "MzM3MjNagQ8yMDIzMDEwOTAwMDcyM1owCwYDVR0PBAQDAgEGMB8GA1UdIwQYMBaA" + "FIK3OEqTqpsQ74C72VTi8Q/7gJzeMB0GA1UdDgQWBBSCtzhKk6qbEO+Au9lU4vEP"
            + "+4Cc3jAMBgNVHRMEBTADAQH/MB0GCSqGSIb2fQdBAAQQMA4bCFY2LjA6NC4wAwIE" + "kDANBgkqhkiG9w0BAQUFAAOCAQEAMtqfQ3XB+m/Jb9urHTY3PrxhGTa3AjwdI1mY"
            + "bJ7uTYXnVMggH6fUu+K/AHd9JGtwL1zBOnZJtdPgI4QqcWoi88EnKZgV9jWQ5ARM" + "w428n2Ec5/0kjNFEQ4wWuptNpdQ1L7wRzr33UTeNn5DkFPEYP77pWRI1+TOS857g"
            + "1WuacZuZS8hxw+GxYQnE5fqR8EI6N300+XLozapiHCHp1fSCEON7BbYtaFYLfn6S" + "LG9NcoIM7VZ0sp25qy0rHRBf2yd1cI/9HdfiAqB55Rzl/69kQFEtnptH20KlfB/C"
            + "pkiw176SaU2k9ilXxXgRGNyHUcoTsmKdTysyvTGlwfpSqwWIyA==" + "\n-----END CERTIFICATE-----";

    private static byte[] testcrl = Base64.decode(("MIHGMHICAQEwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEVEVTVBcNMTEwMTMx"
    		+"MTMzOTE3WhcNMTEwMTMxMTMzOTE3WqAvMC0wHwYDVR0jBBgwFoAUt39s38+I8fP0"
    		+"diUs8Y8TYtCar8gwCgYDVR0UBAMCAQEwDQYJKoZIhvcNAQELBQADQQBcr4CF0sy3"
    		+"5sVvEafzh67itIasqcv/PwUT6DwQxoiX85h53cFtvXQxi/2Xqn+PaNBOqWShByX7"
    		+"TQlMX0Bmoz9/").getBytes());

    private static byte[] testdeltacrl = Base64.decode(("MIHWMIGBAgEBMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBFRFU1QXDTExMDEz"
    		+"MTEzNDcxOFoXDTExMDEzMTEzNDcxOFqgPjA8MB8GA1UdIwQYMBaAFJ5BHYGqJr3K"
    		+"j9IMQxmMP6ad8gDdMAoGA1UdFAQDAgEDMA0GA1UdGwEB/wQDAgECMA0GCSqGSIb3"
    		+"DQEBCwUAA0EAP8CIPLll5m/wmhcLL5SXlb+aYrPGsUlBFNBKYKO0iV1QjBHeDMp5"
    		+"z70nU3g2tIfiEX4IKNFyzFvn5m6e8m0JQQ==").getBytes());

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

    /**
     * DOCUMENT ME!
     * 
     * @throws Exception
     *             DOCUMENT ME!
     */
    @Test
    public void test01GetPartFromDN() throws Exception {
        log.trace(">test01GetPartFromDN()");

        // We try to examine the general case and some special cases, which we
        // want to be able to handle
        String dn0 = "C=SE, O=AnaTom, CN=foo";
        assertEquals(CertTools.getPartFromDN(dn0, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn0, "O"), "AnaTom");
        assertEquals(CertTools.getPartFromDN(dn0, "C"), "SE");
        assertEquals(CertTools.getPartFromDN(dn0, "cn"), "foo");
        assertEquals(CertTools.getPartFromDN(dn0, "o"), "AnaTom");
        assertEquals(CertTools.getPartFromDN(dn0, "c"), "SE");

        String dn1 = "c=SE, o=AnaTom, cn=foo";
        assertEquals(CertTools.getPartFromDN(dn1, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn1, "O"), "AnaTom");
        assertEquals(CertTools.getPartFromDN(dn1, "C"), "SE");
        assertEquals(CertTools.getPartFromDN(dn1, "cn"), "foo");
        assertEquals(CertTools.getPartFromDN(dn1, "o"), "AnaTom");
        assertEquals(CertTools.getPartFromDN(dn1, "c"), "SE");

        String dn2 = "C=SE, O=AnaTom, CN=cn";
        assertEquals(CertTools.getPartFromDN(dn2, "CN"), "cn");

        String dn3 = "C=SE, O=AnaTom, CN=CN";
        assertEquals(CertTools.getPartFromDN(dn3, "CN"), "CN");

        String dn4 = "C=CN, O=AnaTom, CN=foo";
        assertEquals(CertTools.getPartFromDN(dn4, "CN"), "foo");

        String dn5 = "C=cn, O=AnaTom, CN=foo";
        assertEquals(CertTools.getPartFromDN(dn5, "CN"), "foo");

        String dn6 = "CN=foo, O=PrimeKey, C=SE";
        assertEquals(CertTools.getPartFromDN(dn6, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn6, "O"), "PrimeKey");
        assertEquals(CertTools.getPartFromDN(dn6, "C"), "SE");

        String dn7 = "CN=foo, O=PrimeKey, C=cn";
        assertEquals(CertTools.getPartFromDN(dn7, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn7, "C"), "cn");

        String dn8 = "CN=foo, O=PrimeKey, C=CN";
        assertEquals(CertTools.getPartFromDN(dn8, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn8, "C"), "CN");

        String dn9 = "CN=foo, O=CN, C=CN";
        assertEquals(CertTools.getPartFromDN(dn9, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn9, "O"), "CN");

        String dn10 = "CN=foo, CN=bar,O=CN, C=CN";
        assertEquals(CertTools.getPartFromDN(dn10, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn10, "O"), "CN");

        String dn11 = "CN=foo,CN=bar, O=CN, C=CN";
        assertEquals(CertTools.getPartFromDN(dn11, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn11, "O"), "CN");

        String dn12 = "CN=\"foo, OU=bar\", O=baz\\\\\\, quux,C=C";
        assertEquals("Extraction of CN from: "+dn12, "foo, OU=bar", CertTools.getPartFromDN(dn12, "CN"));
        assertEquals("Extraction of O from: "+dn12, "baz\\, quux", CertTools.getPartFromDN(dn12, "O"));
        assertNull(CertTools.getPartFromDN(dn12, "OU"));

        String dn13 = "C=SE, O=PrimeKey, EmailAddress=foo@primekey.se";
        ArrayList<String> emails = CertTools.getEmailFromDN(dn13);
        assertEquals((String) emails.get(0), "foo@primekey.se");

        String dn14 = "C=SE, E=foo@primekey.se, O=PrimeKey";
        emails = CertTools.getEmailFromDN(dn14);
        assertEquals((String) emails.get(0), "foo@primekey.se");

        String dn15 = "C=SE, E=foo@primekey.se, O=PrimeKey, EmailAddress=bar@primekey.se";
        emails = CertTools.getEmailFromDN(dn15);
        assertEquals((String) emails.get(0), "bar@primekey.se");

        log.trace("<test01GetPartFromDN()");
    }

    @Test
    public void test02StringToBCDNString() throws Exception {
        log.trace(">test02StringToBCDNString()");

        // We try to examine the general case and som special cases, which we
        // want to be able to handle
        String dn1 = "C=SE, O=AnaTom, CN=foo";
        assertEquals(CertTools.stringToBCDNString(dn1), "CN=foo,O=AnaTom,C=SE");

        String dn2 = "C=SE, O=AnaTom, CN=cn";
        assertEquals(CertTools.stringToBCDNString(dn2), "CN=cn,O=AnaTom,C=SE");

        String dn3 = "CN=foo, O=PrimeKey, C=SE";
        assertEquals(CertTools.stringToBCDNString(dn3), "CN=foo,O=PrimeKey,C=SE");

        String dn4 = "cn=foo, o=PrimeKey, c=SE";
        assertEquals(CertTools.stringToBCDNString(dn4), "CN=foo,O=PrimeKey,C=SE");

        String dn5 = "cn=foo,o=PrimeKey,c=SE";
        assertEquals(CertTools.stringToBCDNString(dn5), "CN=foo,O=PrimeKey,C=SE");

        String dn6 = "C=SE, O=AnaTom, CN=CN";
        assertEquals(CertTools.stringToBCDNString(dn6), "CN=CN,O=AnaTom,C=SE");

        String dn7 = "C=CN, O=AnaTom, CN=foo";
        assertEquals(CertTools.stringToBCDNString(dn7), "CN=foo,O=AnaTom,C=CN");

        String dn8 = "C=cn, O=AnaTom, CN=foo";
        assertEquals(CertTools.stringToBCDNString(dn8), "CN=foo,O=AnaTom,C=cn");

        String dn9 = "CN=foo, O=PrimeKey, C=CN";
        assertEquals(CertTools.stringToBCDNString(dn9), "CN=foo,O=PrimeKey,C=CN");

        String dn10 = "CN=foo, O=PrimeKey, C=cn";
        assertEquals(CertTools.stringToBCDNString(dn10), "CN=foo,O=PrimeKey,C=cn");

        String dn11 = "CN=foo, O=CN, C=CN";
        assertEquals(CertTools.stringToBCDNString(dn11), "CN=foo,O=CN,C=CN");

        String dn12 = "O=PrimeKey,C=SE,CN=CN";
        assertEquals(CertTools.stringToBCDNString(dn12), "CN=CN,O=PrimeKey,C=SE");

        String dn13 = "O=PrimeKey,C=SE,CN=CN, OU=FooOU";
        assertEquals(CertTools.stringToBCDNString(dn13), "CN=CN,OU=FooOU,O=PrimeKey,C=SE");

        String dn14 = "O=PrimeKey,C=CN,CN=CN, OU=FooOU";
        assertEquals(CertTools.stringToBCDNString(dn14), "CN=CN,OU=FooOU,O=PrimeKey,C=CN");

        String dn15 = "O=PrimeKey,C=CN,CN=cn, OU=FooOU";
        assertEquals(CertTools.stringToBCDNString(dn15), "CN=cn,OU=FooOU,O=PrimeKey,C=CN");

        String dn16 = "CN=foo, CN=bar,O=CN, C=CN";
        assertEquals(CertTools.stringToBCDNString(dn16), "CN=foo,CN=bar,O=CN,C=CN");

        String dn17 = "CN=foo,CN=bar, O=CN, O=C, C=CN";
        assertEquals(CertTools.stringToBCDNString(dn17), "CN=foo,CN=bar,O=CN,O=C,C=CN");

        String dn18 = "cn=jean,cn=EJBCA,dc=home,dc=jean";
        assertEquals(CertTools.stringToBCDNString(dn18), "CN=jean,CN=EJBCA,DC=home,DC=jean");

        String dn19 = "cn=bar, cn=foo,o=oo, O=EJBCA,DC=DC2, dc=dc1, C=SE";
        assertEquals(CertTools.stringToBCDNString(dn19), "CN=bar,CN=foo,O=oo,O=EJBCA,DC=DC2,DC=dc1,C=SE");

        String dn20 = " CN=\"foo, OU=bar\",  O=baz\\\\\\, quux,C=SE ";
        // BC always escapes with backslash, it doesn't use quotes.
        assertEquals("Conversion of: "+dn20, "CN=foo\\, OU\\=bar,O=baz\\\\\\, quux,C=SE", CertTools.stringToBCDNString(dn20));

        String dn21 = "C=SE,O=Foo\\, Inc, OU=Foo\\, Dep, CN=Foo\\'";
        String bcdn21 = CertTools.stringToBCDNString(dn21);
        assertEquals(bcdn21, "CN=Foo\',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE");
        // it is allowed to escape ,
        assertEquals(StringTools.strip(bcdn21), "CN=Foo',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE");

        String dn22 = "C=SE,O=Foo\\, Inc, OU=Foo, Dep, CN=Foo'";
        String bcdn22 = CertTools.stringToBCDNString(dn22);
        assertEquals(bcdn22, "CN=Foo',OU=Foo,O=Foo\\, Inc,C=SE");
        assertEquals(StringTools.strip(bcdn22), "CN=Foo',OU=Foo,O=Foo\\, Inc,C=SE");

        String dn23 = "C=SE,O=Foo, OU=FooOU, CN=Foo, DN=qualf";
        String bcdn23 = CertTools.stringToBCDNString(dn23);
        assertEquals(bcdn23, "DN=qualf,CN=Foo,OU=FooOU,O=Foo,C=SE");
        assertEquals(StringTools.strip(bcdn23), "DN=qualf,CN=Foo,OU=FooOU,O=Foo,C=SE");

        String dn24 = "telephonenumber=08555-666,businesscategory=Surf boards,postaladdress=Stockholm,postalcode=11122,CN=foo,CN=bar, O=CN, O=C, C=CN";
        assertEquals(CertTools.stringToBCDNString(dn24),
                "TelephoneNumber=08555-666,PostalAddress=Stockholm,BusinessCategory=Surf boards,PostalCode=11122,CN=foo,CN=bar,O=CN,O=C,C=CN");

        // This isn't a legal SubjectDN. Since legacy BC did not support multivalues, we assume that the user meant \+.
        String dn25 = "CN=user+name, C=CN";
        assertEquals("CN=user\\+name,C=CN", CertTools.stringToBCDNString(dn25));

        String dn26 = "CN=user\\+name, C=CN";
        assertEquals("CN=user\\+name,C=CN", CertTools.stringToBCDNString(dn26));
        
        String dn27 = "CN=test123456, O=\\\"foo+b\\+ar\\, C=SE\\\"";
        assertEquals("CN=test123456,O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"", CertTools.stringToBCDNString(dn27));
        String dn27_1 = "CN=test123456, O=\\\"foo+b\\+ar\\, C=SE\\";
        assertEquals("CN=test123456,O=\\\"foo\\+b\\+ar\\, C\\=SE\\\\", CertTools.stringToBCDNString(dn27_1));

        String dn28 = "jurisdictionCountry=SE,jurisdictionState=Stockholm,SURNAME=Json,=fff,CN=oid,jurisdictionLocality=Solna,SN=12345,unstructuredname=foo.bar.com,unstructuredaddress=1.2.3.4,NAME=name,C=se";
        assertEquals("JurisdictionCountry=SE,JurisdictionState=Stockholm,JurisdictionLocality=Solna,unstructuredAddress=1.2.3.4,unstructuredName=foo.bar.com,CN=oid,Name=name,SN=12345,SURNAME=Json,C=se",
                CertTools.stringToBCDNString(dn28));
        
        String dn29 = "CN=hexencoded SN,SN=1234";
        assertEquals("CN=hexencoded SN,SN=1234", CertTools.stringToBCDNString(dn29));
        String dn30 = "CN=hexencoded SN,SN=\\#CNJB";
        assertEquals("CN=hexencoded SN,SN=\\#CNJB", CertTools.stringToBCDNString(dn30));
        DERUTF8String str = new DERUTF8String("foo");
        String hex = new String(Hex.encode(str.getEncoded()));
        String dn31 = "CN=hexencoded SN,SN=#"+hex;
        assertEquals("CN=hexencoded SN,SN=foo", CertTools.stringToBCDNString(dn31));

        String dn32a = "CN=eidas,O=MyOrg,ORGANIZATIONIDENTIFIER=12345,C=SE";
        assertEquals("CN=eidas,organizationIdentifier=12345,O=MyOrg,C=SE", CertTools.stringToBCDNString(dn32a));
        String dn32b = "CN=test,O=MyOrg,DESCRIPTION=Test Description,C=SE";
        assertEquals("description=Test Description,CN=test,O=MyOrg,C=SE", CertTools.stringToBCDNString(dn32b));

        // Test spaces in the RDN value
        String dn33a = "CN=cn,O= the org ,C=SE";
        assertEquals("CN=cn,O=the org,C=SE", CertTools.stringToBCDNString(dn33a));
        String dn33b = "CN=cn,O= the org ";
        assertEquals("CN=cn,O=the org", CertTools.stringToBCDNString(dn33b));
        // The following has changed from earlier EJBCA versions there the trailing escaped space would have been kept. (Perhaps through a change in BC's X500NameBuilder.)
        // Document the current behavior with this test to catch future changes.
        String dn34a = "CN=cn,O=\\ the org\\ ,C=SE";
        assertEquals("CN=cn,O=\\ the org\\\\,C=SE", CertTools.stringToBCDNString(dn34a));
        String dn34b = "CN=cn,O=\\ the org\\ ";
        assertEquals("CN=cn,O=\\ the org\\\\", CertTools.stringToBCDNString(dn34b));
        // Same string as tested in EjbcaWSTest.test51CertificateRequestWithNoForbiddenChars
        String dn35 = "CN=Foo,O=|\n|\r|;|A|!|`|?|$|~|, C=SE";
        assertEquals("CN=Foo,O=|\n|\r|\\;|A|!|`|?|$|~|,C=SE", CertTools.stringToBCDNString(dn35));
    }

    @Test
    public void test03AltNames() throws Exception {
        log.trace(">test03AltNames()");

        // We try to examine the general case and som special cases, which we
        // want to be able to handle
        String alt1 = "rfc822Name=ejbca@primekey.se, dNSName=www.primekey.se, uri=http://www.primekey.se/ejbca,registeredID=1.1.1.3,xmppAddr=tomas@xmpp.domain.com,srvName=_Service.Name,fascN=0419d23210d8210c2c1a843085a16858300842108608823210c3e1";
        assertEquals(CertTools.getPartFromDN(alt1, CertTools.EMAIL), "ejbca@primekey.se");
        assertNull(CertTools.getPartFromDN(alt1, CertTools.EMAIL1));
        assertNull(CertTools.getPartFromDN(alt1, CertTools.EMAIL2));
        assertEquals(CertTools.getPartFromDN(alt1, CertTools.DNS), "www.primekey.se");
        assertNull(CertTools.getPartFromDN(alt1, CertTools.URI));
        assertEquals(CertTools.getPartFromDN(alt1, CertTools.URI1), "http://www.primekey.se/ejbca");
        assertEquals(CertTools.getPartFromDN(alt1, CertTools.REGISTEREDID), "1.1.1.3");
        assertEquals(CertTools.getPartFromDN(alt1, CertTools.XMPPADDR), "tomas@xmpp.domain.com");
        assertEquals(CertTools.getPartFromDN(alt1, CertTools.SRVNAME), "_Service.Name");
        assertEquals(CertTools.getPartFromDN(alt1, CertTools.FASCN), "0419d23210d8210c2c1a843085a16858300842108608823210c3e1");

        String alt2 = "email=ejbca@primekey.se, dNSName=www.primekey.se, uniformResourceIdentifier=http://www.primekey.se/ejbca";
        assertEquals(CertTools.getPartFromDN(alt2, CertTools.EMAIL1), "ejbca@primekey.se");
        assertEquals(CertTools.getPartFromDN(alt2, CertTools.URI), "http://www.primekey.se/ejbca");

        String alt3 = "EmailAddress=ejbca@primekey.se, dNSName=www.primekey.se, uniformResourceIdentifier=http://www.primekey.se/ejbca";
        assertEquals(CertTools.getPartFromDN(alt3, CertTools.EMAIL2), "ejbca@primekey.se");

        Certificate cert = CertTools.getCertfromByteArray(guidcert, Certificate.class);
        String upn = CertTools.getUPNAltName(cert);
        assertEquals(upn, "guid@foo.com");
        String guid = CertTools.getGuidAltName(cert);
        assertEquals("1234567890abcdef", guid);
        String altName = CertTools.getSubjectAlternativeName(cert);
        // The returned string does not always have the same order so we can't compare strings directly
        assertTrue(altName.contains("guid=1234567890abcdef"));
        assertTrue(altName.contains("rfc822name=guid@foo.com"));
        assertTrue(altName.contains("upn=guid@foo.com"));
        assertTrue(altName.contains("dNSName=guid.foo.com"));
        assertTrue(altName.contains("iPAddress=10.12.13.14"));
        assertTrue(altName.contains("uniformResourceIdentifier=http://guid.foo.com/"));
        assertFalse(altName.contains("foobar"));
        GeneralNames gns = CertTools.getGeneralNamesFromAltName(altName);
        assertNotNull(gns);
        
        // Test cert containing permanentIdentifier
        cert = CertTools.getCertfromByteArray(permanentIdentifierCert, Certificate.class);
        upn = CertTools.getUPNAltName(cert);
        assertEquals("upn1@example.com", upn);
        String permanentIdentifier = CertTools.getPermanentIdentifierAltName(cert);
        assertEquals("identifier 10003/1.2.3.4.5.6", permanentIdentifier);

        String customAlt = "rfc822Name=foo@bar.com";
        ArrayList<String> oids = CertTools.getCustomOids(customAlt);
        assertEquals(0, oids.size());
        customAlt = "rfc822Name=foo@bar.com, 1.1.1.1.2=foobar, 1.2.2.2.2=barfoo";
        oids = CertTools.getCustomOids(customAlt);
        assertEquals(2, oids.size());
        String oid1 = (String) oids.get(0);
        assertEquals("1.1.1.1.2", oid1);
        String oid2 = (String) oids.get(1);
        assertEquals("1.2.2.2.2", oid2);
        String val1 = CertTools.getPartFromDN(customAlt, oid1);
        assertEquals("foobar", val1);
        String val2 = CertTools.getPartFromDN(customAlt, oid2);
        assertEquals("barfoo", val2);

        customAlt = "rfc822Name=foo@bar.com, 1.1.1.1.2=foobar, 1.1.1.1.2=barfoo";
        oids = CertTools.getCustomOids(customAlt);
        assertEquals(1, oids.size());
        oid1 = (String) oids.get(0);
        assertEquals("1.1.1.1.2", oid1);
        List<String> list = CertTools.getPartsFromDN(customAlt, oid1);
        assertEquals(2, list.size());
        val1 = (String) list.get(0);
        assertEquals("foobar", val1);
        val2 = (String) list.get(1);
        assertEquals("barfoo", val2);

        log.trace("<test03AltNames()");
    }

    @Test
    public void test04DNComponents() throws Exception {
        log.trace(">test04DNComponents()");

        // We try to examine the general case and som special cases, which we
        // want to be able to handle
        String dn1 = "CN=CommonName, O=Org, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName, GivenName=GivenName, Initials=Initials, C=SE";
        String bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,OU=OrgUnit,O=Org,C=SE", bcdn1);

        dn1 = "CN=CommonName, O=Org, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName, GivenName=GivenName,"
                +" Initials=Initials, C=SE, 1.1.1.1=1111Oid, 2.2.2.2=2222Oid";
        bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,OU=OrgUnit,"
                +"O=Org,C=SE,2.2.2.2=2222Oid,1.1.1.1=1111Oid", bcdn1);

        dn1 = "CN=CommonName, 3.3.3.3=3333Oid,O=Org, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName,"+
                " GivenName=GivenName, Initials=Initials, C=SE, 1.1.1.1=1111Oid, 2.2.2.2=2222Oid";
        bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        // 3.3.3.3 is not a valid OID so it should be silently dropped
        assertEquals("CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,"
                        +"OU=OrgUnit,O=Org,C=SE,2.2.2.2=2222Oid,1.1.1.1=1111Oid", bcdn1);

        dn1 = "CN=CommonName, 2.3.3.3=3333Oid,O=Org, K=KKK, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName,"
                +" GivenName=GivenName, Initials=Initials, C=SE, 1.1.1.1=1111Oid, 2.2.2.2=2222Oid";
        bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals(
                bcdn1,
                "CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,OU=OrgUnit,O=Org,C=SE,2.2.2.2=2222Oid,1.1.1.1=1111Oid,2.3.3.3=3333Oid");

        log.trace("<test04DNComponents()");
    }

    /**
     * Tests string coding/decoding international (swedish characters)
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void test05IntlChars() throws Exception {
        log.trace(">test05IntlChars()");
        // We try to examine the general case and som special cases, which we
        // want to be able to handle
        String dn1 = "CN=Tomas?????????, O=?????????-Org, OU=??????-Unit, C=SE";
        String bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=Tomas?????????,OU=??????-Unit,O=?????????-Org,C=SE", bcdn1);
        log.trace("<test05IntlChars()");
    }

    /**
     * Tests some of the other methods of CertTools
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void test06CertOps() throws Exception {
        log.trace(">test06CertOps()");
        Certificate cert = CertTools.getCertfromByteArray(testcert, Certificate.class);
        assertFalse(CertTools.isCA(cert));
        Certificate gcert = CertTools.getCertfromByteArray(guidcert, Certificate.class);
        assertEquals("Wrong issuerDN", CertTools.getIssuerDN(cert), CertTools.stringToBCDNString("CN=TestCA,O=AnaTom,C=SE"));
        assertEquals("Wrong subjectDN", CertTools.getSubjectDN(cert), CertTools.stringToBCDNString("CN=p12test,O=PrimeTest,C=SE"));
        assertEquals("Wrong subject key id", new String(Hex.encode(CertTools.getSubjectKeyId(cert))),
                "E74F5690F48D147783847CD26448E8094ABB08A0".toLowerCase());
        assertEquals("Wrong authority key id", new String(Hex.encode(CertTools.getAuthorityKeyId(cert))),
                "637BF476A854248EA574A57744A6F45E0F579251".toLowerCase());
        assertEquals("Wrong upn alt name", "foo@foo", CertTools.getUPNAltName(cert));
        assertEquals("Wrong guid alt name", "1234567890abcdef", CertTools.getGuidAltName(gcert));
        assertEquals("Wrong certificate policy", "1.1.1.1.1.1", CertTools.getCertificatePolicyId(cert, 0));
        assertNull("Not null policy", CertTools.getCertificatePolicyId(cert, 1));
        // log.debug(cert);
        // FileOutputStream fos = new FileOutputStream("foo.cert");
        // fos.write(cert.getEncoded());
        // fos.close();
        log.trace("<test06CertOps()");
    }

    /**
     * Tests the handling of DC components
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void test07TestDC() throws Exception {
        log.trace(">test07TestDC()");
        // We try to examine the that we handle modern dc components for ldap
        // correctly
        String dn1 = "dc=bigcorp,dc=com,dc=se,ou=users,cn=Mike Jackson";
        String bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        // assertEquals("CN=Mike Jackson,OU=users,DC=se,DC=bigcorp,DC=com",
        // bcdn1);
        String dn2 = "cn=Mike Jackson,ou=users,dc=se,dc=bigcorp,dc=com";
        String bcdn2 = CertTools.stringToBCDNString(dn2);
        log.debug("dn2: " + dn2);
        log.debug("bcdn2: " + bcdn2);
        assertEquals("CN=Mike Jackson,OU=users,DC=se,DC=bigcorp,DC=com", bcdn2);
        log.trace("<test07TestDC()");
    }

    /**
     * Tests the handling of unstructuredName/Address
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void test08TestUnstructured() throws Exception {
        log.trace(">test08TestUnstructured()");
        // We try to examine the that we handle modern dc components for ldap
        // correctly
        String dn1 = "C=SE,O=PrimeKey,unstructuredName=10.1.1.2,unstructuredAddress=foo.bar.se,cn=test";
        String bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("unstructuredAddress=foo.bar.se,unstructuredName=10.1.1.2,CN=test,O=PrimeKey,C=SE", bcdn1);
        log.trace("<test08TestUnstructured()");
    }

    /**
     * Tests the reversing of a DN
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void test09TestReverseDN() throws Exception {
        log.trace(">test09TestReverse()");
        // We try to examine the that we handle modern dc components for ldap
        // correctly
        String dn1 = "dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G";
        String dn2 = "cn=Tomas G,ou=users,ou=orgunit,dc=se,dc=bigcorp,dc=com";
        assertTrue(CertTools.isDNReversed(dn1));
        assertTrue(!CertTools.isDNReversed(dn2));
        assertTrue(CertTools.isDNReversed("C=SE,CN=Foo"));
        assertTrue(!CertTools.isDNReversed("CN=Foo,O=FooO"));
        // Test some bad input
        assertTrue(!CertTools.isDNReversed("asdasd,asdassd"));
        String revdn1 = CertTools.reverseDN(dn1);
        log.debug("dn1: " + dn1);
        log.debug("revdn1: " + revdn1);
        assertEquals(dn2, revdn1);

        String dn3 = "cn=toto,cn=titi,dc=domain,dc=tld";
        String revdn3 = CertTools.reverseDN(dn3);
        assertEquals("dc=tld,dc=domain,cn=titi,cn=toto", revdn3);
        
        X500Name dn4 = CertTools.stringToBcX500Name(dn3, new CeSecoreNameStyle(), true);
        assertEquals("CN=toto,CN=titi,DC=domain,DC=tld", dn4.toString());
        X500Name dn5 = CertTools.stringToBcX500Name(dn3, new CeSecoreNameStyle(), false);
        assertEquals("DC=tld,DC=domain,CN=titi,CN=toto", dn5.toString());
        assertEquals("CN=toto,CN=titi,DC=domain,DC=tld", CertTools.stringToBCDNString(dn3));

        String dn6 = "dc=tld,dc=domain,cn=titi,cn=toto";
        String revdn6 = CertTools.reverseDN(dn6);
        assertEquals("cn=toto,cn=titi,dc=domain,dc=tld", revdn6);
        assertEquals("CN=toto,CN=titi,DC=domain,DC=tld", CertTools.stringToBCDNString(dn3));

        X500Name dn7 = CertTools.stringToBcX500Name(dn6, new CeSecoreNameStyle(), true);
        assertEquals("CN=toto,CN=titi,DC=domain,DC=tld", dn7.toString());
        X500Name revdn7 = CertTools.stringToBcX500Name(dn6, new CeSecoreNameStyle(), false);
        assertEquals("DC=tld,DC=domain,CN=titi,CN=toto", revdn7.toString());

        // Test the test strings from ECA-1699, to prove that we fixed this issue
        String dn8 = "dc=org,dc=foo,o=FOO,cn=FOO Root CA";
        String dn9 = "cn=FOO Root CA,o=FOO,dc=foo,dc=org";
        String revdn8 = CertTools.reverseDN(dn8);
        assertEquals("cn=FOO Root CA,o=FOO,dc=foo,dc=org", revdn8);
        String revdn9 = CertTools.reverseDN(dn9);
        assertEquals("dc=org,dc=foo,o=FOO,cn=FOO Root CA", revdn9);
        X500Name xdn8ldap = CertTools.stringToBcX500Name(dn8, new CeSecoreNameStyle(), true);
        X500Name xdn8x500 = CertTools.stringToBcX500Name(dn8, new CeSecoreNameStyle(), false);
        assertEquals("CN=FOO Root CA,O=FOO,DC=foo,DC=org", xdn8ldap.toString());
        assertEquals("DC=org,DC=foo,O=FOO,CN=FOO Root CA", xdn8x500.toString());
        X500Name xdn9ldap = CertTools.stringToBcX500Name(dn9, new CeSecoreNameStyle(), true);
        X500Name xdn9x500 = CertTools.stringToBcX500Name(dn9, new CeSecoreNameStyle(), false);
        assertEquals("CN=FOO Root CA,O=FOO,DC=foo,DC=org", xdn9ldap.toString());
        assertEquals("DC=org,DC=foo,O=FOO,CN=FOO Root CA", xdn9x500.toString());
        assertEquals("CN=FOO Root CA,O=FOO,DC=foo,DC=org", CertTools.stringToBCDNString(dn8));
        assertEquals("CN=FOO Root CA,O=FOO,DC=foo,DC=org", CertTools.stringToBCDNString(dn9));

        // Test reversing DNs with multiple OU
        String dn10 = "CN=something,OU=A,OU=B,O=someO,C=SE";
        X500Name x500dn10 = CertTools.stringToBcX500Name(dn10, new CeSecoreNameStyle(), true);
        assertEquals("CN=something,OU=A,OU=B,O=someO,C=SE", x500dn10.toString());
        assertEquals("CN=something,OU=A,OU=B,O=someO,C=SE", CertTools.stringToBCDNString(dn10));

        // When we order forwards (LdapOrder) from the beginning, and request !LdapOrder, everything should be reversed
        X500Name ldapdn11 = CertTools.stringToBcX500Name(dn10, new CeSecoreNameStyle(), false);
        assertEquals("C=SE,O=someO,OU=B,OU=A,CN=something", ldapdn11.toString());

        // When we order backwards (X.509, !LdapOrder) from the beginning, we should not reorder anything
        String dn11 = "C=SE,O=someO,OU=B,OU=A,CN=something";
        X500Name x500dn11 = CertTools.stringToBcX500Name(dn11, new CeSecoreNameStyle(), false);
        assertEquals("C=SE,O=someO,OU=B,OU=A,CN=something", x500dn11.toString());
        assertEquals("CN=something,OU=A,OU=B,O=someO,C=SE", CertTools.stringToBCDNString(dn11));

        // Test some bad input
        assertEquals("", CertTools.stringToBCDNString("asdasd,asdassd"));

        log.trace("<test09TestReverse()");
    }

    /**
     * Tests the handling of DC components
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void test10TestMultipleReversed() throws Exception {
        log.trace(">test10TestMultipleReversed()");
        // We try to examine the that we handle modern dc components for ldap
        // correctly
        String dn1 = "dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G";
        String bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=Tomas G,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", bcdn1);

        String dn19 = "C=SE, dc=dc1,DC=DC2,O=EJBCA, O=oo, cn=foo, cn=bar";
        assertEquals("CN=bar,CN=foo,O=oo,O=EJBCA,DC=DC2,DC=dc1,C=SE", CertTools.stringToBCDNString(dn19));
        String dn20 = " C=SE,CN=\"foo, OU=bar\",  O=baz\\\\\\, quux  ";
        // BC always escapes with backslash, it doesn't use quotes.
        assertEquals("Conversion of: " + dn20, "CN=foo\\, OU\\=bar,O=baz\\\\\\, quux,C=SE", CertTools.stringToBCDNString(dn20));

        String dn21 = "C=SE,O=Foo\\, Inc, OU=Foo\\, Dep, CN=Foo\\'";
        String bcdn21 = CertTools.stringToBCDNString(dn21);
        assertEquals("CN=Foo\',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE", bcdn21);
        assertEquals("CN=Foo',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE", StringTools.strip(bcdn21));
        log.trace("<test10TestMultipleReversed()");
    }

    /**
     * Tests the insertCNPostfix function
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void test11TestInsertCNPostfix() throws Exception {
        log.trace(">test11TestInsertCNPostfix()");

        // Test the regular case with one CN beging replaced with " (VPN)"
        // postfix
        final X500NameStyle nameStyle = new CeSecoreNameStyle();
        String dn1 = "CN=Tomas G,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
        String cnpostfix1 = " (VPN)";
        String newdn1 = CertTools.insertCNPostfix(dn1, cnpostfix1, nameStyle);
        assertEquals("CN=Tomas G (VPN),OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", newdn1);

        // Test case when CN doesn't exist
        String dn2 = "OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
        String newdn2 = CertTools.insertCNPostfix(dn2, cnpostfix1, nameStyle);
        assertEquals("OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", newdn2);

        // Test case with two CNs in DN only first one should be replaced.
        String dn3 = "CN=Tomas G,CN=Bagare,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
        String newdn3 = CertTools.insertCNPostfix(dn3, cnpostfix1, nameStyle);
        assertEquals("CN=Tomas G (VPN),CN=Bagare,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", newdn3);

        // Test case with two CNs in reversed DN
        String dn4 = "dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G,CN=Bagare";
        String newdn4 = CertTools.insertCNPostfix(dn4, cnpostfix1, nameStyle);
        assertEquals("DC=com,DC=bigcorp,DC=se,OU=orgunit,OU=users,CN=Tomas G (VPN),CN=Bagare", newdn4);

        // Test case with two CNs in reversed DN
        String dn5 = "UID=tomas,CN=tomas,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
        String cnpostfix5 = " (VPN)";
        String newdn5 = CertTools.insertCNPostfix(dn5, cnpostfix5, nameStyle);
        assertEquals("UID=tomas,CN=tomas (VPN),OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", newdn5);

        log.trace("<test11TestInsertCNPostfix()");
    }

    /**
	 */
    @Test
    public void test12GetPartsFromDN() throws Exception {
        log.trace(">test01GetPartFromDN()");

        // We try to examine the general case and som special cases, which we
        // want to be able to handle
        String dn0 = "C=SE, O=AnaTom, CN=foo";
        assertEquals(CertTools.getPartsFromDN(dn0, "CN").size(), 1);
        assertTrue(CertTools.getPartsFromDN(dn0, "CN").contains("foo"));
        assertEquals(CertTools.getPartsFromDN(dn0, "O").size(), 1);
        assertTrue(CertTools.getPartsFromDN(dn0, "O").contains("AnaTom"));
        assertEquals(CertTools.getPartsFromDN(dn0, "C").size(), 1);
        assertTrue(CertTools.getPartsFromDN(dn0, "C").contains("SE"));
        assertEquals(CertTools.getPartsFromDN(dn0, "cn").size(), 1);
        assertTrue(CertTools.getPartsFromDN(dn0, "cn").contains("foo"));
        assertEquals(CertTools.getPartsFromDN(dn0, "o").size(), 1);
        assertTrue(CertTools.getPartsFromDN(dn0, "o").contains("AnaTom"));
        assertEquals(CertTools.getPartsFromDN(dn0, "c").size(), 1);
        assertTrue(CertTools.getPartsFromDN(dn0, "c").contains("SE"));

        String dn1 = "uri=http://www.a.se, C=SE, O=AnaTom, CN=foo";
        assertEquals(CertTools.getPartsFromDN(dn1, "CN").size(), 1);
        assertTrue(CertTools.getPartsFromDN(dn1, "CN").contains("foo"));
        assertEquals(CertTools.getPartsFromDN(dn1, CertTools.URI).size(), 0);
        assertEquals(CertTools.getPartsFromDN(dn1, CertTools.URI1).size(), 1);
        assertTrue(CertTools.getPartsFromDN(dn1, CertTools.URI1).contains("http://www.a.se"));

        String dn2 = "uri=http://www.a.se, uri=http://www.b.se, C=SE, O=AnaTom, CN=foo";
        assertEquals(CertTools.getPartsFromDN(dn2, "CN").size(), 1);
        assertTrue(CertTools.getPartsFromDN(dn2, "CN").contains("foo"));
        assertEquals(CertTools.getPartsFromDN(dn2, CertTools.URI1).size(), 2);
        assertTrue(CertTools.getPartsFromDN(dn2, CertTools.URI1).contains("http://www.a.se"));
        assertTrue(CertTools.getPartsFromDN(dn2, CertTools.URI1).contains("http://www.b.se"));

        String dn3 = "CN=test\\\"test, dNSName=, dNSName=";
        assertEquals(2, CertTools.getPartsFromDN(dn3, "dNSName").size());
        assertEquals("", CertTools.getPartsFromDN(dn3, "dNSName").get(0));
        assertEquals("", CertTools.getPartsFromDN(dn3, "dNSName").get(1));
        
        String dn4 = "CN=test\\+with\\,escaped=characters";
        assertEquals(1, CertTools.getPartsFromDN(dn4, "CN").size());
        assertEquals("test+with,escaped=characters", CertTools.getPartsFromDN(dn4, "CN").get(0));
        
        log.trace("<test12GetPartsFromDN()");
    }

    @Test
    public void test13GetSubjectAltNameString() throws Exception {
        log.trace(">test13GetSubjectAltNameString()");

        String altNames = CertTools.getSubjectAlternativeName(CertTools.getCertfromByteArray(altNameCert, Certificate.class));
        log.debug(altNames);
        String name = CertTools.getPartFromDN(altNames, CertTools.UPN);
        assertEquals("foo@a.se", name);
        assertEquals("foo@a.se", CertTools.getUPNAltName(CertTools.getCertfromByteArray(altNameCert, Certificate.class)));
        name = CertTools.getPartFromDN(altNames, CertTools.URI);
        assertEquals("http://www.a.se/", name);
        name = CertTools.getPartFromDN(altNames, CertTools.EMAIL);
        assertEquals("tomas@a.se", name);
        name = CertTools.getEMailAddress(CertTools.getCertfromByteArray(altNameCert, Certificate.class));
        assertEquals("tomas@a.se", name);
        name = CertTools.getEMailAddress(CertTools.getCertfromByteArray(testcert, Certificate.class));
        assertNull(name);
        name = CertTools.getEMailAddress(null);
        assertNull(name);
        name = CertTools.getPartFromDN(altNames, CertTools.DNS);
        assertEquals("www.a.se", name);
        name = CertTools.getPartFromDN(altNames, CertTools.IPADDR);
        assertEquals("10.1.1.1", name);
        altNames = CertTools.getSubjectAlternativeName(CertTools.getCertfromByteArray(altNameCertWithXmppAddr, Certificate.class));
        log.debug("altNames: "+altNames);
        name = CertTools.getPartFromDN(altNames, CertTools.UPN);
        assertEquals("foo@a.se", name);
        name = CertTools.getPartFromDN(altNames, CertTools.REGISTEREDID);
        assertEquals("1.1.1.2", name);
        name = CertTools.getPartFromDN(altNames, CertTools.XMPPADDR);
        assertEquals("tomas@xmpp.domain.com", name);
        name = CertTools.getPartFromDN(altNames, CertTools.SRVNAME);
        assertEquals("_Service.Name", name);
        name = CertTools.getPartFromDN(altNames, CertTools.FASCN);
        assertEquals("0419d23210d8210c2c1a843085a16858300842108608823210c3e1", name);
        name = CertTools.getPartFromDN(altNames, CertTools.URI);
        assertEquals("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6", name);
        altNames = CertTools.getSubjectAlternativeName(CertTools.getCertfromByteArray(altNameCertWithSpecialCharacters, Certificate.class));
        // Note that the actual values in this particular certificate contains \, and \\, so that's why it looks like it's double escaped
        assertEquals("uniformResourceIdentifier=http://x/A\\\\\\,B\\\\\\\\, srvName=test\\\\\\,with\\\\\\\\special=characters, permanentIdentifier=test\\\\\\,with\\\\\\\\special=characters/", altNames);
        assertEquals("test\\,with\\\\special=characters/", CertTools.getPartFromDN(altNames, CertTools.PERMANENTIDENTIFIER));
        log.trace("<test13GetSubjectAltNameString()");
    }

    @Test
    public void test14QCStatement() throws Exception {
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

    @Test
    public void test15AiaOcspUri() throws Exception {
        Certificate cert = CertTools.getCertfromByteArray(aiaCert, Certificate.class);
        // log.debug(cert);
        assertEquals("http://localhost:8080/ejbca/publicweb/status/ocsp", CertTools.getAuthorityInformationAccessOcspUrl(cert));
    }

    @Test
    public void test16GetSubjectAltNameStringWithDirectoryName() throws Exception {
        log.trace(">test16GetSubjectAltNameStringWithDirectoryName()");

        Certificate cer = CertTools.getCertfromByteArray(altNameCertWithDirectoryName, Certificate.class);
        String altNames = CertTools.getSubjectAlternativeName(cer);
        log.debug(altNames);

        String name = CertTools.getPartFromDN(altNames, CertTools.UPN);
        assertEquals("testDirName@jamador.pki.gva.es", name);
        assertEquals("testDirName@jamador.pki.gva.es", CertTools.getUPNAltName(cer));

        name = CertTools.getPartFromDN(altNames, CertTools.DIRECTORYNAME);
        assertEquals("CN=testDirName|dir|name", name.replace("cn=", "CN="));
        assertEquals(name.substring("CN=".length()), (new X500Name("CN=testDirName|dir|name").getRDNs()[0].getFirst().getValue()).toString());

        String altName = "rfc822name=foo@bar.se, uri=http://foo.bar.se, directoryName=" + LDAPDN.escapeRDN("CN=testDirName, O=Foo, OU=Bar, C=SE")
                + ", dnsName=foo.bar.se";
        GeneralNames san = CertTools.getGeneralNamesFromAltName(altName);
        GeneralName[] gns = san.getNames();
        boolean found = false;
        for (int i = 0; i < gns.length; i++) {
            int tag = gns[i].getTagNo();
            if (tag == 4) {
                found = true;
                ASN1Encodable enc = gns[i].getName();
                X500Name dir = (X500Name) enc;
                String str = dir.toString();
                log.debug("DirectoryName: " + str);
                assertEquals("CN=testDirName,O=Foo,OU=Bar,C=SE", str);
            }

        }
        assertTrue(found);

        altName = "rfc822name=foo@bar.se, rfc822name=foo@bar.com, uri=http://foo.bar.se, directoryName="
                + LDAPDN.escapeRDN("CN=testDirName, O=Foo, OU=Bar, C=SE") + ", dnsName=foo.bar.se, dnsName=foo.bar.com";
        san = CertTools.getGeneralNamesFromAltName(altName);
        gns = san.getNames();
        int dnscount = 0;
        int rfc822count = 0;
        for (int i = 0; i < gns.length; i++) {
            int tag = gns[i].getTagNo();
            if (tag == 2) {
                dnscount++;
                ASN1Encodable enc = gns[i].getName();
                DERIA5String dir = (DERIA5String) enc;
                String str = dir.getString();
                log.info("DnsName: " + str);
            }
            if (tag == 1) {
                rfc822count++;
                ASN1Encodable enc = gns[i].getName();
                DERIA5String dir = (DERIA5String) enc;
                String str = dir.getString();
                log.info("Rfc822Name: " + str);
            }

        }
        assertEquals(2, dnscount);
        assertEquals(2, rfc822count);
        log.trace("<test16GetSubjectAltNameStringWithDirectoryName()");
    }

    @Test
    public void test17SubjectDirectoryAttributes() throws Exception {
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
    public void test18DNSpaceTrimming() throws Exception {
        log.trace(">test18DNSpaceTrimming()");
        String dn1 = "CN=CommonName, O= Org,C=SE";
        String bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=CommonName,O=Org,C=SE", bcdn1);

        dn1 = "CN=CommonName, O =Org,C=SE";
        bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=CommonName,O=Org,C=SE", bcdn1);

        dn1 = "CN=CommonName, O = Org,C=SE";
        bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=CommonName,O=Org,C=SE", bcdn1);
        log.trace("<test18DNSpaceTrimming()");
    }

    @Test
    public void test19getAltNameStringFromExtension() throws Exception {
        {
            PKCS10CertificationRequest p10 = new JcaPKCS10CertificationRequest(p10ReqWithAltNames);
            Attribute attribute = p10.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)[0];
            // The set of attributes contains a sequence of with type oid
            // PKCSObjectIdentifiers.pkcs_9_at_extensionRequest
            boolean found = false;
            DERSet s = (DERSet) attribute.getAttrValues();
            Extensions exts = Extensions.getInstance(s.getObjectAt(0));
            Extension ext = exts.getExtension(Extension.subjectAlternativeName);
            if (ext != null) {
                found = true;
                String altNames = CertTools.getAltNameStringFromExtension(ext);
                assertEquals("dNSName=ort3-kru.net.polisen.se, iPAddress=10.252.255.237", altNames);

            }
            assertTrue(found);
        }
        {
            PKCS10CertificationRequest p10 = new JcaPKCS10CertificationRequest(p10ReqWithAltNames2);
            // The set of attributes contains a sequence of with type oid
            // PKCSObjectIdentifiers.pkcs_9_at_extensionRequest
            Attribute attribute = p10.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)[0];
            boolean found = false;
            DERSet s = (DERSet) attribute.getAttrValues();
            Extensions exts = Extensions.getInstance(s.getObjectAt(0));
            Extension ext = exts.getExtension(Extension.subjectAlternativeName);
            if (ext != null) {
                found = true;
                String altNames = CertTools.getAltNameStringFromExtension(ext);
                assertEquals("dNSName=foo.bar.com, iPAddress=10.0.0.1", altNames);
            }
            assertTrue(found);
        }

    }

    

    @Test
    public void test20cvcCert() throws Exception {
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
            fail();
        }
        // Test verification of an authenticated request that fails
        parsedObject = CertificateParser.parseCVCObject(cvcreqrenew);
        authreq = (CVCAuthenticatedRequest) parsedObject;
        req = authreq.getRequest();
        try {
            authreq.verify(req.getCertificateBody().getPublicKey());
            fail();
        } catch (Exception e) {
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
    public void test21GenSelfCert() throws Exception {
        KeyPair kp = KeyTools.genKeys("1024", "RSA");
        Certificate cert = CertTools.genSelfCertForPurpose("CN=foo1", 10, null, kp.getPrivate(), kp.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, true, X509KeyUsage.keyCertSign, true);
        assertNotNull(cert);
        PublicKey pk = cert.getPublicKey();
        assertNotNull(pk);
        assertEquals("RSA", pk.getAlgorithm());
        if (pk instanceof RSAPublicKey) {
            BigInteger modulus = ((RSAPublicKey) pk).getModulus();
            int len = modulus.bitLength();
            assertEquals(1024, len);
        } else {
            assertTrue(false);
        }
        assertTrue(CertTools.isCA(cert));
        String subjectdn = CertTools.getSubjectDN(cert);
        assertEquals("CN=foo1", subjectdn);
        String issuerdn = CertTools.getIssuerDN(cert);
        assertEquals("CN=foo1", issuerdn);
        
        // Get signature field
        byte[] sign = CertTools.getSignature(cert);
        assertEquals(128, sign.length);
    }

    @Test
    public void test22CreateCertChain() throws Exception {
        // Test creating a certificate chain for CVC CAs
        Certificate cvccertroot = CertTools.getCertfromByteArray(cvccertchainroot, Certificate.class);
        Certificate cvccertsub = CertTools.getCertfromByteArray(cvccertchainsub, Certificate.class);
        assertTrue(CertTools.isCA(cvccertsub)); // DV is a CA also
        assertTrue(CertTools.isCA(cvccertroot));

        ArrayList<Certificate> certlist = new ArrayList<Certificate>();
        certlist.add(cvccertsub);
        certlist.add(cvccertroot);
        Collection<Certificate> col = CertTools.createCertChain(certlist);
        assertEquals(2, col.size());
        Iterator<Certificate> iter = col.iterator();
        Certificate certsub = (Certificate) iter.next();
        assertEquals("CN=RPS,C=SE", CertTools.getSubjectDN(certsub));
        Certificate certroot = (Certificate) iter.next();
        assertEquals("CN=HSMCVCA,C=SE", CertTools.getSubjectDN(certroot));

        // Test creating a certificate chain for X509CAs
        Certificate x509certsubsub = CertTools.getCertfromByteArray(x509certchainsubsub, Certificate.class);
        assertTrue(CertTools.isCA(x509certsubsub));
        Certificate x509certsub = CertTools.getCertfromByteArray(x509certchainsub, Certificate.class);
        assertTrue(CertTools.isCA(x509certsub));
        Certificate x509certroot = CertTools.getCertfromByteArray(x509certchainroot, Certificate.class);
        assertTrue(CertTools.isCA(x509certroot));
        certlist = new ArrayList<Certificate>();
        certlist.add(x509certsub);
        certlist.add(x509certroot);
        certlist.add(x509certsubsub);
        col = CertTools.createCertChain(certlist);
        assertEquals(3, col.size());
        iter = col.iterator();
        Certificate certsubsub = (Certificate) iter.next();
        assertEquals("CN=SubSubCA", CertTools.getSubjectDN(certsubsub));
        certsub = (Certificate) iter.next();
        assertEquals("CN=SubCA", CertTools.getSubjectDN(certsub));
        certroot = (Certificate) iter.next();
        assertEquals("CN=RootCA", CertTools.getSubjectDN(certroot));

    }

    @Test
    public void test23GenSelfCertDSA() throws Exception {
        KeyPair kp = KeyTools.genKeys("1024", "DSA");
        Certificate cert = CertTools.genSelfCertForPurpose("CN=foo1", 10, null, kp.getPrivate(), kp.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_DSA, true, X509KeyUsage.keyCertSign, true);
        assertNotNull(cert);
        PublicKey pk = cert.getPublicKey();
        assertNotNull(pk);
        assertEquals("DSA", pk.getAlgorithm());
        assertTrue(pk instanceof DSAPublicKey);
        String subjectdn = CertTools.getSubjectDN(cert);
        assertEquals("CN=foo1", subjectdn);
        String issuerdn = CertTools.getIssuerDN(cert);
        assertEquals("CN=foo1", issuerdn);
    }

    @Test
    public void test24GetCrlDistributionPoint() throws Exception {
        log.trace(">test24GetCrlDistributionPoint()");

        Collection<Certificate> certs;
        URL url;
        // Test with normal cert
        try {
            certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(CERT_WITH_URI.getBytes()), Certificate.class);
            url = CertTools.getCrlDistributionPoint(certs.iterator().next());
            assertNotNull(url);
        } catch (CertificateParsingException ex) {
            fail("Exception: " + ex.getMessage());
        }
        // Test with cert that contains CDP without URI
        try {
            certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(CERT_WITHOUT_URI.getBytes()), Certificate.class);
            url = CertTools.getCrlDistributionPoint(certs.iterator().next());
            assertNull(url);
        } catch (CertificateParsingException ex) {
            fail("Exception: " + ex.getMessage());
        }

        log.trace("<test24GetCrlDistributionPoint()");
    }
    
    @Test
    public void test25AiaCaIssuerUri() throws Exception {
        // Only 1 CA Issuer in static aiaCert: "http://localhost:8080/caIssuer"!
        Certificate cert = CertTools.getCertfromByteArray(aiaCert, Certificate.class);
        assertEquals("http://localhost:8080/caIssuer", CertTools.getAuthorityInformationAccessCAIssuerUris( cert).get(0));
    }

    @Test
    public void testKrb5PrincipalName() throws Exception {
        String altName = "krb5principal=foo/bar@P.SE, upn=upn@u.com";
        GeneralNames gn = CertTools.getGeneralNamesFromAltName(altName);
        assertNotNull("getGeneralNamesFromAltName failed for " + altName, gn);

        GeneralName[] names = gn.getNames();
        String ret = CertTools.getGeneralNameString(0, names[1].getName());
        assertEquals("krb5principal=foo/bar@P.SE", ret);

        altName = "krb5principal=foo@P.SE";
        gn = CertTools.getGeneralNamesFromAltName(altName);
        names = gn.getNames();
        ret = CertTools.getGeneralNameString(0, names[0].getName());
        assertEquals("krb5principal=foo@P.SE", ret);

        altName = "krb5principal=foo/A.SE@P.SE";
        gn = CertTools.getGeneralNamesFromAltName(altName);
        names = gn.getNames();
        ret = CertTools.getGeneralNameString(0, names[0].getName());
        assertEquals("krb5principal=foo/A.SE@P.SE", ret);

        Certificate krbcert = CertTools.getCertfromByteArray(krb5principalcert, Certificate.class);
        String s = CertTools.getSubjectAlternativeName(krbcert);
        assertEquals("krb5principal=foo/bar@P.COM", s);
    }

    @Test
    public void testIdOnSIM() throws Exception {
        String otherName = "krb5principal=foo/bar@P.SE, " + RFC4683Tools.SUBJECTIDENTIFICATIONMETHOD +"=2.16.840.1.101.3.4.2.1::CB3AE7FBFFFD9C85A3FB234E51FFFD2190B1F8F161C0A2873B998EFAC067B03A::6D9E6264DDBD0FC997B9B40524247C8BC319D02A583F4B499DD3ECAF06C786DF, upn=upn@u.com";
        GeneralNames gn = CertTools.getGeneralNamesFromAltName(otherName);
        GeneralName[] names = gn.getNames();
        String ret = CertTools.getGeneralNameString(0, names[2].getName());
        assertEquals(names.length, 3);
        assertEquals(RFC4683Tools.SUBJECTIDENTIFICATIONMETHOD +"=2.16.840.1.101.3.4.2.1::CB3AE7FBFFFD9C85A3FB234E51FFFD2190B1F8F161C0A2873B998EFAC067B03A::6D9E6264DDBD0FC997B9B40524247C8BC319D02A583F4B499DD3ECAF06C786DF", ret);
    }
    
    @Test
    public void testPseudonymAndName() throws Exception {
        String dn1 = "c=SE,O=Prime,OU=Tech,TelephoneNumber=555-666,Name=Kalle,PostalAddress=footown,PostalCode=11122,Pseudonym=Shredder,cn=Tomas Gustavsson";
        String bcdn1 = CertTools.stringToBCDNString(dn1);
        assertEquals(
                "Pseudonym=Shredder,TelephoneNumber=555-666,PostalAddress=footown,PostalCode=11122,CN=Tomas Gustavsson,Name=Kalle,OU=Tech,O=Prime,C=SE",
                bcdn1);
    }

    @Test
    public void testEscapedCharacters() throws Exception {
        final String input = "O=\\<fff\\>\\\",CN=oid,SN=12345,NAME=name,C=se";
        final String dn = CertTools.stringToBCDNString(input);
        assertEquals("Conversion of: "+input, "CN=oid,Name=name,SN=12345,O=\\<fff\\>\\\",C=se", dn);
    }

    @Test
    public void testSerialNumberFromString() throws Exception {
        // Test numerical format
        BigInteger serno = CertTools.getSerialNumberFromString("00001");
        assertEquals(1, serno.intValue());
        // Test SE001 format
        serno = CertTools.getSerialNumberFromString("SE021");
        assertEquals(21, serno.intValue());

        // Test numeric and hexadecimal string, will get the numerical part in the middle
        serno = CertTools.getSerialNumberFromString("F53AA");
        assertEquals(53, serno.intValue());

        // Test pure letters
        serno = CertTools.getSerialNumberFromString("FXBAA");
        assertEquals(26748514, serno.intValue());

        // Test a strange format...
        serno = CertTools.getSerialNumberFromString("SE02K");
        assertEquals(2, serno.intValue());

        // Test a real biginteger
        serno = CertTools.getSerialNumberFromString("7331288210307371");
        assertEquals(271610737, serno.intValue());

        // Test a real certificate
        Certificate cert = CertTools.getCertfromByteArray(testcert, Certificate.class);
        serno = CertTools.getSerialNumber(cert);
        assertEquals(271610737, serno.intValue());
        String str = CertTools.getSerialNumberAsString(cert);
        assertEquals(serno.toString(16), str);
    }

    @Test
    public void testReadPEMCertificate() throws Exception {
        X509Certificate cert = CertTools.getCertfromByteArray(pemcert, X509Certificate.class);
        assertNotNull(cert);
        assertEquals("CN=AdminCA1,O=EJBCA Sample,C=SE", cert.getSubjectDN().toString());
    }

    @Test
    public void testNullInput() {
        assertNull(CertTools.stringToBcX500Name(null));
        assertNull(CertTools.stringToBCDNString(null));
        assertNull(CertTools.reverseDN(null));
        assertFalse(CertTools.isDNReversed(null));
        assertNull(CertTools.getPartFromDN(null, null));
        assertEquals(0, CertTools.getPartsFromDN(null, null).size());
        assertEquals(0, CertTools.getCustomOids(null).size());
        try {
        	assertNull(CertTools.getSerialNumber(null));
        	assertTrue("Should throw", false);
        } catch (IllegalArgumentException e) {
        	// NOPMD
        }
        try {
            assertNull(CertTools.getSerialNumberAsString(null));
        	assertTrue("Should throw", false);
        } catch (IllegalArgumentException e) {
        	// NOPMD
        }
        try {
            assertNull(CertTools.getSerialNumberFromString(null));
        	assertTrue("Should throw", false);
        } catch (IllegalArgumentException e) {
        	// NOPMD
        }
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
    
    @Test
    public void testFingerprint() throws Exception {
    	Certificate cert = CertTools.getCertfromByteArray(testcert, Certificate.class);
    	assertEquals("4d66df0017deb32f669346c51c80600964816c84", CertTools.getFingerprintAsString(cert));
    	assertEquals("4d66df0017deb32f669346c51c80600964816c84", CertTools.getFingerprintAsString(testcert));
    	assertEquals("c61bfaa15d733532c5e795756c8001d4", new String(Hex.encode(CertTools.generateMD5Fingerprint(testcert))));
    }

    @Test
    public void testCRLs() throws Exception {
    	X509CRL crl = CertTools.getCRLfromByteArray(testcrl);
    	assertEquals("CN=TEST", CertTools.getIssuerDN(crl));
    	byte[] pembytes = CertTools.getPEMFromCrl(testcrl);
    	String pem = new String(pembytes);
    	assertTrue(pem.contains("BEGIN X509 CRL"));
    	assertEquals(1, CrlExtensions.getCrlNumber(crl).intValue());
    	assertEquals(-1, CrlExtensions.getDeltaCRLIndicator(crl).intValue());

    	X509CRL deltacrl = CertTools.getCRLfromByteArray(testdeltacrl);
    	assertEquals(3, CrlExtensions.getCrlNumber(deltacrl).intValue());
    	assertEquals(2, CrlExtensions.getDeltaCRLIndicator(deltacrl).intValue());

    }
    
    private DERSequence permanentIdentifier(String identifierValue, String assigner) {
        DERSequence result;
        ASN1EncodableVector v = new ASN1EncodableVector(); // this is the OtherName
        v.add(new ASN1ObjectIdentifier(CertTools.PERMANENTIDENTIFIER_OBJECTID));

        // First the PermanentIdentifier sequence
        ASN1EncodableVector piSeq = new ASN1EncodableVector();
        if (identifierValue != null) {
            piSeq.add(new DERUTF8String(identifierValue));
        }
        if (assigner != null) {
            piSeq.add(new ASN1ObjectIdentifier(assigner));
        }
        v.add(new DERTaggedObject(true, 0, new DERSequence(piSeq)));
        result = new DERSequence(v);
        
        log.info(ASN1Dump.dumpAsString(result));
        return result;
    }
    
    @Test
    public void testGetPermanentIdentifierStringFromSequence() throws Exception {
        assertEquals("abc123/1.2.3.4", CertTools.getPermanentIdentifierStringFromSequence(permanentIdentifier("abc123", "1.2.3.4")));
        assertEquals("defg456/", CertTools.getPermanentIdentifierStringFromSequence(permanentIdentifier("defg456", null)));
        assertEquals("/1.2.3.5", CertTools.getPermanentIdentifierStringFromSequence(permanentIdentifier(null, "1.2.3.5")));
        assertEquals("/", CertTools.getPermanentIdentifierStringFromSequence(permanentIdentifier(null, null)));
        
        assertEquals("ident with \\/ slash/1.2.3.4", CertTools.getPermanentIdentifierStringFromSequence(permanentIdentifier("ident with / slash", "1.2.3.4")));
        assertEquals("ident with \\/ slash/", CertTools.getPermanentIdentifierStringFromSequence(permanentIdentifier("ident with / slash", null)));
        assertEquals("ident with \\\\/ slash/1.2.3.6", CertTools.getPermanentIdentifierStringFromSequence(permanentIdentifier("ident with \\/ slash", "1.2.3.6")));
        assertEquals("ident with \\\\/ slash/", CertTools.getPermanentIdentifierStringFromSequence(permanentIdentifier("ident with \\/ slash", null)));
    }
    
    @Test
    public void testGetPermanentIdentifierValues() throws Exception {
        assertEquals("[abc123, 1.2.3.7]", Arrays.toString(CertTools.getPermanentIdentifierValues("abc123/1.2.3.7")));
        assertEquals("[abc123, null]", Arrays.toString(CertTools.getPermanentIdentifierValues("abc123/")));
        assertEquals("[abc123, null]", Arrays.toString(CertTools.getPermanentIdentifierValues("abc123")));
        assertEquals("[null, 1.2.3.8]", Arrays.toString(CertTools.getPermanentIdentifierValues("/1.2.3.8")));
        assertEquals("[null, null]", Arrays.toString(CertTools.getPermanentIdentifierValues("/")));
        assertEquals("[null, null]", Arrays.toString(CertTools.getPermanentIdentifierValues("")));
    }
    
    @Test
    public void testGetGeneralNamesFromAltName4permanentIdentifier() throws Exception {
        // One permanentIdentifier
        String altName = "permanentIdentifier=def321/1.2.5, upn=upn@u.com";
        GeneralNames gn = CertTools.getGeneralNamesFromAltName(altName);
        assertNotNull("getGeneralNamesFromAltName failed for " + altName, gn);
        String[] result = new String[] { 
            CertTools.getGeneralNameString(0, gn.getNames()[0].getName()), 
            CertTools.getGeneralNameString(0, gn.getNames()[1].getName())
        };
        Arrays.sort(result);
        assertEquals("[permanentIdentifier=def321/1.2.5, upn=upn@u.com]", Arrays.toString(result));
        
        // Two permanentIdentifiers
        gn = CertTools.getGeneralNamesFromAltName("permanentIdentifier=def321/1.2.5, upn=upn@example.com, permanentIdentifier=abcd 456/1.2.7");    
        result = new String[] { 
            CertTools.getGeneralNameString(0, gn.getNames()[0].getName()),
            CertTools.getGeneralNameString(0, gn.getNames()[1].getName()),
            CertTools.getGeneralNameString(0, gn.getNames()[2].getName())
        };
        Arrays.sort(result);
        assertEquals("[permanentIdentifier=abcd 456/1.2.7, permanentIdentifier=def321/1.2.5, upn=upn@example.com]", Arrays.toString(result));
    }

    @Test
    public void testGetGeneralNamesFromAltName5DirectoryName() throws Exception {
        // One directoryName
        String altName = "directoryName=CN=Tomas\\,O=PrimeKey\\,C=SE";
        GeneralNames gn = CertTools.getGeneralNamesFromAltName(altName);
        assertNotNull("getGeneralNamesFromAltName failed for " + altName, gn);
        String[] result = new String[] { 
            CertTools.getGeneralNameString(4, gn.getNames()[0].getName()), 
        };
        Arrays.sort(result);
        assertEquals("[directoryName=CN=Tomas,O=PrimeKey,C=SE]", Arrays.toString(result));
        
        // Test UTF-8
        altName = "directoryName=CN=اتمنى لك يوما طيبا";
        gn = CertTools.getGeneralNamesFromAltName(altName);
        assertNotNull("getGeneralNamesFromAltName failed for " + altName, gn);
        result = new String[] { 
            CertTools.getGeneralNameString(4, gn.getNames()[0].getName()), 
        };
        Arrays.sort(result);
        assertEquals("[directoryName=CN=اتمنى لك يوما طيبا]", Arrays.toString(result));
        
    }

    @Test
    public void testStringToBcX500WithIncompleteLoneValue() {
        //Legal as a name even if it won't be legal as a DN
        X500Name result = CertTools.stringToBcX500Name("O=");
        assertNotNull(result);    
        assertEquals("O=", result.toString());
    }
    
    @Test
    public void testStringToBcX500WithTrailingComma() {
        X500Name result = CertTools.stringToBcX500Name("CN=,");
        assertNotNull(result);
        assertEquals("CN=\\,", result.toString());
    }


    @Test
    public void testStringToBcX500WithIncompleteValue() {
        X500Name result = CertTools.stringToBcX500Name("CN=,O=foo");
        assertNotNull(result);
        assertEquals("CN=,O=foo", result.toString());
    }
    
    @Test
    public void testStringToBcX500WithValueAndTrailingComma() {
        X500Name result = CertTools.stringToBcX500Name("CN=f,");
        assertNotNull(result);
        assertEquals("CN=f\\,", result.toString());
    }

    @Test
    public void testStringToBcX500WithEmpty() {
        // Legacy behavior
        X500Name result = CertTools.stringToBcX500Name("");
        assertNotNull(result);    
        assertEquals("", result.toString());
    }
 
    @Test
    public void testStringToBcX500WithEscapedComma() {
        try {
            assertNotNull(CertTools.stringToBcX500Name("O=\\,"));
            assertNotNull(CertTools.stringToBcX500Name("O=f\\,b"));          
        } catch (IllegalArgumentException e) {
            fail("Exception " + e.getClass() + " should not been thrown.");
        }
    }

    @Test
    public void testStringToBcX500WithDefinedEVOrder() {
        try {
            final String[] order1 = { "street", "pseudonym",
                "telephonenumber", "postaladdress", "postalcode", "unstructuredaddress", "unstructuredname", "emailaddress", "e",
                "email", "dn", "uid", "cn", "name", "sn", "gn", "givenname", "initials", "surname", "t", "ou", "o", "l", "st", "dc", "c", "serialnumber", "businesscategory", "jurisdictioncountry", "jurisdictionstate", "jurisdictionlocality"};
            final X500NameStyle nameStyle = CeSecoreNameStyle.INSTANCE;
            final String dn = "JurisdictionCountry=NL,JurisdictionState=State,JurisdictionLocality=Åmål,BusinessCategory=Private Organization,CN=evssltest6.test.lan,SN=1234567890,OU=XY,O=MyOrg B.V.,L=Åmål,ST=Norrland,C=SE"; 
            X500Name name = CertTools.stringToBcX500Name(dn, nameStyle, false, order1);
            assertNotNull(name);
            String desiredDN = "JurisdictionLocality=Åmål,JurisdictionState=State,JurisdictionCountry=NL,BusinessCategory=Private Organization,C=SE,ST=Norrland,L=Åmål,O=MyOrg B.V.,OU=XY,SN=1234567890,CN=evssltest6.test.lan";
            assertEquals("Name order should be as defined in order string array", desiredDN, name.toString());
            // Another order
            final String[] order2 = { "jurisdictioncountry", "jurisdictionstate", "jurisdictionlocality","businesscategory","serialnumber","c","dc","st","l","o","ou","t","surname","initials","givenname","gn","sn","name","cn","uid","dn","email","e","emailaddress","unstructuredname","unstructuredaddress","postalcode","postaladdress","telephonenumber","pseudonym","street"};
            name = CertTools.stringToBcX500Name(dn, nameStyle, false, order2);
            assertNotNull(name);
            String desiredDNNoLap = "CN=evssltest6.test.lan,OU=XY,O=MyOrg B.V.,L=Åmål,ST=Norrland,C=SE,SN=1234567890,BusinessCategory=Private Organization,JurisdictionLocality=Åmål,JurisdictionState=State,JurisdictionCountry=NL";
            assertEquals("Name order should be as defined in order string array", desiredDNNoLap, name.toString());
            name = CertTools.stringToBcX500Name(dn, nameStyle, true, order2);
            String desiredDNWithLDAP = "JurisdictionCountry=NL,JurisdictionState=State,JurisdictionLocality=Åmål,BusinessCategory=Private Organization,SN=1234567890,C=SE,ST=Norrland,L=Åmål,O=MyOrg B.V.,OU=XY,CN=evssltest6.test.lan"; 
            assertEquals("Name order should be as defined in order string array", desiredDNWithLDAP, name.toString());
            // Ignore LDAP DN order (do not apply)
            name = CertTools.stringToBcX500Name(dn, nameStyle, true, order2, false);
            assertEquals("Name order should be as defined in order string array", desiredDNWithLDAP, name.toString());
            name = CertTools.stringToBcX500Name(dn, nameStyle, false, order2, false);
            assertEquals("Name order should be as defined in order string array", desiredDNWithLDAP, name.toString());
            // Don't ignore LDAP DN order (apply it == true), should be the same as without the extra boolean
            name = CertTools.stringToBcX500Name(dn, nameStyle, true, order2, true);
            assertEquals("Name order should be as defined in order string array", desiredDNWithLDAP, name.toString());
            name = CertTools.stringToBcX500Name(dn, nameStyle, false, order2, true);
            assertEquals("Name order should be as defined in order string array", desiredDNNoLap, name.toString());
            
            // If the ordering string is missing some components that exist in the DN, these will just be added to the beginning of the resulting DN
            final String[] orderWithMissing = { "street", "pseudonym",
                    "telephonenumber", "postaladdress", "postalcode", "unstructuredaddress", "unstructuredname", "emailaddress", "e",
                    "email", "dn", "uid", "cn", "name", "sn", "gn", "givenname", "initials", "surname", "t", "ou", "o", "l", "st", "dc", "c", "serialnumber", "jurisdictionstate", "jurisdictionlocality"};
            name = CertTools.stringToBcX500Name(dn, nameStyle, false, orderWithMissing);
            assertNotNull(name);
            desiredDN = "BusinessCategory=Private Organization,JurisdictionCountry=NL,JurisdictionLocality=Åmål,JurisdictionState=State,C=SE,ST=Norrland,L=Åmål,O=MyOrg B.V.,OU=XY,SN=1234567890,CN=evssltest6.test.lan";
            assertEquals("Name order should be as defined in order string array", desiredDN, name.toString());
            // Standard ldap order
            name = CertTools.stringToBcX500Name(dn, nameStyle, true, null);
            assertNotNull(name);
            desiredDN = "JurisdictionCountry=NL,JurisdictionState=State,JurisdictionLocality=Åmål,BusinessCategory=Private Organization,CN=evssltest6.test.lan,SN=1234567890,OU=XY,O=MyOrg B.V.,L=Åmål,ST=Norrland,C=SE";
            assertEquals("Name order should be as defined DnComponents (forward) order array", desiredDN, name.toString());
            // Standard x500 order
            name = CertTools.stringToBcX500Name(dn, nameStyle, false, null);
            assertNotNull(name);
            desiredDN = "C=SE,ST=Norrland,L=Åmål,O=MyOrg B.V.,OU=XY,SN=1234567890,CN=evssltest6.test.lan,BusinessCategory=Private Organization,JurisdictionLocality=Åmål,JurisdictionState=State,JurisdictionCountry=NL";
            assertEquals("Name order should be as defined DnComponents (reverse) order array", desiredDN, name.toString());
        } catch (IllegalArgumentException e) {
            fail("Exception " + e.getClass() + " should not been thrown.");
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
    
    /**
     * Tests the following methods:
     * <ul>
     * <li>{@link CertTools.checkNameConstraints}</li>
     * <li>{@link NameConstraint.parseNameConstraintsList}</li>
     * <li>{@link NameConstraint.toGeneralSubtrees}</li>
     * </ul>
     */
    @Test
    public void testNameConstraints() throws Exception {
        final String permitted = "C=SE,O=PrimeKey,CN=example.com\n" +
                                 "example.com\n" +
                                 "@mail.example\n" +
                                 "user@host.com\n" +
                                 "10.0.0.0/8\n" +
                                 "   C=SE,  CN=spacing    \n";
        final String excluded = "forbidden.example.com\n" +
                                "postmaster@mail.example\n" +
                                "10.1.0.0/16\n" +
                                "::/0"; // IPv6
        
        final List<Extension> extensions = new ArrayList<Extension>();
        GeneralSubtree[] permittedSubtrees = NameConstraint.toGeneralSubtrees(NameConstraint.parseNameConstraintsList(permitted));
        GeneralSubtree[] excludedSubtrees = NameConstraint.toGeneralSubtrees(NameConstraint.parseNameConstraintsList(excluded));
        byte[] extdata = new NameConstraints(permittedSubtrees, excludedSubtrees).toASN1Primitive().getEncoded();
        extensions.add(new Extension(Extension.nameConstraints, false, extdata));
        
        final KeyPair testkeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate cacert = CertTools.genSelfCertForPurpose("C=SE,CN=Test Name Constraints CA", 365, null,
                testkeys.getPrivate(), testkeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true,
                X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, "BC", true, extensions);
        
        // Allowed subject DNs
        final X500Name validDN = new X500Name("C=SE,O=PrimeKey,CN=example.com"); // re-used below
        CertTools.checkNameConstraints(cacert, validDN, null);
        CertTools.checkNameConstraints(cacert, new X500Name("C=SE,CN=spacing"), null);
        // When importing certificates issued by Name Constrained CAs we may run into issues with DN encoding and DN order
        // In EndEntityManagementSessionBean.addUser we use something like:
        // X500Name subjectDNName1 = CertTools.stringToBcX500Name(CertTools.getSubjectDN(subjectCert), nameStyle, useLdapDnOrder);
        // Where nameStyle and dnOrder can have different values
        X500Name validDN2 = CertTools.stringToBcX500Name("C=SE,O=PrimeKey,CN=example.com", CeSecoreNameStyle.INSTANCE, false);
        CertTools.checkNameConstraints(cacert, validDN2, null);
        X500Name invalidDN1 = CertTools.stringToBcX500Name("C=SE,O=PrimeKey,CN=example.com", CeSecoreNameStyle.INSTANCE, true);
        checkNCException(cacert, invalidDN1, null, "ldapDnOrder true was accepted");
        X500Name invalidDN2 = CertTools.stringToBcX500Name("C=SE,O=PrimeKey,CN=example.com", PrintableStringNameStyle.INSTANCE, false);
        checkNCException(cacert, invalidDN2, null, "PrintableStringNameStyle was accepted");


        // Allowed subject alternative names
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, "example.com")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.dNSName, "x.sub.example.com")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "someuser@mail.example")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "user@host.com")));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("10.0.0.1").getAddress()))));
        CertTools.checkNameConstraints(cacert, validDN, new GeneralNames(new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("10.255.255.255").getAddress()))));
        
        // Disallowed subject DN
        checkNCException(cacert, new X500Name("C=DK,CN=example.com"), null, "Disallowed DN (wrong field value) was accepted");
        checkNCException(cacert, new X500Name("C=SE,O=Company,CN=example.com"), null, "Disallowed DN (extra field) was accepted");
        
        // Disallowed SAN
        // The commented out lines are allowed by BouncyCastle but disallowed by the RFC
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "bad.com"), "Disallowed SAN (wrong DNS name) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.dNSName, "forbidden.example.com"), "Disallowed SAN (excluded DNS subdomain) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.rfc822Name, "wronguser@host.com"), "Disallowed SAN (wrong e-mail) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("10.1.0.1").getAddress())), "Disallowed SAN (excluded IPv4 address) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("192.0.2.1").getAddress())), "Disallowed SAN (wrong IPv4 address) was accepted");
        checkNCException(cacert, validDN, new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("2001:DB8::").getAddress())), "Disallowed SAN (IPv6 address) was accepted");
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
        
        ObjectInputStream objectInputStream = null;
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
            if (objectInputStream != null) {
                objectInputStream.close();
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
        
        ObjectInputStream objectInputStream = null;
        ByteArrayOutputStream byteArrayOutputStream = null;
        try {
            byteArrayOutputStream = new ByteArrayOutputStream();
            SecurityFilterInputStreamTest.prepareExploitStream(byteArrayOutputStream, 0x1FFFFF);  // 0x1FFFFF just simulates exploit stream

            CertTools.getCertfromByteArray(byteArrayOutputStream.toByteArray(), X509Certificate.class);
            fail("No Java heap error happened for StringBuilder exploit (MaxHeap = " + Runtime.getRuntime().maxMemory()/(1024*1024) + "MB) and"
                    + " SecurityFilterInputStream hasn't limited the size of input stream during testPreventingHeapOverflowDuringgetCertsFromByteArray");
        } catch (CertificateParsingException e) { //It seems that BC provider while generating certificate wraps RuntimeException into CertificateException (which CertTools wraps into CertificateParsingException...)
            //Good
        } catch (Exception e){
            fail("Unexpected exception: " + e.getMessage() + " during testPreventingHeapOverflowDuringgetCertsFromByteArray");
        }finally {
            if (byteArrayOutputStream != null) {
                byteArrayOutputStream.close();
            }
            if (objectInputStream != null) {
                objectInputStream.close();
            }
        }
        
        log.trace("<testPreventingHeapOverflowDuringgetCertsFromByteArray()");
    }

    /** Test CertTools methods for reading CertificatePolicy information from a certificate
     * @throws CertificateParsingException 
     * @throws IOException 
     */
    @Test
    public void testCertificatePolicies() throws CertificateParsingException, IOException {
        // The altname test certificate does not have any policy oids
        Certificate certwithnone = CertTools.getCertfromByteArray(altNameCert, Certificate.class);
        List<ASN1ObjectIdentifier> oids = CertTools.getCertificatePolicyIds(certwithnone);
        assertEquals("Should be no Cert Policy OIDs", 0, oids.size());
        // This policy test cert have 4 oids with different contents
        //X509v3 Certificate Policies: 
        //    Policy: 1.1.1.2
        //      CPS: https://ejbca.org/2
        //    Policy: 1.1.1.3
        //      CPS: https://ejbca.org/3
        //    Policy: 1.1.1.1
        //    Policy: 1.1.1.4
        //      User Notice (UTF-8):
        //        Explicit Text: My User Notice Text
        Certificate cert = CertTools.getCertfromByteArray(certPoliciesCert, Certificate.class);
        oids = CertTools.getCertificatePolicyIds(cert);
        assertEquals("Should be 5 Cert Policy OIDs", 5, oids.size());
        assertEquals("1.1.1.2", oids.get(0).getId());
        assertEquals("1.1.1.3", oids.get(1).getId());
        assertEquals("1.1.1.1", oids.get(2).getId());
        assertEquals("1.1.1.4", oids.get(3).getId());
        assertEquals("1.1.1.5", oids.get(4).getId());
        // Get the full policy objects
        List<PolicyInformation> pi = CertTools.getCertificatePolicies(cert);
        assertEquals("Should be 5 Cert Policies", 5, pi.size());
        assertEquals("1.1.1.2", pi.get(0).getPolicyIdentifier().getId());
        assertEquals("1.1.1.3", pi.get(1).getPolicyIdentifier().getId());
        assertEquals("1.1.1.1", pi.get(2).getPolicyIdentifier().getId());
        assertEquals("1.1.1.4", pi.get(3).getPolicyIdentifier().getId());
        assertEquals("1.1.1.5", pi.get(4).getPolicyIdentifier().getId());
        // Now it's getting hairier, get the policy qualifiers, which can be anything, as defined in the qualifier
        // PolicyInformation ::= SEQUENCE {
        //    policyIdentifier   CertPolicyId,
        //    policyQualifiers   SEQUENCE SIZE (1..MAX) OF
        //                            PolicyQualifierInfo OPTIONAL }
        // PolicyQualifierInfo ::= SEQUENCE {
        //    policyQualifierId  PolicyQualifierId,
        //    qualifier          ANY DEFINED BY policyQualifierId }
        // -- policyQualifierIds for Internet policy qualifiers
        // id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
        // id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
        // id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
        
        // The first Policy object has a CPS URI
        ASN1Encodable qualifier = pi.get(0).getPolicyQualifiers().getObjectAt(0);
        //System.out.println(ASN1Dump.dumpAsString(qualifier));
        PolicyQualifierInfo pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_cps = 1.3.6.1.5.5.7.2.1
        assertEquals(PolicyQualifierId.id_qt_cps.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_cps, we know this is a DERIA5String
        DERIA5String str = DERIA5String.getInstance(pqi.getQualifier());
        assertEquals("https://ejbca.org/2", str.getString());
        
        // The second Policy object has a CPS URI
        qualifier = pi.get(1).getPolicyQualifiers().getObjectAt(0);
        //System.out.println(ASN1Dump.dumpAsString(qualifier));
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_cps = 1.3.6.1.5.5.7.2.1
        assertEquals(PolicyQualifierId.id_qt_cps.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_cps, we know this is a DERIA5String
        str = DERIA5String.getInstance(pqi.getQualifier());
        assertEquals("https://ejbca.org/3", str.getString());
        
        // The third Policy object has only an OID
        qualifier = pi.get(2).getPolicyQualifiers();
        assertNull(qualifier);
        
        // The fourth Policy object has a User Notice
        qualifier = pi.get(3).getPolicyQualifiers().getObjectAt(0);
        //System.out.println(ASN1Dump.dumpAsString(qualifier));
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_unotice = 1.3.6.1.5.5.7.2.2
        assertEquals(PolicyQualifierId.id_qt_unotice.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_unutice, we know this is a UserNotice
        UserNotice un = UserNotice.getInstance(pqi.getQualifier());
        assertEquals("My User Notice Text", un.getExplicitText().getString());
        
        // The fifth Policy object has both a CPS URI and a User Notice
        qualifier = pi.get(4).getPolicyQualifiers().getObjectAt(0);
        //System.out.println(ASN1Dump.dumpAsString(qualifier));
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_unotice = 1.3.6.1.5.5.7.2.2
        assertEquals(PolicyQualifierId.id_qt_unotice.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_unutice, we know this is a UserNotice
        un = UserNotice.getInstance(pqi.getQualifier());
        assertEquals("EJBCA User Notice", un.getExplicitText().getString());
        qualifier = pi.get(4).getPolicyQualifiers().getObjectAt(1);
        //System.out.println(ASN1Dump.dumpAsString(qualifier));
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_cps = 1.3.6.1.5.5.7.2.1
        assertEquals(PolicyQualifierId.id_qt_cps.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_cps, we know this is a DERIA5String
        str = DERIA5String.getInstance(pqi.getQualifier());
        assertEquals("https://ejbca.org/CPS", str.getString());
    }
    
    @Test
    public void testOrderCertChain() throws CertificateParsingException, CertPathValidatorException {
        X509Certificate root = CertTools.getCertfromByteArray(chainRootCA, X509Certificate.class);
        X509Certificate sub = CertTools.getCertfromByteArray(chainSubCA, X509Certificate.class);
        X509Certificate ee = CertTools.getCertfromByteArray(chainUser, X509Certificate.class);
        // Try different orders...and see that we get the right things back
        List<X509Certificate> order1 = new ArrayList<X509Certificate>();
        order1.add(ee);
        order1.add(sub);
        order1.add(root);
        List<X509Certificate> list = CertTools.orderX509CertificateChain(order1);
        assertEquals("List should be of size 3", 3, list.size());
        assertEquals("EE cert should be first", CertTools.getSubjectDN(ee), CertTools.getSubjectDN(list.get(0)));
        assertEquals("SubCA cert should be second", CertTools.getSubjectDN(sub), CertTools.getSubjectDN(list.get(1)));
        assertEquals("RootCA cert should be third", CertTools.getSubjectDN(root), CertTools.getSubjectDN(list.get(2)));

        List<X509Certificate> order2 = new ArrayList<X509Certificate>();
        order2.add(sub);
        order2.add(root);
        order2.add(ee);
        list = CertTools.orderX509CertificateChain(order2);
        assertEquals("List should be of size 3", 3, list.size());
        assertEquals("EE cert should be first", CertTools.getSubjectDN(ee), CertTools.getSubjectDN(list.get(0)));
        assertEquals("SubCA cert should be second", CertTools.getSubjectDN(sub), CertTools.getSubjectDN(list.get(1)));
        assertEquals("RootCA cert should be third", CertTools.getSubjectDN(root), CertTools.getSubjectDN(list.get(2)));
        
        List<X509Certificate> order3 = new ArrayList<X509Certificate>();
        order3.add(sub);
        order3.add(ee);
        order3.add(root);
        list = CertTools.orderX509CertificateChain(order3);
        assertEquals("List should be of size 3", 3, list.size());
        assertEquals("EE cert should be first", CertTools.getSubjectDN(ee), CertTools.getSubjectDN(list.get(0)));
        assertEquals("SubCA cert should be second", CertTools.getSubjectDN(sub), CertTools.getSubjectDN(list.get(1)));
        assertEquals("RootCA cert should be third", CertTools.getSubjectDN(root), CertTools.getSubjectDN(list.get(2)));
        
        // Skip root, should order anyway up to sub
        List<X509Certificate> order4 = new ArrayList<X509Certificate>();
        order4.add(sub);
        order4.add(ee);
        list = CertTools.orderX509CertificateChain(order4);
        assertEquals("List should be of size 2", 2, list.size());
        assertEquals("EE cert should be first", CertTools.getSubjectDN(ee), CertTools.getSubjectDN(list.get(0)));
        assertEquals("SubCA cert should be second", CertTools.getSubjectDN(sub), CertTools.getSubjectDN(list.get(1)));

        List<X509Certificate> order5 = new ArrayList<X509Certificate>();
        order5.add(ee);
        order5.add(sub);
        list = CertTools.orderX509CertificateChain(order5);
        assertEquals("List should be of size 2", 2, list.size());
        assertEquals("EE cert should be first", CertTools.getSubjectDN(ee), CertTools.getSubjectDN(list.get(0)));
        assertEquals("SubCA cert should be second", CertTools.getSubjectDN(sub), CertTools.getSubjectDN(list.get(1)));
    }
    
    @Test
    public void testEscapeFieldValue() {
        assertEquals(null, CertTools.escapeFieldValue(null));
        assertEquals("", CertTools.escapeFieldValue(""));
        assertEquals("CN=", CertTools.escapeFieldValue("CN="));
        assertEquals("DIRECTORYNAME=DESCRIPTION=Test\\\\test\\,O=PrimeKey", CertTools.escapeFieldValue("DIRECTORYNAME=DESCRIPTION=Test\\test,O=PrimeKey"));
        assertEquals("CN=123\\+456", CertTools.escapeFieldValue("CN=123+456"));
        assertEquals("CN=abc\\\"def", CertTools.escapeFieldValue("CN=abc\"def"));
        assertEquals("CN=abc\\>def", CertTools.escapeFieldValue("CN=abc>def"));
    }
    
    @Test
    public void testUnescapeFieldValue() {
        assertEquals(null, CertTools.unescapeFieldValue(null));
        assertEquals("", CertTools.unescapeFieldValue(""));
        assertEquals("CN=", CertTools.unescapeFieldValue("CN="));
        assertEquals("DESCRIPTION=Test\\test,O=PrimeKey", CertTools.unescapeFieldValue("DESCRIPTION=Test\\\\test\\,O=PrimeKey"));
        assertEquals("DIRECTORYNAME=DESCRIPTION=Test\\test,O=PrimeKey", CertTools.unescapeFieldValue("DIRECTORYNAME=DESCRIPTION=Test\\\\test\\,O=PrimeKey"));
        assertEquals("CN=123+456", CertTools.unescapeFieldValue("CN=123\\+456"));
        assertEquals("abc\"def", CertTools.unescapeFieldValue("abc\\\"def"));
        assertEquals("abc>def", CertTools.unescapeFieldValue("abc\\>def"));
        assertEquals("\\>\"abc ", CertTools.unescapeFieldValue("\\\\\\>\\\"abc\\ "));
    }

    @Test
    public void testGetOidFromString() {
        assertEquals("1.2.3.4", CertTools.getOidFromString("1.2.3.4.value"));
        assertEquals("1.2.3.4", CertTools.getOidFromString("1.2.3.4.value2"));
        assertEquals("1.12.123.1234", CertTools.getOidFromString("1.12.123.1234.value3"));
        assertEquals("1.2.3.4", CertTools.getOidFromString("1.2.3.4.foobar"));
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
    
    private void checkNCException(X509Certificate cacert, X500Name subjectDNName, GeneralName subjectAltName, String message) {
        try {
            CertTools.checkNameConstraints(cacert, subjectDNName, new GeneralNames(subjectAltName));
            fail(message);
        } catch (IllegalNameException e) { /* NOPMD expected */ }
    }    
}