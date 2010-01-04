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

package org.ejbca.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Vector;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.util.cert.QCStatementExtension;
import org.ejbca.util.cert.SubjectDirAttrExtension;
import org.ejbca.util.keystore.KeyTools;

import com.novell.ldap.LDAPDN;

/**
 * Tests the CertTools class .
 * 
 * @version $Id$
 */
public class TestCertTools extends TestCase {
	private static Logger log = Logger.getLogger(TestCertTools.class);
	private static byte[] testcert = Base64
			.decode(("MIIDATCCAmqgAwIBAgIIczEoghAwc3EwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
					+ "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAzMDky"
					+ "NDA2NDgwNFoXDTA1MDkyMzA2NTgwNFowMzEQMA4GA1UEAxMHcDEydGVzdDESMBAG"
					+ "A1UEChMJUHJpbWVUZXN0MQswCQYDVQQGEwJTRTCBnTANBgkqhkiG9w0BAQEFAAOB"
					+ "iwAwgYcCgYEAnPAtfpU63/0h6InBmesN8FYS47hMvq/sliSBOMU0VqzlNNXuhD8a"
					+ "3FypGfnPXvjJP5YX9ORu1xAfTNao2sSHLtrkNJQBv6jCRIMYbjjo84UFab2qhhaJ"
					+ "wqJgkQNKu2LHy5gFUztxD8JIuFPoayp1n9JL/gqFDv6k81UnDGmHeFcCARGjggEi"
					+ "MIIBHjAPBgNVHRMBAf8EBTADAQEAMA8GA1UdDwEB/wQFAwMHoAAwOwYDVR0lBDQw"
					+ "MgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDBAYIKwYBBQUHAwUGCCsGAQUF"
					+ "BwMHMB0GA1UdDgQWBBTnT1aQ9I0Ud4OEfNJkSOgJSrsIoDAfBgNVHSMEGDAWgBRj"
					+ "e/R2qFQkjqV0pXdEpvReD1eSUTAiBgNVHREEGzAZoBcGCisGAQQBgjcUAgOgCQwH"
					+ "Zm9vQGZvbzASBgNVHSAECzAJMAcGBSkBAQEBMEUGA1UdHwQ+MDwwOqA4oDaGNGh0"
					+ "dHA6Ly8xMjcuMC4wLjE6ODA4MC9lamJjYS93ZWJkaXN0L2NlcnRkaXN0P2NtZD1j"
					+ "cmwwDQYJKoZIhvcNAQEFBQADgYEAU4CCcLoSUDGXJAOO9hGhvxQiwjGD2rVKCLR4"
					+ "emox1mlQ5rgO9sSel6jHkwceaq4A55+qXAjQVsuy76UJnc8ncYX8f98uSYKcjxo/"
					+ "ifn1eHMbL8dGLd5bc2GNBZkmhFIEoDvbfn9jo7phlS8iyvF2YhC4eso8Xb+T7+BZ"
					+ "QUOBOvc=").getBytes());

	private static byte[] guidcert = Base64
			.decode(("MIIC+zCCAmSgAwIBAgIIBW0F4eGmH0YwDQYJKoZIhvcNAQEFBQAwMTERMA8GA1UE"
					+ "AxMIQWRtaW5DQTExDzANBgNVBAoTBkFuYVRvbTELMAkGA1UEBhMCU0UwHhcNMDQw"
					+ "OTE2MTc1NzQ1WhcNMDYwOTE2MTgwNzQ1WjAyMRQwEgYKCZImiZPyLGQBARMEZ3Vp"
					+ "ZDENMAsGA1UEAxMER3VpZDELMAkGA1UEBhMCU0UwgZ8wDQYJKoZIhvcNAQEBBQAD"
					+ "gY0AMIGJAoGBANdjsBcLJKUN4hzJU1p3cqaXhPgEjGul62/3xv+Gow+7oOYePcK8"
					+ "bM5VO4zdQVWEhuGOZFaZ70YbXhei4F9kvqlN7xuG47g7DNZ0/fnRzvGY0BHmIR4Y"
					+ "/U87oMEDa2Giy0WTjsmT14uzy4luFgqb2ZA3USGcyJ9hoT6j1WDyOxitAgMBAAGj"
					+ "ggEZMIIBFTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDA7BgNVHSUENDAy"
					+ "BggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDBQYIKwYBBQUH"
					+ "AwcwHQYDVR0OBBYEFJlDddj88zI7tz3SPfdig0gw5IWvMB8GA1UdIwQYMBaAFI1k"
					+ "9WhE1WXpeezZx/kM0qsoZyqVMHgGA1UdEQRxMG+BDGd1aWRAZm9vLmNvbYIMZ3Vp"
					+ "ZC5mb28uY29thhRodHRwOi8vZ3VpZC5mb28uY29tL4cECgwNDqAcBgorBgEEAYI3"
					+ "FAIDoA4MDGd1aWRAZm9vLmNvbaAXBgkrBgEEAYI3GQGgCgQIEjRWeJCrze8wDQYJ"
					+ "KoZIhvcNAQEFBQADgYEAq39n6CZJgJnW0CH+QkcuU5F4RQveNPGiJzIJxUeOQ1yQ"
					+ "gSkt3hvNwG4kLBmmwe9YLdS83dgNImMWL/DgID/47aENlBNai14CvtMceokik4IN"
					+ "sacc7x/Vp3xezHLuBMcf3E3VSo4FwqcUYFmu7Obke3ebmB08nC6gnQHkzjNsmQw=")
					.getBytes());

	private static byte[] altNameCert = Base64
			.decode(("MIIDDzCCAfegAwIBAgIIPiL0klmu1uIwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
					+ "AxMIQWRtaW5DQTExFTATBgNVBAoTDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw"
					+ "HhcNMDUwODAyMTAxOTQ5WhcNMDcwODAyMTAyOTQ5WjAsMQwwCgYDVQQDEwNmb28x"
					+ "DzANBgNVBAoTBkFuYVRvbTELMAkGA1UEBhMCU0UwXDANBgkqhkiG9w0BAQEFAANL"
					+ "ADBIAkEAmMVWkkEMLbDNoB/NG3kJ22eC18syXqaHWRWc4DldFeCMGeLzfB2NklNv"
					+ "hmr2kgIJcK+wyFpMkYm46dSMOrvovQIDAQABo4HxMIHuMAwGA1UdEwEB/wQCMAAw"
					+ "DgYDVR0PAQH/BAQDAgWgMDsGA1UdJQQ0MDIGCCsGAQUFBwMBBggrBgEFBQcDAgYI"
					+ "KwYBBQUHAwQGCCsGAQUFBwMFBggrBgEFBQcDBzAdBgNVHQ4EFgQUIV/Fck/+UVnw"
					+ "tJigtZIF5OuuhlIwHwYDVR0jBBgwFoAUB/2KRYNOZxRDkJ5oChjNeXgwtCcwUQYD"
					+ "VR0RBEowSIEKdG9tYXNAYS5zZYIId3d3LmEuc2WGEGh0dHA6Ly93d3cuYS5zZS+H"
					+ "BAoBAQGgGAYKKwYBBAGCNxQCA6AKDAhmb29AYS5zZTANBgkqhkiG9w0BAQUFAAOC"
					+ "AQEAfAGJM0/s+Yi1Ewmvt9Z/9w8X/T/02bF8P8MJG2H2eiIMCs/tkNhnlFGYYGhD"
					+ "Km8ynveQZbdYvKFioOr/D19gMis/HNy9UDfOMrJdeGWiwxUHvKKbtcSlOPH3Hm0t"
					+ "LSKomWdKfjTksfj69Tf01S0oNonprvwGxIdsa1uA9BC/MjkkPt1qEWkt/FWCfq9u"
					+ "8Xyj2tZEJKjLgAW6qJ3ye81pEVKHgMmapWTQU2uI1qyEPYxoT9WkQtSObGI1wCqO"
					+ "YmKglnd5BIUBPO9LOryyHlSRTID5z0UgDlrTAaNYuN8QOYF+DZEQxm4bSXTDooGX"
					+ "rHjSjn/7Urb31CXWAxq0Zhk3fg==").getBytes());

	private static byte[] altNameCertWithDirectoryName = Base64
			.decode(("MIIFkjCCBPugAwIBAgIIBzGqGNsLMqwwDQYJKoZIhvcNAQEFBQAwWTEYMBYGA1UEAwwPU1VCX0NBX1dJTkRPV1MzMQ8wDQYDVQQLEwZQS0lHVkExHzAdBgNVBAoTFkdlbmVyYWxpdGF0IFZhbGVuY2lhbmExCzAJBgNVBAYTAkVTMB4XDTA2MDQyMTA5NDQ0OVoXDTA4MDQyMDA5NTQ0OVowcTEbMBkGCgmSJomT8ixkAQETC3Rlc3REaXJOYW1lMRQwEgYDVQQDEwt0ZXN0RGlyTmFtZTEOMAwGA1UECxMFbG9nb24xHzAdBgNVBAoTFkdlbmVyYWxpdGF0IFZhbGVuY2lhbmExCzAJBgNVBAYTAkVTMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCDLxMhz40RxCm21HoCBNa9x1UyPmhVkPdtt2V7dixgjOYz+ffKeebjn/jSd4nfXgd7fxpzezB8t673F2OtC3ENl1zek5Msj2KoinVu8vvZ78KMRq/H1rDFguhjSL0o19Cpob0qQFB/ukPZMNoKBNnMVnR1C4juB1eJVXWmHyJxIwIDAQABo4IDSTCCA0UwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwMwYDVR0lBCwwKgYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDBwYKKwYBBAGCNxQCAjAdBgNVHQ4EFgQUZz4hrh3dr6VWvEbAPe8pg7szNi4wHwYDVR0jBBgwFoAUTuOaap9UBpQ8dqwOufYoOQucfUowXAYDVR0RBFUwU6QhMB8xHTAbBgNVBAMMFHRlc3REaXJOYW1lfGRpcnxuYW1loC4GCisGAQQBgjcUAgOgIAwedGVzdERpck5hbWVAamFtYWRvci5wa2kuZ3ZhLmVzMIIBtgYDVR0gBIIBrTCCAakwggGlBgsrBgEEAb9VAwoBADCCAZQwggFeBggrBgEFBQcCAjCCAVAeggFMAEMAZQByAHQAaQBmAGkAYwBhAGQAbwAgAHIAZQBjAG8AbgBvAGMAaQBkAG8AIABkAGUAIABFAG4AdABpAGQAYQBkACAAZQB4AHAAZQBkAGkAZABvACAAcABvAHIAIABsAGEAIABBAHUAdABvAHIAaQBkAGEAZAAgAGQAZQAgAEMAZQByAHQAaQBmAGkAYwBhAGMAaQDzAG4AIABkAGUAIABsAGEAIABDAG8AbQB1AG4AaQB0AGEAdAAgAFYAYQBsAGUAbgBjAGkAYQBuAGEAIAAoAFAAbAAuACAATQBhAG4AaQBzAGUAcwAgADEALgAgAEMASQBGACAAUwA0ADYAMQAxADAAMAAxAEEAKQAuACAAQwBQAFMAIAB5ACAAQwBQACAAZQBuACAAaAB0AHQAcAA6AC8ALwB3AHcAdwAuAGEAYwBjAHYALgBlAHMwMAYIKwYBBQUHAgEWJGh0dHA6Ly93d3cuYWNjdi5lcy9sZWdpc2xhY2lvbl9jLmh0bTBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vemFyYXRob3MuamFtYWRvci5ndmEuZXMvU1VCX0NBX1dJTkRPV1MzLmNybDBTBggrBgEFBQcBAQRHMEUwQwYIKwYBBQUHMAGGN2h0dHA6Ly91bGlrLnBraS5ndmEuZXM6ODA4MC9lamJjYS9wdWJsaWN3ZWIvc3RhdHVzL29jc3AwDQYJKoZIhvcNAQEFBQADgYEASofgaj06BOE847RTEgVba52lmPWADgeWxKHZAk1t9LdNzuFJ8B/SC3gi0rsAA/lQGSd4WzPbkmJKkVZ6Q9ybpqg4AJRaIZBkoQw1KNXPYAcgt5XLeIhUACdKIPhfPQr+vQtaC1wi5xV8EBCLpLmpzN9bpZdze/724UB4Y94KhII=")
					.getBytes());

	/** The reference certificate from RFC3739 */
	private static byte[] qcRefCert = Base64
			.decode(("MIIDEDCCAnmgAwIBAgIESZYC0jANBgkqhkiG9w0BAQUFADBIMQswCQYDVQQGEwJE"
					+ "RTE5MDcGA1UECgwwR01EIC0gRm9yc2NodW5nc3plbnRydW0gSW5mb3JtYXRpb25z"
					+ "dGVjaG5payBHbWJIMB4XDTA0MDIwMTEwMDAwMFoXDTA4MDIwMTEwMDAwMFowZTEL"
					+ "MAkGA1UEBhMCREUxNzA1BgNVBAoMLkdNRCBGb3JzY2h1bmdzemVudHJ1bSBJbmZv"
					+ "cm1hdGlvbnN0ZWNobmlrIEdtYkgxHTAMBgNVBCoMBVBldHJhMA0GA1UEBAwGQmFy"
					+ "emluMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDc50zVodVa6wHPXswg88P8"
					+ "p4fPy1caIaqKIK1d/wFRMN5yTl7T+VOS57sWxKcdDzGzqZJqjwjqAP3DqPK7AW3s"
					+ "o7lBG6JZmiqMtlXG3+olv+3cc7WU+qDv5ZXGEqauW4x/DKGc7E/nq2BUZ2hLsjh9"
					+ "Xy9+vbw+8KYE9rQEARdpJQIDAQABo4HpMIHmMGQGA1UdCQRdMFswEAYIKwYBBQUH"
					+ "CQQxBBMCREUwDwYIKwYBBQUHCQMxAxMBRjAdBggrBgEFBQcJATERGA8xOTcxMTAx"
					+ "NDEyMDAwMFowFwYIKwYBBQUHCQIxCwwJRGFybXN0YWR0MA4GA1UdDwEB/wQEAwIG"
					+ "QDASBgNVHSAECzAJMAcGBSskCAEBMB8GA1UdIwQYMBaAFAABAgMEBQYHCAkKCwwN"
					+ "Dg/+3LqYMDkGCCsGAQUFBwEDBC0wKzApBggrBgEFBQcLAjAdMBuBGW11bmljaXBh"
					+ "bGl0eUBkYXJtc3RhZHQuZGUwDQYJKoZIhvcNAQEFBQADgYEAj4yAu7LYa3X04h+C"
					+ "7+DyD2xViJCm5zEYg1m5x4znHJIMZsYAU/vJJIJQkPKVsIgm6vP/H1kXyAu0g2Ep"
					+ "z+VWPnhZK1uw+ay1KRXw8rw2mR8hQ2Ug6QZHYdky2HH3H/69rWSPp888G8CW8RLU"
					+ "uIKzn+GhapCuGoC4qWdlGLWqfpc=").getBytes());

	private static byte[] qcPrimeCert = Base64
			.decode(("MIIDMDCCAhigAwIBAgIIUDIxBvlO2qcwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
					+ "AxMIQWRtaW5DQTExFTATBgNVBAoTDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw"
					+ "HhcNMDYwMTIyMDgxNTU0WhcNMDgwMTIyMDgyNTU0WjAOMQwwCgYDVQQDEwNxYzIw"
					+ "gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKkuPOqOEWCJH9xb11sS++vfKb/z"
					+ "gHf2clwyf2vSFWTSDzQHOa2j5rwZ/F23X/mZl96fFAIfTBmr5dCwt0xAXZvTcKfO"
					+ "RAcKl7ZBXvsAYvwl1KIUpA8NqEbgjwA+OaTdND2vpAhII7PoU4CkoNajy44EuL3Y"
					+ "xP6KNWTMiks9KP5vAgMBAAGjgewwgekwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8E"
					+ "BAMCBPAwJwYDVR0lBCAwHgYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDBzAd"
					+ "BgNVHQ4EFgQUZsj/dUVp1FmOJpYZ2j5fYKIdXYowHwYDVR0jBBgwFoAUs8UBsa9O"
					+ "S1c8/I07DHYFJp0po0AwYAYIKwYBBQUHAQMEVDBSMCMGCCsGAQUFBwsBMBcGAykB"
					+ "AjAQgQ5xY0BwcmltZWtleS5zZTAIBgYEAI5GAQEwFwYGBACORgECMA0TA1NFSwID"
					+ "AMNQAgEAMAgGBgQAjkYBBDANBgkqhkiG9w0BAQUFAAOCAQEAjmL27XY5Wt0/axsI"
					+ "PbtcfrJ6xEm5PlYabM+T3I6lksov6Rz1+/n/L1S5poGPG8iOdJCExcnR0HbNkeB+"
					+ "2oPltqSaxyoSfGugVn/Oufz2BfFd7OCWe14dPsA181oC7/nq+mzhBpQ7App9JirA"
					+ "aeJQrcRDNK7vVOmg2LZ2oSYno/TuRTFq0GxsEVjEdzAxpAxY7N8ff6gY7IHd7+hc"
					+ "4GiFY+NnNp9Dvf6mOYTXLxsOc+093S7uK2ohhq99aYCkzJmrngtrImtKi0y/LMjq"
					+ "oviMCQmzMLY2Ifcw+CsOyQZx7nxwafZ7BAzm6vIvSeiIe3VlskRGzYDM66NJJNNo"
					+ "C2HsPA==").getBytes());

	private static byte[] aiaCert = Base64
			.decode(("MIIDYDCCAkigAwIBAgIIFlJveCmyW4owDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
					+ "AwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw"
					+ "HhcNMDgxMDIwMDkxOTM0WhcNMDkxMDIwMDkxOTM0WjA9MQwwCgYDVQQDDANhaWEx"
					+ "DDAKBgNVBAoMA0ZvbzESMBAGA1UEBwwJU3RvY2tob2xtMQswCQYDVQQGEwJTRTCB"
					+ "nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAlYyB3bj/Tmf1FGoPWXCJneWYd9Th"
					+ "gPi4ET5pL0JNGwOsuH6cPngIIN33fn2JiiBnBkNm7AKHx8Qt9BH4VPJRs/GdsVGO"
					+ "ECmpGmtY6WMYmxMC99KNiXSrRQjPGZeemMj6T1KyxhKljZr8Q92tmc9YA1VFMeqA"
					+ "zNzjEGBDj/h2gBcCAwEAAaOB7TCB6jB5BggrBgEFBQcBAQRtMGswKgYIKwYBBQUH"
					+ "MAKGHmh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9jYUlzc3VlcjA9BggrBgEFBQcwAYYx"
					+ "aHR0cDovL2xvY2FsaG9zdDo4MDgwL2VqYmNhL3B1YmxpY3dlYi9zdGF0dXMvb2Nz"
					+ "cDAdBgNVHQ4EFgQUF4YFO3HJordNZlJ/7T1L1KfqgTMwDAYDVR0TAQH/BAIwADAf"
					+ "BgNVHSMEGDAWgBSSeB41+0/rZ+2/qiX7X4bvrVKjWDAPBgkrBgEFBQcwAQUEAgUA"
					+ "MA4GA1UdDwEB/wQEAwIGwDANBgkqhkiG9w0BAQUFAAOCAQEAU1BHlD6TpSnmblU4"
					+ "jhECKZfU7P5JBvZMkUQH54U+lubhM4yeymaF1NJylOusLKxZzEd6+iLXkvVCBKPT"
					+ "3aVWUI5DO4D0RW9Lia6QFiRuI8d7a39f1663ODuwpjiccuehrmF3e+P7uCyjqhhT"
					+ "g3uXQh2dXcv3DbvU2lfSVXRnuOz+K0ZUMAW96nsCeT41viM6w4x18zZeb+Px8RL9"
					+ "swtcYdObNK0qmjZ4X+DcbdGRRrh8kr9GPLHYqtVLRM6z6hH3n54WJzojeIebKCsY"
					+ "MoHGmOJkaIcFRXfneXrId1/k7b1QdOagGjvLkgw3pi/7k6vOJn+DrudNMFmsNpVY"
					+ "fkrayw==").getBytes());

	private static byte[] subjDirAttrCert = Base64
			.decode(("MIIGmTCCBYGgAwIBAgIQGMYCpWmOBXXOL2ODrM8FHzANBgkqhkiG9w0BAQUFADBx"
					+ "MQswCQYDVQQGEwJUUjEoMCYGA1UEChMfRWxla3Ryb25payBCaWxnaSBHdXZlbmxp"
					+ "Z2kgQS5TLjE4MDYGA1UEAxMvZS1HdXZlbiBFbGVrdHJvbmlrIFNlcnRpZmlrYSBI"
					+ "aXptZXQgU2FnbGF5aWNpc2kwHhcNMDYwMzI4MDAwMDAwWhcNMDcwMzI4MjM1OTU5"
					+ "WjCCAR0xCzAJBgNVBAYTAlRSMSgwJgYDVQQKDB9FbGVrdHJvbmlrIEJpbGdpIEd1"
					+ "dmVubGlnaSBBLlMuMQ8wDQYDVQQLDAZHS05FU0kxFDASBgNVBAUTCzIyOTI0NTQ1"
					+ "MDkyMRswGQYDVQQLDBJEb2d1bSBZZXJpIC0gQlVSU0ExIjAgBgNVBAsMGURvZ3Vt"
					+ "IFRhcmloaSAtIDAxLjA4LjE5NzcxPjA8BgNVBAsMNU1hZGRpIFPEsW7EsXIgLSA1"
					+ "MC4wMDAgWVRMLTIuMTYuNzkyLjEuNjEuMC4xLjUwNzAuMS4yMRcwFQYDVQQDDA5Z"
					+ "QVPEsE4gQkVDRU7EsDEjMCEGCSqGSIb3DQEJARYUeWFzaW5AdHVya2VrdWwuYXYu"
					+ "dHIwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKaJXVLvXC7qyjiqTAlM582X"
					+ "GPdQJxUfRxgTm6jlBZKtEhbWN5hbH4ASJTzmXWryGricejdKM+JBJECFdelyWPHs"
					+ "UkEL/U0uft3KLIdYo72oTibaL3j4vkEhjyubikSdl9CywkY6WS8nV9JNc66QOYxE"
					+ "5ZdE5CR19ScIYcOh7YpxAgMBAAGjggMBMIIC/TAJBgNVHRMEAjAAMAsGA1UdDwQE"
					+ "AwIGwDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLmUtZ3V2ZW4uY29tL0Vs"
					+ "ZWt0cm9uaWtCaWxnaUd1dmVubGlnaUFTR0tORVNJL0xhdGVzdENSTC5jcmwwHwYD"
					+ "VR0jBBgwFoAUyT6jfNNisqvczhIzwmTXZTTyfrowggEcBgNVHSAEggETMIIBDzCB"
					+ "/wYJYIYYAwABAQECMIHxMDYGCCsGAQUFBwIBFipodHRwczovL3d3dy5lLWd1dmVu"
					+ "LmNvbS9lLWltemEvYmlsZ2lkZXBvc3UwgbYGCCsGAQUFBwICMIGpGoGmQnUgc2Vy"
					+ "dGlmaWthLCA1MDcwIHNhef1s/SBFbGVrdHJvbmlrIN1temEgS2FudW51bmEgZ/Zy"
					+ "ZSBuaXRlbGlrbGkgZWxla3Ryb25payBzZXJ0aWZpa2Fk/XIuIE9JRDogMi4xNi43"
					+ "OTIuMS42MS4wLjEuNTA3MC4xLjEgLSBPSUQ6IDAuNC4wLjE0NTYuMS4yIC0gT0lE"
					+ "OiAwLjQuMC4xODYyLjEuMTALBglghhgDAAEBBQQwgaEGCCsGAQUFBwEDBIGUMIGR"
					+ "MHYGCCsGAQUFBwsBMGoGC2CGGAE9AAGnTgEBMFuGWUJ1IFNlcnRpZmlrYSA1MDcw"
					+ "IHNhef1s/SBFbGVrdHJvbmlrIN1temEgS2FudW51bmEgZ/ZyZSBuaXRlbGlrbGkg"
					+ "ZWxla3Ryb25payBzZXJ0aWZpa2Fk/XIuMBcGBgQAjkYBAjANEwNZVEwCAwDDUAIB"
					+ "ADB2BggrBgEFBQcBAQRqMGgwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmUtZ3V2"
					+ "ZW4uY29tMCIGCCsGAQUFBzAChhZodHRwOi8vd3d3LmUtZ3V2ZW4uY29tMB0GAytv"
					+ "DoYWaHR0cDovL3d3dy5lLWd1dmVuLmNvbTAbBgNVHQkEFDASMBAGCCsGAQUFBwkE"
					+ "MQQTAlRSMBEGCWCGSAGG+EIBAQQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEA3yVY"
					+ "rURakBcrfv1hJjhDg7+ylCjXf9q6yP2E03kG4t606TLIyqWoqGkrndMtanp+a440"
					+ "rLPIe456XfRJBilj99H0NjzKACAVfLMTL8h/JBGLDYJJYA1S8PzBnMLHA8dhfBJ7"
					+ "StYEPM9BKW/WuBfOOdBNrRZtYKCHwGK2JANfM/JlfzOyG4A+XDQcgjiNoosjes1P"
					+ "qUHsaccIy0MM7FLMVV0HJNNQ84N9CuKIrBSSWopOudkajVqNtI3+FCcy+yXiH6LX"
					+ "fmpHZ346zprcafcjQmAiKfzPSljruvGDIVI3WN7S7WOMrx6MDq54626cZzQl9GFT"
					+ "D1gNo3fjOFhK33DY1Q==").getBytes());

	private static byte[] subjDirAttrCert2 = Base64
			.decode(("MIIEsjCCA5qgAwIBAgIIFsYK/Jx7XEEwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
					+ "AxMIQWRtaW5DQTExFTATBgNVBAoTDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw"
					+ "HhcNMDYwNTMwMDcxNjU2WhcNMDgwNTI5MDcyNjU2WjA5MRkwFwYDVQQDExBUb21h"
					+ "cyBHdXN0YXZzc29uMQ8wDQYDVQQKEwZGb29PcmcxCzAJBgNVBAYTAlNFMIGfMA0G"
					+ "CSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvhUYzNVW6iG5TpYi2Dr9VX37g05jcGEyP"
					+ "Lix05oxs3FnzPUf6ykxGy4nUYO12PfC6u9Gh+zelFfg6nKNQqYI48D4ufJc928Nx"
					+ "dZQZi41UmnFT5UXn3JcG4DQe0wZp+BKCch/UbtRjuE6iNxH24R//8W4wXc1R++FG"
					+ "5V6CQzHxXwIDAQABo4ICQjCCAj4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMC"
					+ "BPAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQ54I1p"
					+ "TGNwAeQEdnmcjNT+XMMjsjAfBgNVHSMEGDAWgBRzBo+b/XQZqq0DU6J10x17GoKS"
					+ "sDBMBgNVHSAERTBDMEEGAykBATA6MB4GCCsGAQUFBwICMBIeEABGAPYA9gBCAGEA"
					+ "cgDkAOQwGAYIKwYBBQUHAgEWDGh0dHA6LzExMS5zZTBuBgNVHR8EZzBlMGOgYaBf"
					+ "hl1odHRwOi8vbG9jYWxob3N0OjgwODAvZWpiY2EvcHVibGljd2ViL3dlYmRpc3Qv"
					+ "Y2VydGRpc3Q/Y21kPWNybCZpc3N1ZXI9Q049VGVzdENBLE89QW5hVG9tLEM9U0Uw"
					+ "TQYIKwYBBQUHAQEEQTA/MD0GCCsGAQUFBzABhjFodHRwOi8vbG9jYWxob3N0Ojgw"
					+ "ODAvZWpiY2EvcHVibGljd2ViL3N0YXR1cy9vY3NwMDoGCCsGAQUFBwEDBC4wLDAg"
					+ "BggrBgEFBQcLAjAUMBKBEHJhQGNvbW1maWRlcy5jb20wCAYGBACORgEBMHYGA1Ud"
					+ "CQRvMG0wEAYIKwYBBQUHCQUxBBMCU0UwEAYIKwYBBQUHCQQxBBMCU0UwDwYIKwYB"
					+ "BQUHCQMxAxMBTTAXBggrBgEFBQcJAjELEwlTdG9ja2hvbG0wHQYIKwYBBQUHCQEx"
					+ "ERgPMTk3MTA0MjUxMjAwMDBaMA0GCSqGSIb3DQEBBQUAA4IBAQA+vgNnGjw29xEs"
					+ "cnJi7wInUBvtTzQ4+SVSBPTzNA/ZEk+CJVsr/2xbPl+SShZ0SHObj9un1kwKst4n"
					+ "zcNqsnBorrluM92Z5gYwDN3mRGF0szbYEshr/KezMhY2MdXkE+i3nEx6awdemuCG"
					+ "g+LAfL4ODLAzAJJI4MfF+fz0IK7Zeobo1aVGS6Ii9sEnDdQOsLbdfHBNccrT353d"
					+ "NAwxPGnfunGBQ+Los6vjDApy/szMT32NFJDe4WTmkDxqYJQqQjhdrHTxpFEr0VQB"
					+ "s7KRRCYjga/Z52XytwwDBLFM9CPZJfyKxZTV9I9i6e0xSn2xEW8NRplY1HOKa/2B"
					+ "VzvWW9G5").getBytes());

	private static byte[] krb5principalcert = Base64.decode(("MIIDIzCCAgugAwIBAgIIdSCEXyq32cIwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
			+"AwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw"
			+"HhcNMDgxMDIzMTEyMzAzWhcNMTgwODE2MTQ1MzA2WjAqMQ0wCwYDVQQDDARrcmIx"
			+"MQwwCgYDVQQKDANGb28xCzAJBgNVBAYTAlNFMIGfMA0GCSqGSIb3DQEBAQUAA4GN"
			+"ADCBiQKBgQCYkX8BcUXezxG8eKsQT0+lxjUZLeg7EQk0hdiKGsKxhS6BmLpeBOGs"
			+"HwZgn70zhJj9XLtCQ/o8RJatL/lFtHpVX+RnRdckKDOooLUguxSiO5TK7HlQpsFG"
			+"8AB7m/jCkIGarh5x6LSL5t1VAMyPh9DFBMXPuC5xAb5SGa6LRXoZ/QIDAQABo4HD"
			+"MIHAMB0GA1UdDgQWBBTUIo6ZQUrVKoI5GPifVn3KbUGAljAMBgNVHRMBAf8EAjAA"
			+"MB8GA1UdIwQYMBaAFJJ4HjX7T+tn7b+qJftfhu+tUqNYMA4GA1UdDwEB/wQEAwIF"
			+"oDAnBgNVHSUEIDAeBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMEMDcGA1Ud"
			+"EQQwMC6gLAYGKwYBBQICoCIwIKAHGwVQLkNPTaEVMBOgAwIBAKEMMAobA2ZvbxsD"
			+"YmFyMA0GCSqGSIb3DQEBBQUAA4IBAQBgQpzPpCUDY6P0XePJSFJ2MGBhgMOVB4SL"
			+"iHP9biEmqcqELWQcUL5Ylf+/JYxg1kBnk2ZtALgt0adi0ZiZPbM2F5Oq9ZxxB2nY"
			+"Alat0RwZIY8wAR0DRNXiEs4TMu5LqzvD1U6+vaHYraePBLExo2oxG9TI7gQjj2X+"
			+"KSxEzOf3+npWo/G7ooDvKpN+w3J//kF4vdM3SQtHQaBkIuCU05Jy16AhvIkLQzq5"
			+"+a1UI5lIKun3C6NWCSZrE5fFuoax7D+Ofw1Bdxkhvk7DUlHVPdmxb/0hpx8aO64D"
			+"J626d8c1b25g9hSYslbo2geP2ohV40WW/R1ZjwX6Pd/ip5KuSSzv").getBytes());
	
	private static byte[] p10ReqWithAltNames = Base64
			.decode(("MIICtDCCAZwCAQAwNDELMAkGA1UEBhMCU0UxDDAKBgNVBAoTA1JQUzEXMBUGA1UE"
					+ "AxMOMTAuMjUyLjI1NS4yMzcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB"
					+ "AQC45+Dh1dO/qaZR2TLnWB44wmYXvBuZ5sGXotlLvuRR09DGlSyPrTG/OVg4xVZa"
					+ "AzNMpWCyk1OAl4qJkmzrnQa/Tq6Hv6Y8QrZNSAJooL+kHmFSD9h8tyM9nBkpb90l"
					+ "o+qbXeFmB3II0KJjGXiXZVSKwUsjYRSzf9hfVz4U7ZwwmH9vMFNwuOIsAR9O5CTr"
					+ "8ofsshze9bxJpKY6/iyaEhQDoNl9jyxsZ1NuyNme3w1yoeGP5OXYcSVVY9cW4ze8"
					+ "o5ZE4jTy1Q8U41OHiG3TevMvJ7l+/Ps+xyu3Qi68Lajeimemf118M0eqAY26Xiw2"
					+ "wS8CCbj6UmUjcem3XOZhSfkZAgMBAAGgOzA5BgkqhkiG9w0BCQ4xLDAqMCgGA1Ud"
					+ "EQQhMB+CF29ydDMta3J1Lm5ldC5wb2xpc2VuLnNlhwQK/P/tMA0GCSqGSIb3DQEB"
					+ "BQUAA4IBAQCzAPsZdMqhPwCGpnq/Eywm5KQ4zYLuP8dQVdgvo4Wca2w4QxxjPlVI"
					+ "X/yyXLhA1CpiKq4PtkpTBpJiByowj8g/7Q/pLY/EQcfYOrut7CMx1FzmwghZ2lUn"
					+ "DDhFw2hD7TcmoAZpr4neXYR4HbaFpBc39nlqDa4XGi8J7d9AU4iaQE53LC3WzIq1"
					+ "/3ZCXboQAoeLMoPCDvzAiXKDBApMMzrBwhgdsiOe5k1e6jlpURsbuhiKs+0FxtMp"
					+ "snKPO0WbwXFyFTSWoKRH5rHrpD6lybn7c0uPkaQzrLoIRMld4osqeaImfZuJztZy"
					+ "C0elzlLYWFbX6zHEqvsUAZy/8Khgyw5Q").getBytes());

	private static byte[] p10ReqWithAltNames2 = Base64
			.decode(("MIIBMzCB3gIBADAzMREwDwYDVQQDDAhzY2VwdGVzdDERMA8GA1UECgwIUHJpbWVL"
					+ "ZXkxCzAJBgNVBAYTAlNFMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIMasNAoxA9N"
					+ "6UknbjigXz5tJWWydLoVSQFUxcJM8cR4Kfb2bRLh3RDqCVyJQ0XITFUnmIJFU9Z8"
					+ "1W+nw1Gx8b0CAwEAAaBGMBUGCSqGSIb3DQEJBzEIDAZmb28xMjMwLQYJKoZIhvcN"
					+ "AQkOMSAwHjAcBgNVHREEFTATggtmb28uYmFyLmNvbYcECgAAATANBgkqhkiG9w0B"
					+ "AQUFAANBADUO2tpAkxaeB/2zY9wsfcwE5hGvcuA0oJwXlcMq1wm32MJFV1G9JJQI"
					+ "Exz4OC1eT1LH/6i5SU8Op3VOKVLpTTo=").getBytes());

	private static byte[] cvccert = Base64
			.decode(("fyGCAWF/ToHZXykBAEIKU0VSUFMxMDExMH9JgZUGCgQAfwAHAgICAQGBgYEAk4Aq"
					+ "LqYXchIouF9yBv/2hFnf5N65hdpvQPUdfH1k2qnHAlOL5DYYlKCBh8YFCC2RZD+K"
					+ "nJ99cHxh8oxh28U23Z/MqTOKv5tR8JIUUm3G3Hjj2erVVTEJ49MqLzsyVGfw4yCu"
					+ "YRdwBYFWJu2t6PcS5KPnpNtbNdBzrDJAqxPAsO2CAwEAAV8gClNFUlBTMTAxMTB/"
					+ "TA4GCQQAfwAHAwECAVMBw18lBgAIAAUABV8kBgEAAAUABV83gYB88jfXZ3njYpuD"
					+ "4fpS6BV53y9+iz3KAQM/74LPMI49elGtcAVyMn1EMn/bU4MeMARfv3Njd2Go4ZhM"
					+ "j5xuY2Pvktz3Dq4ogjkgqAJqqIvG+M9KXh9XAv2m2wjmsueKbXUJ8TpJR87k4o97"
					+ "buZXbuStDOb5FibhxyVgWIxuCn8quQ==").getBytes());

	private static byte[] cvcreqrenew = Base64.decode(("Z4IBtn8hggFmf06CASZfKQEAQg5TRUlTQlBPT0wwMDAwNn9Jgf0GCgQAfwAHAgIC"+
			"AgKBHNfBNKomQ2aGKhgwJXXR14ewnwdXl9qJ9X7IwP+CHGil5iypzmwcKZgDpsFT"+
			"C1FOGCrYsAQqWcrSn0ODHCWA9jzP5EE4hwcTsakjaeM+ITXSZtuzcjhsQAuEOQQN"+
			"kCmtLH5c9DQII7KofcaMnkzjF0webv3uEsB9WKpW93LAcm8kxrieTs2sJDVLnpnK"+
			"o/bTdhQCzYUc18E0qiZDZoYqGDAlddD7mNEWvEtt3ryjpaeTn4Y5BBQte2aU3YOQ"+
			"Ykf73/UluNQOpMlnHt9PXplomqhuAZ0QxwXb6TCG3rZJhVwe0wx0R1mqz3U+fJnU"+
			"hwEBXyAOU0VJU0JQT09MMDAwMDZfNzgErOAjPCoQ+WN8K6pzztZp+Mt6YGNkJzkk"+
			"WdLnvfPGZkEF0oUjcw+NjexaNCLOA0mCfu4oQwsjrUIOU0VJU0JQT09MMDAwMDVf"+
			"NzhSmH1c7YJhbLTRzwuSozUd9hlBHKEIfFqSUE9/FrbWXEtR+rHRYKAGu/nw8PAH"+
			"oM+HPMzMVVLDVg==").getBytes());

		private static byte[] cvcreq = Base64.decode(("fyGCAWZ/ToIBJl8pAQBCDlNFSVNCUE9PTDAwMDA1f0mB/QYKBAB/AAcCAgICAoEc"+
			"18E0qiZDZoYqGDAlddHXh7CfB1eX2on1fsjA/4IcaKXmLKnObBwpmAOmwVMLUU4Y"+
			"KtiwBCpZytKfQ4McJYD2PM/kQTiHBxOxqSNp4z4hNdJm27NyOGxAC4Q5BA2QKa0s"+
			"flz0NAgjsqh9xoyeTOMXTB5u/e4SwH1Yqlb3csBybyTGuJ5OzawkNUuemcqj9tN2"+
			"FALNhRzXwTSqJkNmhioYMCV10PuY0Ra8S23evKOlp5OfhjkEOwPDLflRVBj2iayW"+
			"VzpO2BICGO+PqFeuce1EZM4o1EIfLzoackPowabEMANfNltZvt5bWyzkZleHAQFf"+
			"IA5TRUlTQlBPT0wwMDAwNV83OEnwL+XYDhXqK/0fBuZ6lZV0HncoZyn3oo8MmaUL"+
			"2mNzpezLAoZMux0l5aYperrSDsuHw0zrf0yo").getBytes());
	
		private static byte[] cvccertchainroot = Base64
		.decode(("fyGCAmx/ToIBYl8pAQBCDlNFSFNNQ1ZDQTAwMDAxf0mCARUGCgQAfwAHAgICAQKB"+
			"ggEAyGju6NHTACB+pl2x27/VJVKuGBTgf98j3gQOyW5vDzXI7PkiwR1/ObPjFiuW"+
			"iBRH0WsPzHX7A3jysZr7IohLjy4oQMdP5z282/ZT4mBwlVu5pAEcHt2eHbpILwIJ"+
			"Hbv6130T+RoG/3bI/eHk9HWi3/ipVnwRX1CsylczFfdyPTMyGOJmmElT0GQgV8Rt"+
			"b5Us/Hz66qiUX67eRBrahJfwiVwawYzmZ5Rn9u/vXHQYeUh+lLja+H+kXof9ARuw"+
			"p5S09DO2VZWbbR2BZHk0IaNgo54Xoih+5c/nIA/2+j9Afdf+wuqmxqib5aPOMHO3"+
			"WOVmVMF84Xo2V+duIZ4b7KkRXYIDAQABXyAOU0VIU01DVkNBMDAwMDF/TA4GCQQA"+
			"fwAHAwECAVMBw18lBgAIAAUCBl8kBgEAAAUCBl83ggEAMiiqI+HF8DyhPfH8dTeU"+
			"4/0/DNnjZ2/Qy1a5GATWU04da+L2iWI8QclN64cw0l/zroBGyeq+flDKzVWnqril"+
			"HX/PD3/xoCEhZSfZ/1AQZBP39/t1lYZLJ36VeFwrsmvN8rq6RnNtR2CrDYDFkFRq"+
			"A6v9dNYMbnEDN7m8wD/DWM2fZr+loqznT1/egx+SBqUY+KnU6ntxQyw7gzL1DV9Z"+
			"OlyxjDaWY8i2Q/tcdDxdZYBBMgFhxivXV5ou2YiBZKKIlP2ots6P8TlSVwdyaHTI"+
			"8z8Hpvx1QcB2maOVn6IFAyq/X71p9Zb626YLhjaFO6v80SYnlefVu5Uir5n/HzpW"+
			"kg==").getBytes());

		private static byte[] cvccertchainsub = Base64
		.decode(("fyGCAeV/ToHcXykBAEIOU0VIU01DVkNBMDAwMDF/SYGUBgoEAH8ABwICAgECgYGA"+
			"rdRouw7ksS6M5kw28YkWAD350vbDlnPCmqsKPfKiNvDxowviWDUTn9Ai3xpTIzGO"+
			"cl40DqxYPA2X4XO52+r5ZUazsVyyx6F6XwznHdjUpDff4QFyG74Vjq7DDrCCKOzH"+
			"b0H6rNJFC5YEKI4wpEPou+3bq2jhLWkzU35EfydJHXWCAwEAAV8gClNFUlBTRFZF"+
			"WDJ/TA4GCQQAfwAHAwECAVMBgl8lBgAIAAYABV8kBgEAAAUCBl83ggEAbawFepay"+
			"gX+VrBOsGzbQCpG2mR1NrJbaNdBJcouWYTNzlDP/hRssU9/lTzHulRPupkarepAI"+
			"GMIDMOo3lNImlYlU8ZlaV6mbKRgWZVjtZmVgq+wLARS4dXNlHRJvS2AustfseGVr"+
			"kqJ0+UYo8x8UL13fB7VCSVqADnOnbemtvE1cIdFcIAqP1JLh91ACJ4lpoaAn10+g"+
			"5coIGGa01BYEDtiA++SFnRl7kYFykAZrs3eXq+zuPmOo9hr4JxLZuiN5DnIrZdLA"+
			"DWq7GeCFr6wCMg2jPuK9Kqvl06tqylVy4ravVHv58WvAxWFgyuezdRbyV7YAfVF3"+
			"tlcVDXa3R+mfYg==").getBytes());

		private static byte[] x509certchainsubsub = Base64
		.decode(("MIICSzCCAbSgAwIBAgIILiuXZS09/bQwDQYJKoZIhvcNAQEFBQAwNDEOMAwGA1UE"+
			"AwwFU3ViQ0ExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0UwHhcN"+
			"MDgwNjA1MTEyMTE4WhcNMTAwNjA1MTEyMDU0WjA3MREwDwYDVQQDDAhTdWJTdWJD"+
			"QTEVMBMGA1UECgwMRUpCQ0EgU2FtcGxlMQswCQYDVQQGEwJTRTCBnzANBgkqhkiG"+
			"9w0BAQEFAAOBjQAwgYkCgYEAq/bznrOJ/65Fmf2jFHq4wHrhbAuxl/SqwjGYsO+8"+
			"F2/DzdBYLEl5Ma0j+Nyrf1fF5/18MEGOjfdQvmkPGBs+k6IzErpLepR0hOufQTCS"+
			"+A74iEO9sNCm+r6MMFH/2JTIFC7r25YhXAagaw9yHDnc7H6gJZ9CpQ6dy+rv8Eks"+
			"6X0CAwEAAaNjMGEwHQYDVR0OBBYEFOC1jBwHPF+KoXDLytg5dvySL6bAMA8GA1Ud"+
			"EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUhyBsMvIXwRH0mDjLOv8i8H2VOVowDgYD"+
			"VR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUAA4GBADJKlJcndLXJPl6HFg52IiXy"+
			"nLcco+rIGx12vdBKk46tzVt883NZhypub5y21Qu5jFkArjr3sG2V3OuE4xdt1cy6"+
			"PexpDDZTuzpGVWvb5FW31RN+e/4fUozUBK+xExJVZ7xfpbO7JGcognAUUpstJzvO"+
			"Gd6Hb8EUQJnQuIfUjny4").getBytes());

		private static byte[] x509certchainsub = Base64
		.decode(("MIIC1zCCAb+gAwIBAgIISS6X7IKkCbYwDQYJKoZIhvcNAQEFBQAwQjERMA8GA1UE"+
			"AwwIQWRtaW5DQTExIDAeBgNVBAoMF0VKQkNBIFRvbWFzTGFwdG9wIE15U1FMMQsw"+
			"CQYDVQQGEwJTRTAeFw0wODA2MDUxMTIwNTRaFw0xMDA2MDUxMTIwNTRaMDQxDjAM"+
			"BgNVBAMMBVN1YkNBMRUwEwYDVQQKDAxFSkJDQSBTYW1wbGUxCzAJBgNVBAYTAlNF"+
			"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCCPW8wrgDDD0UCtr2AOl/3EDXV"+
			"AezYQFdeerdJactX8o8G/ORbgt8XiLp8n2SLYEUbsIxt6pYX4/eCudxeAUNDBap7"+
			"T7S5kgd8B+QytJi0uWvTdK7i0tjvx6Zudzn1ATk3JwiMFFUSsEEE/2bbMsTNMlC8"+
			"I8PgyRgrrBWiXXtDtQIDAQABo2MwYTAdBgNVHQ4EFgQUhyBsMvIXwRH0mDjLOv8i"+
			"8H2VOVowDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBSnW4ik+/9kkwub9avi"+
			"r63Lqvgv7jAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBACGGuToj"+
			"vmRXBQh5xcGwcYGrEFdL2zBJe6BwIrZWIPkjTcjY8ZAtMaaJBcPV8HJT1u4HmbUt"+
			"cYJ3E3V+zwfqMlSzJpk4YaMTup8lfsjg1AZUX3JXIkqN6ITyoJ80TqiinWWKA8i6"+
			"ueIyDegX3Z00ZWQo3CIy0rvbaejoncscsDOvcj1TusdAmQTQpUi5o0CTzxhwVtzL"+
			"yGQoMaoRi5QQzkC2M3LwIenIm+PbpMgmrCnD/4RldJe6eZl85ZlsrS5Y8PZkH/kb"+
			"jojskDzqeQ5kEkUWkV9AuNE9RIB6RcFVJhcAWdjWGCNsvxsByhdNsVIWXZ2oOi8x"+
			"nYD8LhXhCvDE6Tc=").getBytes());

		private static byte[] x509certchainroot = Base64
		.decode(("MIIDaTCCAlGgAwIBAgIIa10wLePiLM8wDQYJKoZIhvcNAQEFBQAwQjERMA8GA1UE"+
			"AwwIQWRtaW5DQTExIDAeBgNVBAoMF0VKQkNBIFRvbWFzTGFwdG9wIE15U1FMMQsw"+
			"CQYDVQQGEwJTRTAeFw0wNzEyMjcxNjM4NDdaFw0xNzEyMjQxNjM4NDdaMEIxETAP"+
			"BgNVBAMMCEFkbWluQ0ExMSAwHgYDVQQKDBdFSkJDQSBUb21hc0xhcHRvcCBNeVNR"+
			"TDELMAkGA1UEBhMCU0UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCN"+
			"HlBg12X4INZ/XuXsLAI/mLRgNNm68I95pjK0pqIwLht4/cNUYXS7+WRrG8XWJAJt"+
			"oo+vYzQmYtlwk115oA/y4T1bsLDARqEOmdmhywevp7IgEF66+6+Bf07pv3X/g68n"+
			"NiemAzZq16aEj5CTt+OXuC0i5zHIDOog4gcmQIMfbeMWL9brqnnEM0fVEXztJN+A"+
			"yWJeeYbtx8sCpNXI/v7yLNYynSUVBsQOYaORYUsEOQJfmBCC633sVN/0OXSXKpSK"+
			"dhEnpEEcN19knsBDWUWQbUuVs2FGRmHqsWTr5O4/ORqB59tgOtfPp+6/K3SGlKty"+
			"DEUyO9d4sR/665oha4GNAgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P"+
			"AQH/BAQDAgGGMB0GA1UdDgQWBBSnW4ik+/9kkwub9avir63Lqvgv7jAfBgNVHSME"+
			"GDAWgBSnW4ik+/9kkwub9avir63Lqvgv7jANBgkqhkiG9w0BAQUFAAOCAQEARHIp"+
			"C13zA9hBn6zo/Bv68KFRlu5lOmF1B8O2Hv6rw/dcB7JP9nX8TfMVN+Ax8EG+Put2"+
			"yFmcJ6X8oZQgnpJhR5u7plK46YeAHWU9Hkw2LoHzAjZoKCYY9J+/ETbwBRkXYVjs"+
			"fnFEz721qExO96t3V5oKDcM0SHwrTPUIQ8XiupEGUgoHQ9IK/cYhm9pdZOb7z5nY"+
			"8BUXd66IQBOqNyZjb2pCqHXKUo1ELS+MZmmdJdO696jhkt+VsX1LWptMTZlYmiaW"+
			"woLvPKz+s2iaoTigNwZZ/ojxL9GRfqkTPuPtgWP73dC5E9wPgDEzsORnm7mooprJ"+
			"FDNTBZWv96kf9grOhA==").getBytes());

	/**
	 * Creates a new TestCertTools object.
	 * 
	 * @param name
	 *            DOCUMENT ME!
	 */
	public TestCertTools(String name) {
		super(name);
	}

	protected void setUp() throws Exception {
		log.trace(">setUp()");
		CertTools.installBCProvider();
		log.trace("<setUp()");
	}

	protected void tearDown() throws Exception {
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @throws Exception
	 *             DOCUMENT ME!
	 */
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
		assertEquals(CertTools.getPartFromDN(dn12, "CN"), "foo, OU=bar");
		assertEquals(CertTools.getPartFromDN(dn12, "O"), "baz\\, quux");
		assertNull(CertTools.getPartFromDN(dn12, "OU"));

		String dn13 = "C=SE, O=PrimeKey, EmailAddress=foo@primekey.se";
		ArrayList emails = CertTools.getEmailFromDN(dn13);
		assertEquals((String) emails.get(0), "foo@primekey.se");

		String dn14 = "C=SE, E=foo@primekey.se, O=PrimeKey";
		emails = CertTools.getEmailFromDN(dn14);
		assertEquals((String) emails.get(0), "foo@primekey.se");

		String dn15 = "C=SE, E=foo@primekey.se, O=PrimeKey, EmailAddress=bar@primekey.se";
		emails = CertTools.getEmailFromDN(dn15);
		assertEquals((String) emails.get(0), "bar@primekey.se");

		log.trace("<test01GetPartFromDN()");
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @throws Exception
	 *             DOCUMENT ME!
	 */
	public void test02StringToBCDNString() throws Exception {
		log.trace(">test02StringToBCDNString()");

		// We try to examine the general case and som special cases, which we
		// want to be able to handle
		String dn1 = "C=SE, O=AnaTom, CN=foo";
		assertEquals(CertTools.stringToBCDNString(dn1), "CN=foo,O=AnaTom,C=SE");

		String dn2 = "C=SE, O=AnaTom, CN=cn";
		assertEquals(CertTools.stringToBCDNString(dn2), "CN=cn,O=AnaTom,C=SE");

		String dn3 = "CN=foo, O=PrimeKey, C=SE";
		assertEquals(CertTools.stringToBCDNString(dn3),
				"CN=foo,O=PrimeKey,C=SE");

		String dn4 = "cn=foo, o=PrimeKey, c=SE";
		assertEquals(CertTools.stringToBCDNString(dn4),
				"CN=foo,O=PrimeKey,C=SE");

		String dn5 = "cn=foo,o=PrimeKey,c=SE";
		assertEquals(CertTools.stringToBCDNString(dn5),
				"CN=foo,O=PrimeKey,C=SE");

		String dn6 = "C=SE, O=AnaTom, CN=CN";
		assertEquals(CertTools.stringToBCDNString(dn6), "CN=CN,O=AnaTom,C=SE");

		String dn7 = "C=CN, O=AnaTom, CN=foo";
		assertEquals(CertTools.stringToBCDNString(dn7), "CN=foo,O=AnaTom,C=CN");

		String dn8 = "C=cn, O=AnaTom, CN=foo";
		assertEquals(CertTools.stringToBCDNString(dn8), "CN=foo,O=AnaTom,C=cn");

		String dn9 = "CN=foo, O=PrimeKey, C=CN";
		assertEquals(CertTools.stringToBCDNString(dn9),
				"CN=foo,O=PrimeKey,C=CN");

		String dn10 = "CN=foo, O=PrimeKey, C=cn";
		assertEquals(CertTools.stringToBCDNString(dn10),
				"CN=foo,O=PrimeKey,C=cn");

		String dn11 = "CN=foo, O=CN, C=CN";
		assertEquals(CertTools.stringToBCDNString(dn11), "CN=foo,O=CN,C=CN");

		String dn12 = "O=PrimeKey,C=SE,CN=CN";
		assertEquals(CertTools.stringToBCDNString(dn12),
				"CN=CN,O=PrimeKey,C=SE");

		String dn13 = "O=PrimeKey,C=SE,CN=CN, OU=FooOU";
		assertEquals(CertTools.stringToBCDNString(dn13),
				"CN=CN,OU=FooOU,O=PrimeKey,C=SE");

		String dn14 = "O=PrimeKey,C=CN,CN=CN, OU=FooOU";
		assertEquals(CertTools.stringToBCDNString(dn14),
				"CN=CN,OU=FooOU,O=PrimeKey,C=CN");

		String dn15 = "O=PrimeKey,C=CN,CN=cn, OU=FooOU";
		assertEquals(CertTools.stringToBCDNString(dn15),
				"CN=cn,OU=FooOU,O=PrimeKey,C=CN");

		String dn16 = "CN=foo, CN=bar,O=CN, C=CN";
		assertEquals(CertTools.stringToBCDNString(dn16),
				"CN=foo,CN=bar,O=CN,C=CN");

		String dn17 = "CN=foo,CN=bar, O=CN, O=C, C=CN";
		assertEquals(CertTools.stringToBCDNString(dn17),
				"CN=foo,CN=bar,O=CN,O=C,C=CN");

		String dn18 = "cn=jean,cn=EJBCA,dc=home,dc=jean";
		assertEquals(CertTools.stringToBCDNString(dn18),
				"CN=jean,CN=EJBCA,DC=home,DC=jean");

		String dn19 = "cn=bar, cn=foo,o=oo, O=EJBCA,DC=DC2, dc=dc1, C=SE";
		assertEquals(CertTools.stringToBCDNString(dn19),
				"CN=bar,CN=foo,O=oo,O=EJBCA,DC=DC2,DC=dc1,C=SE");

		String dn20 = " CN=\"foo, OU=bar\",  O=baz\\\\\\, quux,C=SE ";
		// BC always escapes with backslash, it doesn't use quotes.
		assertEquals(CertTools.stringToBCDNString(dn20),
				"CN=foo\\, OU\\=bar,O=baz\\\\\\, quux,C=SE");

		String dn21 = "C=SE,O=Foo\\, Inc, OU=Foo\\, Dep, CN=Foo\\'";
		String bcdn21 = CertTools.stringToBCDNString(dn21);
		assertEquals(bcdn21, "CN=Foo\',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE");
		// it is allowed to escape ,
		assertEquals(StringTools.strip(bcdn21),
				"CN=Foo',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE");

		String dn22 = "C=SE,O=Foo\\, Inc, OU=Foo, Dep, CN=Foo'";
		String bcdn22 = CertTools.stringToBCDNString(dn22);
		assertEquals(bcdn22, "CN=Foo',OU=Foo,O=Foo\\, Inc,C=SE");
		assertEquals(StringTools.strip(bcdn22),
				"CN=Foo',OU=Foo,O=Foo\\, Inc,C=SE");

		String dn23 = "C=SE,O=Foo, OU=FooOU, CN=Foo, DN=qualf";
		String bcdn23 = CertTools.stringToBCDNString(dn23);
		assertEquals(bcdn23, "DN=qualf,CN=Foo,OU=FooOU,O=Foo,C=SE");
		assertEquals(StringTools.strip(bcdn23),
				"DN=qualf,CN=Foo,OU=FooOU,O=Foo,C=SE");

		String dn24 = "telephonenumber=08555-666,businesscategory=Surf boards,postaladdress=Stockholm,postalcode=11122,CN=foo,CN=bar, O=CN, O=C, C=CN";
		assertEquals(CertTools.stringToBCDNString(dn24),
				"TelephoneNumber=08555-666,PostalAddress=Stockholm,BusinessCategory=Surf boards,PostalCode=11122,CN=foo,CN=bar,O=CN,O=C,C=CN");

		String dn25 = "CN=user+name, C=CN";
		assertEquals(CertTools.stringToBCDNString(dn25),"CN=user\\+name,C=CN");

		String dn26 = "CN=user\\+name, C=CN";
		assertEquals(CertTools.stringToBCDNString(dn26),"CN=user\\\\\\+name,C=CN");

		log.trace("<test02StringToBCDNString()");
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @throws Exception
	 *             DOCUMENT ME!
	 */
	public void test03AltNames() throws Exception {
		log.trace(">test03AltNames()");

		// We try to examine the general case and som special cases, which we
		// want to be able to handle
		String alt1 = "rfc822Name=ejbca@primekey.se, dNSName=www.primekey.se, uri=http://www.primekey.se/ejbca";
		assertEquals(CertTools.getPartFromDN(alt1, CertTools.EMAIL),
				"ejbca@primekey.se");
		assertNull(CertTools.getPartFromDN(alt1, CertTools.EMAIL1));
		assertNull(CertTools.getPartFromDN(alt1, CertTools.EMAIL2));
		assertEquals(CertTools.getPartFromDN(alt1, CertTools.DNS),
				"www.primekey.se");
		assertNull(CertTools.getPartFromDN(alt1, CertTools.URI));
		assertEquals(CertTools.getPartFromDN(alt1, CertTools.URI1),
				"http://www.primekey.se/ejbca");

		String alt2 = "email=ejbca@primekey.se, dNSName=www.primekey.se, uniformResourceIdentifier=http://www.primekey.se/ejbca";
		assertEquals(CertTools.getPartFromDN(alt2, CertTools.EMAIL1),
				"ejbca@primekey.se");
		assertEquals(CertTools.getPartFromDN(alt2, CertTools.URI),
				"http://www.primekey.se/ejbca");

		String alt3 = "EmailAddress=ejbca@primekey.se, dNSName=www.primekey.se, uniformResourceIdentifier=http://www.primekey.se/ejbca";
		assertEquals(CertTools.getPartFromDN(alt3, CertTools.EMAIL2),
				"ejbca@primekey.se");

		Certificate cert = CertTools.getCertfromByteArray(guidcert);
		String upn = CertTools.getUPNAltName(cert);
		assertEquals(upn, "guid@foo.com");
		String guid = CertTools.getGuidAltName(cert);
		assertEquals(guid, "1234567890abcdef");

		String customAlt = "rfc822Name=foo@bar.com";
		ArrayList oids = CertTools.getCustomOids(customAlt);
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

		log.trace("<test03AltNames()");
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @throws Exception
	 *             DOCUMENT ME!
	 */
	public void test04DNComponents() throws Exception {
		log.trace(">test04DNComponents()");

		// We try to examine the general case and som special cases, which we
		// want to be able to handle
		String dn1 = "CN=CommonName, O=Org, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName, GivenName=GivenName, Initials=Initials, C=SE";
		String bcdn1 = CertTools.stringToBCDNString(dn1);
		log.debug("dn1: " + dn1);
		log.debug("bcdn1: " + bcdn1);
		assertEquals(
				bcdn1,
				"CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,OU=OrgUnit,O=Org,C=SE");

		dn1 = "CN=CommonName, O=Org, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName, GivenName=GivenName, Initials=Initials, C=SE, 1.1.1.1=1111Oid, 2.2.2.2=2222Oid";
		bcdn1 = CertTools.stringToBCDNString(dn1);
		log.debug("dn1: " + dn1);
		log.debug("bcdn1: " + bcdn1);
		assertEquals(
				bcdn1,
				"CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,OU=OrgUnit,O=Org,C=SE,2.2.2.2=2222Oid,1.1.1.1=1111Oid");

		dn1 = "CN=CommonName, 3.3.3.3=3333Oid,O=Org, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName, GivenName=GivenName, Initials=Initials, C=SE, 1.1.1.1=1111Oid, 2.2.2.2=2222Oid";
		bcdn1 = CertTools.stringToBCDNString(dn1);
		log.debug("dn1: " + dn1);
		log.debug("bcdn1: " + bcdn1);
		// 3.3.3.3 is not a valid OID so it should be silently dropped
		assertEquals(
				bcdn1,
				"CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,OU=OrgUnit,O=Org,C=SE,2.2.2.2=2222Oid,1.1.1.1=1111Oid");

		dn1 = "CN=CommonName, 2.3.3.3=3333Oid,O=Org, K=KKK, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName, GivenName=GivenName, Initials=Initials, C=SE, 1.1.1.1=1111Oid, 2.2.2.2=2222Oid";
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
	public void test05IntlChars() throws Exception {
		log.trace(">test05IntlChars()");
		// We try to examine the general case and som special cases, which we
		// want to be able to handle
		String dn1 = "CN=Tomas?????????, O=?????????-Org, OU=??????-Unit, C=SE";
		String bcdn1 = CertTools.stringToBCDNString(dn1);
		log.debug("dn1: " + dn1);
		log.debug("bcdn1: " + bcdn1);
		assertEquals("CN=Tomas?????????,OU=??????-Unit,O=?????????-Org,C=SE",
				bcdn1);
		log.trace("<test05IntlChars()");
	}

	/**
	 * Tests some of the other methods of CertTools
	 * 
	 * @throws Exception
	 *             if error...
	 */
	public void test06CertOps() throws Exception {
		log.trace(">test06CertOps()");
		Certificate cert = CertTools.getCertfromByteArray(testcert);
		Certificate gcert = CertTools.getCertfromByteArray(guidcert);
		assertEquals("Wrong issuerDN", CertTools.getIssuerDN(cert), CertTools
				.stringToBCDNString("CN=TestCA,O=AnaTom,C=SE"));
		assertEquals("Wrong subjectDN", CertTools.getSubjectDN(cert), CertTools
				.stringToBCDNString("CN=p12test,O=PrimeTest,C=SE"));
		assertEquals("Wrong subject key id", new String(Hex.encode(CertTools
				.getSubjectKeyId(cert))),
				"E74F5690F48D147783847CD26448E8094ABB08A0".toLowerCase());
		assertEquals("Wrong authority key id", new String(Hex.encode(CertTools
				.getAuthorityKeyId(cert))),
				"637BF476A854248EA574A57744A6F45E0F579251".toLowerCase());
		assertEquals("Wrong upn alt name", "foo@foo", CertTools
				.getUPNAltName(cert));
		assertEquals("Wrong guid alt name", "1234567890abcdef", CertTools
				.getGuidAltName(gcert));
		assertEquals("Wrong certificate policy", "1.1.1.1.1.1", CertTools
				.getCertificatePolicyId(cert, 0));
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
	public void test08TestUnstructured() throws Exception {
		log.trace(">test08TestUnstructured()");
		// We try to examine the that we handle modern dc components for ldap
		// correctly
		String dn1 = "C=SE,O=PrimeKey,unstructuredName=10.1.1.2,unstructuredAddress=foo.bar.se,cn=test";
		String bcdn1 = CertTools.stringToBCDNString(dn1);
		log.debug("dn1: " + dn1);
		log.debug("bcdn1: " + bcdn1);
		assertEquals(
				"unstructuredAddress=foo.bar.se,unstructuredName=10.1.1.2,CN=test,O=PrimeKey,C=SE",
				bcdn1);
		log.trace("<test08TestUnstructured()");
	}

	/**
	 * Tests the reversing of a DN
	 * 
	 * @throws Exception
	 *             if error...
	 */
	public void test09TestReverse() throws Exception {
		log.trace(">test09TestReverse()");
		// We try to examine the that we handle modern dc components for ldap
		// correctly
		String dn1 = "dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G";
		String dn2 = "cn=Tomas G,ou=users,ou=orgunit,dc=se,dc=bigcorp,dc=com";
		assertTrue(CertTools.isDNReversed(dn1));
		assertTrue(!CertTools.isDNReversed(dn2));
		assertTrue(CertTools.isDNReversed("C=SE,CN=Foo"));
		assertTrue(!CertTools.isDNReversed("CN=Foo,O=FooO"));
		String revdn1 = CertTools.reverseDN(dn1);
		log.debug("dn1: " + dn1);
		log.debug("revdn1: " + revdn1);
		assertEquals(dn2, revdn1);

		String dn3 = "cn=toto,cn=titi,dc=domain,dc=tld";
		String revdn3 = CertTools.reverseDN(dn3);
		assertEquals("dc=tld,dc=domain,cn=titi,cn=toto", revdn3);
		
        Vector dnorder = CertTools.getX509FieldOrder(true);
        X509Name dn4 = CertTools.stringToBcX509Name(dn3, new X509DefaultEntryConverter(), dnorder);
		assertEquals("CN=toto,CN=titi,DC=domain,DC=tld", dn4.toString());
        dnorder = CertTools.getX509FieldOrder(false);
        X509Name dn5 = CertTools.stringToBcX509Name(dn3, new X509DefaultEntryConverter(), dnorder);
		// This ordering is not optimal...
		assertEquals("DC=domain,DC=tld,CN=toto,CN=titi", dn5.toString());

		log.trace("<test09TestReverse()");
	}

	/**
	 * Tests the handling of DC components
	 * 
	 * @throws Exception if error...
	 */
	public void test10TestMultipleReversed() throws Exception {
		log.trace(">test10TestMultipleReversed()");
		// We try to examine the that we handle modern dc components for ldap
		// correctly
		String dn1 = "dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G";
		String bcdn1 = CertTools.stringToBCDNString(dn1);
		log.debug("dn1: " + dn1);
		log.debug("bcdn1: " + bcdn1);
		assertEquals("CN=Tomas G,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com",
				bcdn1);

		String dn19 = "C=SE, dc=dc1,DC=DC2,O=EJBCA, O=oo, cn=foo, cn=bar";
		assertEquals("CN=bar,CN=foo,O=oo,O=EJBCA,DC=DC2,DC=dc1,C=SE", CertTools
				.stringToBCDNString(dn19));
		String dn20 = " C=SE,CN=\"foo, OU=bar\",  O=baz\\\\\\, quux  ";
		// BC always escapes with backslash, it doesn't use quotes.
		assertEquals("CN=foo\\, OU\\=bar,O=baz\\\\\\, quux,C=SE", CertTools
				.stringToBCDNString(dn20));

		String dn21 = "C=SE,O=Foo\\, Inc, OU=Foo\\, Dep, CN=Foo\\'";
		String bcdn21 = CertTools.stringToBCDNString(dn21);
		assertEquals("CN=Foo\',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE", bcdn21);
		assertEquals("CN=Foo',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE", StringTools
				.strip(bcdn21));
		log.trace("<test10TestMultipleReversed()");
	}

	/**
	 * Tests the insertCNPostfix function
	 * 
	 * @throws Exception
	 *             if error...
	 */
	public void test11TestInsertCNPostfix() throws Exception {
		log.trace(">test11TestInsertCNPostfix()");

		// Test the regular case with one CN beging replaced with " (VPN)"
		// postfix
		String dn1 = "CN=Tomas G,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
		String cnpostfix1 = " (VPN)";
		String newdn1 = CertTools.insertCNPostfix(dn1, cnpostfix1);
		assertEquals(
				"CN=Tomas G (VPN),OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com",
				newdn1);

		// Test case when CN doesn't exist
		String dn2 = "OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
		String newdn2 = CertTools.insertCNPostfix(dn2, cnpostfix1);
		assertEquals("OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", newdn2);

		// Test case with two CNs in DN only first one should be replaced.
		String dn3 = "CN=Tomas G,CN=Bagare,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
		String newdn3 = CertTools.insertCNPostfix(dn3, cnpostfix1);
		assertEquals(
				"CN=Tomas G (VPN),CN=Bagare,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com",
				newdn3);

		// Test case with two CNs in reversed DN
		String dn4 = "dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G,CN=Bagare";
		String newdn4 = CertTools.insertCNPostfix(dn4, cnpostfix1);
		assertEquals(
				"dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G (VPN),CN=Bagare",
				newdn4);

		// Test case with two CNs in reversed DN
		String dn5 = "UID=tomas,CN=tomas,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
		String cnpostfix5 = " (VPN)";
		String newdn5 = CertTools.insertCNPostfix(dn5, cnpostfix5);
		assertEquals(
				"UID=tomas,CN=tomas (VPN),OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com",
				newdn5);

		log.trace("<test11TestInsertCNPostfix()");
	}

	/**
	 */
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
		assertTrue(CertTools.getPartsFromDN(dn1, CertTools.URI1).contains(
				"http://www.a.se"));

		String dn2 = "uri=http://www.a.se, uri=http://www.b.se, C=SE, O=AnaTom, CN=foo";
		assertEquals(CertTools.getPartsFromDN(dn2, "CN").size(), 1);
		assertTrue(CertTools.getPartsFromDN(dn2, "CN").contains("foo"));
		assertEquals(CertTools.getPartsFromDN(dn2, CertTools.URI1).size(), 2);
		assertTrue(CertTools.getPartsFromDN(dn2, CertTools.URI1).contains(
				"http://www.a.se"));
		assertTrue(CertTools.getPartsFromDN(dn2, CertTools.URI1).contains(
				"http://www.b.se"));

		log.trace("<test12GetPartsFromDN()");
	}

	public void test13GetSubjectAltNameString() throws Exception {
		log.trace(">test13GetSubjectAltNameString()");

		String altNames = CertTools.getSubjectAlternativeName(CertTools
				.getCertfromByteArray(altNameCert));
		log.debug(altNames);
		String name = CertTools.getPartFromDN(altNames, CertTools.UPN);
		assertEquals("foo@a.se", name);
		assertEquals("foo@a.se", CertTools.getUPNAltName(CertTools
				.getCertfromByteArray(altNameCert)));
		name = CertTools.getPartFromDN(altNames, CertTools.URI);
		assertEquals("http://www.a.se/", name);
		name = CertTools.getPartFromDN(altNames, CertTools.EMAIL);
		assertEquals("tomas@a.se", name);
		name = CertTools.getEMailAddress(CertTools
				.getCertfromByteArray(altNameCert));
		assertEquals("tomas@a.se", name);
		name = CertTools.getEMailAddress(CertTools
				.getCertfromByteArray(testcert));
		assertNull(name);
		name = CertTools.getEMailAddress(null);
		assertNull(name);
		name = CertTools.getPartFromDN(altNames, CertTools.DNS);
		assertEquals("www.a.se", name);
		name = CertTools.getPartFromDN(altNames, CertTools.IPADDR);
		assertEquals("10.1.1.1", name);
		log.trace("<test13GetSubjectAltNameString()");
	}

	public void test14QCStatement() throws Exception {
		Certificate cert = CertTools.getCertfromByteArray(qcRefCert);
		// log.debug(cert);
		assertEquals("rfc822name=municipality@darmstadt.de",
				QCStatementExtension.getQcStatementAuthorities(cert));
		Collection ids = QCStatementExtension.getQcStatementIds(cert);
		assertTrue(ids
				.contains(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2
						.getId()));
		Certificate cert2 = CertTools.getCertfromByteArray(qcPrimeCert);
		assertEquals("rfc822name=qc@primekey.se", QCStatementExtension
				.getQcStatementAuthorities(cert2));
		ids = QCStatementExtension.getQcStatementIds(cert2);
		assertTrue(ids
				.contains(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1
						.getId()));
		assertTrue(ids
				.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance
						.getId()));
		assertTrue(ids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD
				.getId()));
		assertTrue(ids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue
				.getId()));
		String limit = QCStatementExtension.getQcStatementValueLimit(cert2);
		assertEquals("50000 SEK", limit);
	}

	public void test15AiaOcspUri() throws Exception {
		Certificate cert = CertTools.getCertfromByteArray(aiaCert);
		//log.debug(cert);
		assertEquals("http://localhost:8080/ejbca/publicweb/status/ocsp",
				CertTools.getAuthorityInformationAccessOcspUrl(cert));
	}

	public void test16GetSubjectAltNameStringWithDirectoryName()
			throws Exception {
		log.trace(">test16GetSubjectAltNameStringWithDirectoryName()");

		Certificate cer = CertTools
				.getCertfromByteArray(altNameCertWithDirectoryName);
		String altNames = CertTools.getSubjectAlternativeName(cer);
		log.debug(altNames);

		String name = CertTools.getPartFromDN(altNames, CertTools.UPN);
		assertEquals("testDirName@jamador.pki.gva.es", name);
		assertEquals("testDirName@jamador.pki.gva.es", CertTools
				.getUPNAltName(cer));

		name = CertTools.getPartFromDN(altNames, CertTools.DIRECTORYNAME);
		assertEquals("CN=testDirName|dir|name", name);
		assertEquals(name.substring("CN=".length()), new X509Name(
				"CN=testDirName|dir|name").getValues().get(0));

		String altName = "rfc822name=foo@bar.se, uri=http://foo.bar.se, directoryName="
				+ LDAPDN.escapeRDN("CN=testDirName, O=Foo, OU=Bar, C=SE")
				+ ", dnsName=foo.bar.se";
		GeneralNames san = CertTools.getGeneralNamesFromAltName(altName);
		GeneralName[] gns = san.getNames();
		boolean found = false;
		for (int i = 0; i < gns.length; i++) {
			int tag = gns[i].getTagNo();
			if (tag == 4) {
				found = true;
				DEREncodable enc = gns[i].getName();
				X509Name dir = (X509Name) enc;
				String str = dir.toString();
				log.debug("DirectoryName: " + str);
				assertEquals("CN=testDirName,O=Foo,OU=Bar,C=SE", str);
			}

		}
		assertTrue(found);

		altName = "rfc822name=foo@bar.se, rfc822name=foo@bar.com, uri=http://foo.bar.se, directoryName="
				+ LDAPDN.escapeRDN("CN=testDirName, O=Foo, OU=Bar, C=SE")
				+ ", dnsName=foo.bar.se, dnsName=foo.bar.com";
		san = CertTools.getGeneralNamesFromAltName(altName);
		gns = san.getNames();
		int dnscount = 0;
		int rfc822count = 0;
		for (int i = 0; i < gns.length; i++) {
			int tag = gns[i].getTagNo();
			if (tag == 2) {
				dnscount++;
				DEREncodable enc = gns[i].getName();
				DERIA5String dir = (DERIA5String) enc;
				String str = dir.getString();
				log.info("DnsName: " + str);
			}
			if (tag == 1) {
				rfc822count++;
				DEREncodable enc = gns[i].getName();
				DERIA5String dir = (DERIA5String) enc;
				String str = dir.getString();
				log.info("Rfc822Name: " + str);
			}

		}
		assertEquals(2, dnscount);
		assertEquals(2, rfc822count);
		log.trace("<test16GetSubjectAltNameStringWithDirectoryName()");
	}

	public void test17SubjectDirectoryAttributes() throws Exception {
		log.trace(">test17SubjectDirectoryAttributes()");
		Certificate cer = CertTools.getCertfromByteArray(subjDirAttrCert);
		String ret = SubjectDirAttrExtension.getSubjectDirectoryAttributes(cer);
		assertEquals("countryOfCitizenship=TR", ret);
		cer = CertTools.getCertfromByteArray(subjDirAttrCert2);
		ret = SubjectDirAttrExtension.getSubjectDirectoryAttributes(cer);
		assertEquals(
				"countryOfResidence=SE, countryOfCitizenship=SE, gender=M, placeOfBirth=Stockholm, dateOfBirth=19710425",
				ret);
		log.trace("<test17SubjectDirectoryAttributes()");
	}

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

	public void test19getAltNameStringFromExtension() throws Exception {
		PKCS10CertificationRequest p10 = new PKCS10CertificationRequest(
				p10ReqWithAltNames);
		CertificationRequestInfo info = p10.getCertificationRequestInfo();
		ASN1Set set = info.getAttributes();
		// The set of attributes contains a sequence of with type oid
		// PKCSObjectIdentifiers.pkcs_9_at_extensionRequest
		Enumeration en = set.getObjects();
		boolean found = false;
		while (en.hasMoreElements()) {
			ASN1Sequence seq = ASN1Sequence.getInstance(en.nextElement());
			DERObjectIdentifier oid = (DERObjectIdentifier) seq.getObjectAt(0);
			if (oid.equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
				// The object at position 1 is a SET of x509extensions
				DERSet s = (DERSet) seq.getObjectAt(1);
				X509Extensions exts = X509Extensions.getInstance(s
						.getObjectAt(0));
				X509Extension ext = exts
						.getExtension(X509Extensions.SubjectAlternativeName);
				if (ext != null) {
					found = true;
					String altNames = CertTools
							.getAltNameStringFromExtension(ext);
					assertEquals(
							"dNSName=ort3-kru.net.polisen.se, iPAddress=10.252.255.237",
							altNames);
				}
			}
		}
		assertTrue(found);

		p10 = new PKCS10CertificationRequest(p10ReqWithAltNames2);
		info = p10.getCertificationRequestInfo();
		set = info.getAttributes();
		// The set of attributes contains a sequence of with type oid
		// PKCSObjectIdentifiers.pkcs_9_at_extensionRequest
		en = set.getObjects();
		found = false;
		while (en.hasMoreElements()) {
			ASN1Sequence seq = ASN1Sequence.getInstance(en.nextElement());
			DERObjectIdentifier oid = (DERObjectIdentifier) seq.getObjectAt(0);
			if (oid.equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
				// The object at position 1 is a SET of x509extensions
				DERSet s = (DERSet) seq.getObjectAt(1);
				X509Extensions exts = X509Extensions.getInstance(s
						.getObjectAt(0));
				X509Extension ext = exts
						.getExtension(X509Extensions.SubjectAlternativeName);
				if (ext != null) {
					found = true;
					String altNames = CertTools
							.getAltNameStringFromExtension(ext);
					assertEquals("dNSName=foo.bar.com, iPAddress=10.0.0.1",
							altNames);
				}
			}
		}
		assertTrue(found);

	}

	public void test20cvcCert() throws Exception {
		Certificate cert = CertTools.getCertfromByteArray(cvccert);
		assertNotNull(cert);
		PublicKey pk = cert.getPublicKey();
		assertNotNull(pk);
		assertEquals("RSA", pk.getAlgorithm());
		if( pk instanceof RSAPublicKey){
			BigInteger modulus = ((RSAPublicKey)pk).getModulus(); 
			int len = modulus.bitLength();
			assertEquals(1024, len);
		} else {
			assertTrue(false);
		}
		String subjectdn = CertTools.getSubjectDN(cert);
		assertEquals("CN=RPS,C=SE", subjectdn);
		String issuerdn = CertTools.getIssuerDN(cert);
		assertEquals("CN=RPS,C=SE", issuerdn);
		assertEquals("10110", CertTools.getSerialNumberAsString(cert));
		CardVerifiableCertificate cvcert = (CardVerifiableCertificate)cert;
		assertEquals("CVCA", cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name());

		// Serialization, CVC provider is installed by CertTools.installBCProvider
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(cert);
		oos.close();
		baos.close();
		ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
		ObjectInputStream ois = new ObjectInputStream(bais);
		Object o = ois.readObject();
		Certificate ocert = (Certificate)o;
		assertEquals("CVC", ocert.getType());

		// Test CVC certificate request encoding
		CVCObject parsedObject = CertificateParser.parseCVCObject(cvcreq);
		CVCertificate req = (CVCertificate)parsedObject;
		PublicKey pubKey = req.getCertificateBody().getPublicKey();
		assertNotNull(pubKey);
		assertEquals("CVC", pubKey.getFormat());
		BigInteger modulus = ((RSAPublicKey)pk).getModulus(); 
		int len = modulus.bitLength();
		assertEquals(1024, len); 

		// Test verification of an authenticated request
		parsedObject = CertificateParser.parseCVCObject(cvcreqrenew);
		CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest)parsedObject;
		try {
			authreq.verify(pubKey);
		} catch (Exception e) {
			assertTrue(false);
		}	  
		// Test verification of an authenticated request that fails
		parsedObject = CertificateParser.parseCVCObject(cvcreqrenew);
		authreq = (CVCAuthenticatedRequest)parsedObject;
		req = authreq.getRequest();
		try {
			authreq.verify(req.getCertificateBody().getPublicKey());
			assertTrue(false);
		} catch (Exception e) {
		}	  
	}

	public void test21GenSelfCert() throws Exception {
		KeyPair kp = KeyTools.genKeys("1024", "RSA");
		Certificate cert = CertTools.genSelfCertForPurpose("CN=foo1", 10, null,
				kp.getPrivate(), kp.getPublic(),
				CATokenInfo.SIGALG_SHA256_WITH_RSA_AND_MGF1, true,
				X509KeyUsage.keyCertSign);
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
		String subjectdn = CertTools.getSubjectDN(cert);
		assertEquals("CN=foo1", subjectdn);
		String issuerdn = CertTools.getIssuerDN(cert);
		assertEquals("CN=foo1", issuerdn);
	}
	
	public void test22CreateCertChain() throws Exception {
		// Test creating a certificate chain for CVC CAs
		Certificate cvccertroot = CertTools.getCertfromByteArray(cvccertchainroot);
		Certificate cvccertsub = CertTools.getCertfromByteArray(cvccertchainsub);
		
		ArrayList certlist = new ArrayList();
		certlist.add(cvccertsub);
		certlist.add(cvccertroot);
		Collection col = CertTools.createCertChain(certlist);
		assertEquals(2, col.size());
		Iterator iter = col.iterator();
		Certificate certsub = (Certificate)iter.next();
		assertEquals("CN=RPS,C=SE", CertTools.getSubjectDN(certsub));
		Certificate certroot = (Certificate)iter.next();
		assertEquals("CN=HSMCVCA,C=SE", CertTools.getSubjectDN(certroot));
		
		// Test creating a certificate chain for X509CAs
		Certificate x509certsubsub = CertTools.getCertfromByteArray(x509certchainsubsub);
		Certificate x509certsub = CertTools.getCertfromByteArray(x509certchainsub);
		Certificate x509certroot = CertTools.getCertfromByteArray(x509certchainroot);
		certlist = new ArrayList();
		certlist.add(x509certsub);
		certlist.add(x509certroot);
		certlist.add(x509certsubsub);
		col = CertTools.createCertChain(certlist);
		assertEquals(3, col.size());
		iter = col.iterator();
		Certificate certsubsub = (Certificate)iter.next();
		assertEquals("CN=SubSubCA,O=EJBCA Sample,C=SE", CertTools.getSubjectDN(certsubsub));
		certsub = (Certificate)iter.next();
		assertEquals("CN=SubCA,O=EJBCA Sample,C=SE", CertTools.getSubjectDN(certsub));
		certroot = (Certificate)iter.next();
		assertEquals("CN=AdminCA1,O=EJBCA TomasLaptop MySQL,C=SE", CertTools.getSubjectDN(certroot));
		
	}
	
	public void test23GenSelfCertDSA() throws Exception {
		KeyPair kp = KeyTools.genKeys("1024", "DSA");
		Certificate cert = CertTools.genSelfCertForPurpose("CN=foo1", 10, null,
				kp.getPrivate(), kp.getPublic(),
				CATokenInfo.SIGALG_SHA1_WITH_DSA, true,
				X509KeyUsage.keyCertSign);
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
	
	public void testKrb5PrincipalName() throws Exception {
		String altName =  "krb5principal=foo/bar@P.SE, upn=upn@u.com";
		GeneralNames gn = CertTools.getGeneralNamesFromAltName(altName);

		GeneralName[] names = gn.getNames();
		String ret = CertTools.getGeneralNameString(0, names[1].getName());
		assertEquals("krb5principal=foo/bar@P.SE", ret);

		altName =  "krb5principal=foo@P.SE";
		gn = CertTools.getGeneralNamesFromAltName(altName);
		names = gn.getNames();
		ret = CertTools.getGeneralNameString(0, names[0].getName());
		assertEquals("krb5principal=foo@P.SE", ret);

		altName =  "krb5principal=foo/A.SE@P.SE";
		gn = CertTools.getGeneralNamesFromAltName(altName);
		names = gn.getNames();
		ret = CertTools.getGeneralNameString(0, names[0].getName());
		assertEquals("krb5principal=foo/A.SE@P.SE", ret);
		
		Certificate krbcert = CertTools.getCertfromByteArray(krb5principalcert);
		String s = CertTools.getSubjectAlternativeName(krbcert);
		assertEquals("krb5principal=foo/bar@P.COM", s);
	}
	
	public void testPseudonymAndName() throws Exception {
		String dn1 = "c=SE,O=Prime,OU=Tech,TelephoneNumber=555-666,Name=Kalle,PostalAddress=footown,PostalCode=11122,Pseudonym=Shredder,cn=Tomas Gustavsson";
		String bcdn1 = CertTools.stringToBCDNString(dn1);
		assertEquals("Pseudonym=Shredder,TelephoneNumber=555-666,PostalAddress=footown,PostalCode=11122,CN=Tomas Gustavsson,Name=Kalle,OU=Tech,O=Prime,C=SE", bcdn1);		
	}

	public void testEscapedCharacters() throws Exception {
        String dn = CertTools.stringToBCDNString("O=\\<fff\\>\\\",CN=oid,SN=12345,NAME=name,C=se");
        assertEquals("CN=oid,Name=name,SN=12345,O=\\<fff\\>\\\",C=se", dn);
	}

}
