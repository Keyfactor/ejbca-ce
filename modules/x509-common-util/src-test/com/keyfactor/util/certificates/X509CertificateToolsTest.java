/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.certificates;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.RDN;
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
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.cert.QCStatementExtension;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.RFC4683Tools;
import org.cesecore.util.StringTools;
import org.junit.Test;

import com.novell.ldap.LDAPDN;

/**
 *
 */
public class X509CertificateToolsTest {

    private static final Logger log = Logger.getLogger(X509CertificateToolsTest.class);
    
    private static byte[] testcert = Base64.decode(("MIIDATCCAmqgAwIBAgIIczEoghAwc3EwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAzMDky" + "NDA2NDgwNFoXDTA1MDkyMzA2NTgwNFowMzEQMA4GA1UEAxMHcDEydGVzdDESMBAG"
            + "A1UEChMJUHJpbWVUZXN0MQswCQYDVQQGEwJTRTCBnTANBgkqhkiG9w0BAQEFAAOB" + "iwAwgYcCgYEAnPAtfpU63/0h6InBmesN8FYS47hMvq/sliSBOMU0VqzlNNXuhD8a"
            + "3FypGfnPXvjJP5YX9ORu1xAfTNao2sSHLtrkNJQBv6jCRIMYbjjo84UFab2qhhaJ" + "wqJgkQNKu2LHy5gFUztxD8JIuFPoayp1n9JL/gqFDv6k81UnDGmHeFcCARGjggEi"
            + "MIIBHjAPBgNVHRMBAf8EBTADAQEAMA8GA1UdDwEB/wQFAwMHoAAwOwYDVR0lBDQw" + "MgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDBAYIKwYBBQUHAwUGCCsGAQUF"
            + "BwMHMB0GA1UdDgQWBBTnT1aQ9I0Ud4OEfNJkSOgJSrsIoDAfBgNVHSMEGDAWgBRj" + "e/R2qFQkjqV0pXdEpvReD1eSUTAiBgNVHREEGzAZoBcGCisGAQQBgjcUAgOgCQwH"
            + "Zm9vQGZvbzASBgNVHSAECzAJMAcGBSkBAQEBMEUGA1UdHwQ+MDwwOqA4oDaGNGh0" + "dHA6Ly8xMjcuMC4wLjE6ODA4MC9lamJjYS93ZWJkaXN0L2NlcnRkaXN0P2NtZD1j"
            + "cmwwDQYJKoZIhvcNAQEFBQADgYEAU4CCcLoSUDGXJAOO9hGhvxQiwjGD2rVKCLR4" + "emox1mlQ5rgO9sSel6jHkwceaq4A55+qXAjQVsuy76UJnc8ncYX8f98uSYKcjxo/"
            + "ifn1eHMbL8dGLd5bc2GNBZkmhFIEoDvbfn9jo7phlS8iyvF2YhC4eso8Xb+T7+BZ" + "QUOBOvc=").getBytes());
    
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
    
    /**
     * Tests the reversing of a DN
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void testTestReverseDN() throws Exception {
        log.trace(">test09TestReverse()");
        // We try to examine the that we handle modern dc components for ldap
        // correctly
        String dn1 = "dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G";
        String dn2 = "cn=Tomas G,ou=users,ou=orgunit,dc=se,dc=bigcorp,dc=com";
        assertTrue(X509CertificateTools.isDNReversed(dn1));
        assertTrue(!X509CertificateTools.isDNReversed(dn2));
        assertTrue(X509CertificateTools.isDNReversed("C=SE,CN=Foo"));
        assertTrue(!X509CertificateTools.isDNReversed("CN=Foo,O=FooO"));
        // Test some bad input
        assertTrue(!X509CertificateTools.isDNReversed("asdasd,asdassd"));
        String revdn1 = X509CertificateTools.reverseDN(dn1);
        log.debug("dn1: " + dn1);
        log.debug("revdn1: " + revdn1);
        assertEquals(dn2, revdn1);

        String dn3 = "cn=toto,cn=titi,dc=domain,dc=tld";
        String revdn3 = X509CertificateTools.reverseDN(dn3);
        assertEquals("dc=tld,dc=domain,cn=titi,cn=toto", revdn3);
        
        X500Name dn4 = X509CertificateTools.stringToBcX500Name(dn3, new CeSecoreNameStyle(), true);
        assertEquals("CN=toto,CN=titi,DC=domain,DC=tld", dn4.toString());
        X500Name dn5 = X509CertificateTools.stringToBcX500Name(dn3, new CeSecoreNameStyle(), false);
        assertEquals("DC=tld,DC=domain,CN=titi,CN=toto", dn5.toString());
        assertEquals("CN=toto,CN=titi,DC=domain,DC=tld", X509CertificateTools.stringToBCDNString(dn3));

        String dn6 = "dc=tld,dc=domain,cn=titi,cn=toto";
        String revdn6 = X509CertificateTools.reverseDN(dn6);
        assertEquals("cn=toto,cn=titi,dc=domain,dc=tld", revdn6);
        assertEquals("CN=toto,CN=titi,DC=domain,DC=tld", X509CertificateTools.stringToBCDNString(dn3));

        X500Name dn7 = X509CertificateTools.stringToBcX500Name(dn6, new CeSecoreNameStyle(), true);
        assertEquals("CN=toto,CN=titi,DC=domain,DC=tld", dn7.toString());
        X500Name revdn7 = X509CertificateTools.stringToBcX500Name(dn6, new CeSecoreNameStyle(), false);
        assertEquals("DC=tld,DC=domain,CN=titi,CN=toto", revdn7.toString());

        // Test the test strings from ECA-1699, to prove that we fixed this issue
        String dn8 = "dc=org,dc=foo,o=FOO,cn=FOO Root CA";
        String dn9 = "cn=FOO Root CA,o=FOO,dc=foo,dc=org";
        String revdn8 = X509CertificateTools.reverseDN(dn8);
        assertEquals("cn=FOO Root CA,o=FOO,dc=foo,dc=org", revdn8);
        String revdn9 = X509CertificateTools.reverseDN(dn9);
        assertEquals("dc=org,dc=foo,o=FOO,cn=FOO Root CA", revdn9);
        X500Name xdn8ldap = X509CertificateTools.stringToBcX500Name(dn8, new CeSecoreNameStyle(), true);
        X500Name xdn8x500 = X509CertificateTools.stringToBcX500Name(dn8, new CeSecoreNameStyle(), false);
        assertEquals("CN=FOO Root CA,O=FOO,DC=foo,DC=org", xdn8ldap.toString());
        assertEquals("DC=org,DC=foo,O=FOO,CN=FOO Root CA", xdn8x500.toString());
        X500Name xdn9ldap = X509CertificateTools.stringToBcX500Name(dn9, new CeSecoreNameStyle(), true);
        X500Name xdn9x500 = X509CertificateTools.stringToBcX500Name(dn9, new CeSecoreNameStyle(), false);
        assertEquals("CN=FOO Root CA,O=FOO,DC=foo,DC=org", xdn9ldap.toString());
        assertEquals("DC=org,DC=foo,O=FOO,CN=FOO Root CA", xdn9x500.toString());
        assertEquals("CN=FOO Root CA,O=FOO,DC=foo,DC=org", X509CertificateTools.stringToBCDNString(dn8));
        assertEquals("CN=FOO Root CA,O=FOO,DC=foo,DC=org", X509CertificateTools.stringToBCDNString(dn9));

        // Test reversing DNs with multiple OU
        String dn10 = "CN=something,OU=A,OU=B,O=someO,C=SE";
        X500Name x500dn10 = X509CertificateTools.stringToBcX500Name(dn10, new CeSecoreNameStyle(), true);
        assertEquals("CN=something,OU=A,OU=B,O=someO,C=SE", x500dn10.toString());
        assertEquals("CN=something,OU=A,OU=B,O=someO,C=SE", X509CertificateTools.stringToBCDNString(dn10));

        // When we order forwards (LdapOrder) from the beginning, and request !LdapOrder, everything should be reversed
        X500Name ldapdn11 = X509CertificateTools.stringToBcX500Name(dn10, new CeSecoreNameStyle(), false);
        assertEquals("C=SE,O=someO,OU=B,OU=A,CN=something", ldapdn11.toString());

        // When we order backwards (X.509, !LdapOrder) from the beginning, we should not reorder anything
        String dn11 = "C=SE,O=someO,OU=B,OU=A,CN=something";
        X500Name x500dn11 = X509CertificateTools.stringToBcX500Name(dn11, new CeSecoreNameStyle(), false);
        assertEquals("C=SE,O=someO,OU=B,OU=A,CN=something", x500dn11.toString());
        assertEquals("CN=something,OU=A,OU=B,O=someO,C=SE", X509CertificateTools.stringToBCDNString(dn11));

        // Test some bad input
        try {
            // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
            assertEquals("", X509CertificateTools.stringToBCDNString("asdasd,asdassd"));
            fail("Should throw");
        } catch (IllegalArgumentException e) {
            // invalid and should throw
            assertEquals("Exception message is wrong", "badly formatted directory string", e.getMessage());
        }

        log.trace("<test09TestReverse()");
    }
    
    @Test
    public void testSerialNumberFromString() throws Exception {
        // Test numerical format
        BigInteger serno = X509CertificateTools.getSerialNumberFromString("00001");
        assertEquals(1, serno.intValue());
        // Test SE001 format
        serno = X509CertificateTools.getSerialNumberFromString("SE021");
        assertEquals(21, serno.intValue());

        // Test numeric and hexadecimal string, will get the numerical part in the middle
        serno = X509CertificateTools.getSerialNumberFromString("F53AA");
        assertEquals(53, serno.intValue());

        // Test pure letters
        serno = X509CertificateTools.getSerialNumberFromString("FXBAA");
        assertEquals(26748514, serno.intValue());

        // Test a strange format...
        serno = X509CertificateTools.getSerialNumberFromString("SE02K");
        assertEquals(2, serno.intValue());

        // Test a real biginteger
        serno = X509CertificateTools.getSerialNumberFromString("7331288210307371");
        assertEquals(271610737, serno.intValue());

        // Test a real certificate
        X509Certificate cert = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, testcert);
        serno = X509CertificateTools.getSerialNumber(cert);
        assertEquals(271610737, serno.intValue());
        String str = X509CertificateTools.getSerialNumberAsString(cert);
        assertEquals(serno.toString(16), str);
    }
    
    @Test
    public void testDNSpaceTrimming() throws Exception {
        String dn1 = "CN=CommonName, O= Org,C=SE";
        String bcdn1 = X509CertificateTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=CommonName,O=Org,C=SE", bcdn1);

        dn1 = "CN=CommonName, O =Org,C=SE";
        bcdn1 = X509CertificateTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=CommonName,O=Org,C=SE", bcdn1);

        dn1 = "CN=CommonName, O = Org,C=SE";
        bcdn1 = X509CertificateTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=CommonName,O=Org,C=SE", bcdn1);
    }
    
    @Test
    public void testgetAltNameStringFromExtension() throws Exception {
        {
            PKCS10CertificationRequest p10 = new JcaPKCS10CertificationRequest(p10ReqWithAltNames);
            Attribute attribute = p10.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)[0];
            // The set of attributes contains a sequence of with type oid
            // PKCSObjectIdentifiers.pkcs_9_at_extensionRequest
            boolean found = false;
            ASN1Set s = ASN1Set.getInstance(attribute.getAttrValues());
            Extensions exts = Extensions.getInstance(s.getObjectAt(0));
            Extension ext = exts.getExtension(Extension.subjectAlternativeName);
            if (ext != null) {
                found = true;
                String altNames = X509CertificateTools.getAltNameStringFromExtension(ext);
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
            ASN1Set s = ASN1Set.getInstance(attribute.getAttrValues());
            Extensions exts = Extensions.getInstance(s.getObjectAt(0));
            Extension ext = exts.getExtension(Extension.subjectAlternativeName);
            if (ext != null) {
                found = true;
                String altNames = X509CertificateTools.getAltNameStringFromExtension(ext);
                assertEquals("dNSName=foo.bar.com, iPAddress=10.0.0.1", altNames);
            }
            assertTrue(found);
        }

    }
    
    @Test
    public void testStringToBCDNString() throws Exception {
        log.trace(">testStringToBCDNString()");

        // We try to examine the general case and som special cases, which we
        // want to be able to handle
        String dn1 = "C=SE, O=AnaTom, CN=foo";
        assertEquals(X509CertificateTools.stringToBCDNString(dn1), "CN=foo,O=AnaTom,C=SE");

        String dn2 = "C=SE, O=AnaTom, CN=cn";
        assertEquals(X509CertificateTools.stringToBCDNString(dn2), "CN=cn,O=AnaTom,C=SE");

        String dn3 = "CN=foo, O=PrimeKey, C=SE";
        assertEquals(X509CertificateTools.stringToBCDNString(dn3), "CN=foo,O=PrimeKey,C=SE");

        String dn4 = "cn=foo, o=PrimeKey, c=SE";
        assertEquals(X509CertificateTools.stringToBCDNString(dn4), "CN=foo,O=PrimeKey,C=SE");

        String dn5 = "cn=foo,o=PrimeKey,c=SE";
        assertEquals(X509CertificateTools.stringToBCDNString(dn5), "CN=foo,O=PrimeKey,C=SE");

        String dn6 = "C=SE, O=AnaTom, CN=CN";
        assertEquals(X509CertificateTools.stringToBCDNString(dn6), "CN=CN,O=AnaTom,C=SE");

        String dn7 = "C=CN, O=AnaTom, CN=foo";
        assertEquals(X509CertificateTools.stringToBCDNString(dn7), "CN=foo,O=AnaTom,C=CN");

        String dn8 = "C=cn, O=AnaTom, CN=foo";
        assertEquals(X509CertificateTools.stringToBCDNString(dn8), "CN=foo,O=AnaTom,C=cn");

        String dn9 = "CN=foo, O=PrimeKey, C=CN";
        assertEquals(X509CertificateTools.stringToBCDNString(dn9), "CN=foo,O=PrimeKey,C=CN");

        String dn10 = "CN=foo, O=PrimeKey, C=cn";
        assertEquals(X509CertificateTools.stringToBCDNString(dn10), "CN=foo,O=PrimeKey,C=cn");

        String dn11 = "CN=foo, O=CN, C=CN";
        assertEquals(X509CertificateTools.stringToBCDNString(dn11), "CN=foo,O=CN,C=CN");

        String dn12 = "O=PrimeKey,C=SE,CN=CN";
        assertEquals(X509CertificateTools.stringToBCDNString(dn12), "CN=CN,O=PrimeKey,C=SE");

        String dn13 = "O=PrimeKey,C=SE,CN=CN, OU=FooOU";
        assertEquals(X509CertificateTools.stringToBCDNString(dn13), "CN=CN,OU=FooOU,O=PrimeKey,C=SE");

        String dn14 = "O=PrimeKey,C=CN,CN=CN, OU=FooOU";
        assertEquals(X509CertificateTools.stringToBCDNString(dn14), "CN=CN,OU=FooOU,O=PrimeKey,C=CN");

        String dn15 = "O=PrimeKey,C=CN,CN=cn, OU=FooOU";
        assertEquals(X509CertificateTools.stringToBCDNString(dn15), "CN=cn,OU=FooOU,O=PrimeKey,C=CN");

        String dn16 = "CN=foo, CN=bar,O=CN, C=CN";
        assertEquals(X509CertificateTools.stringToBCDNString(dn16), "CN=foo,CN=bar,O=CN,C=CN");

        String dn17 = "CN=foo,CN=bar, O=CN, O=C, C=CN";
        assertEquals(X509CertificateTools.stringToBCDNString(dn17), "CN=foo,CN=bar,O=CN,O=C,C=CN");

        String dn18 = "cn=jean,cn=EJBCA,dc=home,dc=jean";
        assertEquals(X509CertificateTools.stringToBCDNString(dn18), "CN=jean,CN=EJBCA,DC=home,DC=jean");

        String dn19 = "cn=bar, cn=foo,o=oo, O=EJBCA,DC=DC2, dc=dc1, C=SE";
        assertEquals(X509CertificateTools.stringToBCDNString(dn19), "CN=bar,CN=foo,O=oo,O=EJBCA,DC=DC2,DC=dc1,C=SE");

        String dn20 = " CN=\"foo, OU=bar\",  O=baz\\\\\\, quux,C=SE ";
        // BC always escapes with backslash, it doesn't use quotes.
        assertEquals("Conversion of: "+dn20, "CN=foo\\, OU\\=bar,O=baz\\\\\\, quux,C=SE", X509CertificateTools.stringToBCDNString(dn20));

        String dn21 = "C=SE,O=Foo\\, Inc, OU=Foo\\, Dep, CN=Foo\\'";
        String bcdn21 = X509CertificateTools.stringToBCDNString(dn21);
        assertEquals(bcdn21, "CN=Foo\',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE");
        // it is allowed to escape ,
        assertEquals(StringTools.strip(bcdn21), "CN=Foo',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE");

        try {
            // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
            // We used to swallow this badly formatted DN string, but doesn't do that anymore
            String dn22 = "C=SE,O=Foo\\, Inc, OU=Foo, Dep, CN=Foo'";
            X509CertificateTools.stringToBCDNString(dn22);
            fail("should fail since directory string is badly formatted 'Foo, Dep' and the '-character must be escaped");
        } catch (IllegalArgumentException e) {
            assertEquals("Exception message is wrong", "badly formatted directory string", e.getMessage());
        }
        // If we want to use comma, it must be escaped
        String dn22 = "C=SE,O=Foo\\, Inc, OU=Foo\\, Dep, CN=Foo\\'";
        String bcdn22 = X509CertificateTools.stringToBCDNString(dn22);
        assertEquals(bcdn22, "CN=Foo',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE");
        assertEquals(StringTools.strip(bcdn22), "CN=Foo',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE");

        String dn23 = "C=SE,O=Foo, OU=FooOU, CN=Foo, DN=qualf";
        String bcdn23 = X509CertificateTools.stringToBCDNString(dn23);
        assertEquals(bcdn23, "DN=qualf,CN=Foo,OU=FooOU,O=Foo,C=SE");
        assertEquals(StringTools.strip(bcdn23), "DN=qualf,CN=Foo,OU=FooOU,O=Foo,C=SE");

        String dn24 = "telephonenumber=08555-666,businesscategory=Surf boards,postaladdress=Stockholm,postalcode=11122,CN=foo,CN=bar, O=CN, O=C, C=CN";
        assertEquals(X509CertificateTools.stringToBCDNString(dn24),
                "TelephoneNumber=08555-666,PostalAddress=Stockholm,BusinessCategory=Surf boards,PostalCode=11122,CN=foo,CN=bar,O=CN,O=C,C=CN");

        // This wasn't a legal SubjectDN until EJBCA 7.0.0. Since legacy BC did not support multi-values, we used to assume that the user meant \+.
        String dn25 = "CN=user+name, C=CN";
        try {
            // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
            X509CertificateTools.stringToBCDNString(dn25);
            fail("Should have thrown an exception due to badly formatted string. CN=user+name is not a valid multi-value RDN (should perhaps be CN=user+UID=name)");
        } catch (IllegalArgumentException e) {
            assertEquals("Exception message is wrong", "badly formatted directory string", e.getMessage());
        }
        // We must escape plus signs
        String dn26 = "CN=user\\+name, C=CN";
        assertEquals("CN=user\\+name,C=CN", X509CertificateTools.stringToBCDNString(dn26));
        // We must escape equal signs
        String dn26_1 = "CN=user;C=SE";
        assertEquals("CN=user\\;C", X509CertificateTools.stringToBCDNString(dn26_1));
        String dn26_2 = "CN=user;C\\=SE";
        assertEquals("CN=user\\;C\\=SE", X509CertificateTools.stringToBCDNString(dn26_2));

        try {
            String dn27 = "CN=test123456, O=\\\"foo+b\\+ar\\, C=SE\\\"";
            // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
            X509CertificateTools.stringToBCDNString(dn27);
            fail("Should have thrown an exception due to badly formatted string");
        } catch (IllegalArgumentException e) {
            assertEquals("Exception message is wrong", "Unknown object id - b\\+ar\\, C - passed to distinguished name", e.getMessage());
        }
        // Equal signs and plus must be escaped
        String dn27 = "CN=test123456, O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"";
        assertEquals("CN=test123456,O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"", X509CertificateTools.stringToBCDNString(dn27));

        String dn27_1 = "CN=test123456, O=\\\"foo+b\\+ar\\, C=SE\\";
        try {
            // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
            assertEquals("CN=test123456,O=\\\"foo\\+b\\+ar\\, C\\=SE\\\\", X509CertificateTools.stringToBCDNString(dn27_1));
            fail("Should have thrown an exception due to badly formatted string");
        } catch (IllegalArgumentException e) {
            assertEquals("Exception message is wrong", "Unknown object id - b\\+ar\\, C - passed to distinguished name", e.getMessage());
        }

        try {
            String dn28 = "jurisdictionCountry=SE,jurisdictionState=Stockholm,SURNAME=Json,=fff,CN=oid,jurisdictionLocality=Solna,SN=12345,unstructuredname=foo.bar.com,unstructuredaddress=1.2.3.4,NAME=name,C=se";
            // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
            X509CertificateTools.stringToBCDNString(dn28);
            fail("Should have thrown an exception due to badly formatted string");
        } catch (StringIndexOutOfBoundsException e) {
            // due to the "=fff" that does not have a type
            assertEquals("Exception message is wrong", "String index out of range: 0", e.getMessage());
        }
        // No invalid parts like '=fff' allowed
        String dn28 = "jurisdictionCountry=SE,jurisdictionState=Stockholm,SURNAME=Json,CN=oid,jurisdictionLocality=Solna,SN=12345,unstructuredname=foo.bar.com,unstructuredaddress=1.2.3.4,NAME=name,C=se";
        assertEquals("JurisdictionCountry=SE,JurisdictionState=Stockholm,JurisdictionLocality=Solna,unstructuredAddress=1.2.3.4,unstructuredName=foo.bar.com,CN=oid,Name=name,SN=12345,SURNAME=Json,C=se",
                X509CertificateTools.stringToBCDNString(dn28));
        
        String dn29 = "CN=hexencoded SN,SN=1234";
        assertEquals("CN=hexencoded SN,SN=1234", X509CertificateTools.stringToBCDNString(dn29));
        String dn30 = "CN=hexencoded SN,SN=\\#CNJB";
        assertEquals("CN=hexencoded SN,SN=\\#CNJB", X509CertificateTools.stringToBCDNString(dn30));
        DERUTF8String str = new DERUTF8String("foo");
        String hex = new String(Hex.encode(str.getEncoded()));
        String dn31 = "CN=hexencoded SN,SN=#"+hex;
        assertEquals("CN=hexencoded SN,SN=foo", X509CertificateTools.stringToBCDNString(dn31));

        String dn32a = "CN=eidas,O=MyOrg,ORGANIZATIONIDENTIFIER=12345,C=SE";
        assertEquals("CN=eidas,organizationIdentifier=12345,O=MyOrg,C=SE", X509CertificateTools.stringToBCDNString(dn32a));
        String dn32b = "CN=test,O=MyOrg,DESCRIPTION=Test Description,C=SE";
        assertEquals("description=Test Description,CN=test,O=MyOrg,C=SE", X509CertificateTools.stringToBCDNString(dn32b));

        // Test spaces in the RDN value
        String dn33a = "CN=cn,O= the org ,C=SE";
        assertEquals("CN=cn,O=the org,C=SE", X509CertificateTools.stringToBCDNString(dn33a));
        String dn33b = "CN=cn,O= the org ";
        assertEquals("CN=cn,O=the org", X509CertificateTools.stringToBCDNString(dn33b));
        // The following has changed from earlier EJBCA versions there the trailing escaped space would have been kept. (Perhaps through a change in BC's X500NameBuilder.)
        // Document the current behavior with this test to catch future changes.
        // this value changed again when introducing multi-valued RDNs and starting to use IETFUtils.rDNsFromString in ECA-3934
        String dn34a = "CN=cn,O=\\ the org\\ ,C=SE";
        // Backslash-space in the end used to become backslash-backslash-space, now only backslash-space, which is more logical
        assertEquals("CN=cn,O=\\ the org\\ ,C=SE", X509CertificateTools.stringToBCDNString(dn34a));
        String dn34b = "CN=cn,O=\\ the org\\ ";
        assertEquals("CN=cn,O=\\ the org\\ ", X509CertificateTools.stringToBCDNString(dn34b));
        // Same string as tested in EjbcaWSTest.test51CertificateRequestWithNoForbiddenChars
        String dn35 = "CN=Foo,O=|\n|\r|;|A|!|`|?|$|~|, C=SE";
        assertEquals("CN=Foo,O=|\n|\r|\\;|A|!|`|?|$|~|,C=SE", X509CertificateTools.stringToBCDNString(dn35));

        String dn36 = "CN=Name2,EMAIL=foo@bar.com,OU=MyOrgU,OU=Unit2,C=SE,O=Org1";
        assertEquals("E=foo@bar.com,CN=Name2,OU=MyOrgU,OU=Unit2,O=Org1,C=SE", X509CertificateTools.stringToBCDNString(dn36));
    }
    
    @Test
    public void testFingerprint() throws Exception {
        Certificate cert = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, testcert);
        assertEquals("4d66df0017deb32f669346c51c80600964816c84", X509CertificateTools.getFingerprintAsString(cert));
        assertEquals("4d66df0017deb32f669346c51c80600964816c84", X509CertificateTools.getFingerprintAsString(testcert));
        assertEquals("c61bfaa15d733532c5e795756c8001d4", new String(Hex.encode(X509CertificateTools.generateMD5Fingerprint(testcert))));
    }
    
    /**
     * Tests string coding/decoding international (swedish characters)
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void testIntlChars() throws Exception {
        // We try to examine the general case and som special cases, which we
        // want to be able to handle
        String dn1 = "CN=Tomas?????????, O=?????????-Org, OU=??????-Unit, C=SE";
        String bcdn1 = X509CertificateTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=Tomas?????????,OU=??????-Unit,O=?????????-Org,C=SE", bcdn1);
    }
    
    /**
     * Tests the handling of DC components
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void testTestDC() throws Exception {
        // We try to examine the that we handle modern dc components for ldap
        // correctly
        String dn1 = "dc=bigcorp,dc=com,dc=se,ou=users,cn=Mike Jackson";
        String bcdn1 = X509CertificateTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        // assertEquals("CN=Mike Jackson,OU=users,DC=se,DC=bigcorp,DC=com",
        // bcdn1);
        String dn2 = "cn=Mike Jackson,ou=users,dc=se,dc=bigcorp,dc=com";
        String bcdn2 = X509CertificateTools.stringToBCDNString(dn2);
        log.debug("dn2: " + dn2);
        log.debug("bcdn2: " + bcdn2);
        assertEquals("CN=Mike Jackson,OU=users,DC=se,DC=bigcorp,DC=com", bcdn2);
    }

    /**
     * Tests the handling of unstructuredName/Address
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void testTestUnstructured() throws Exception {
        // We try to examine the that we handle modern dc components for ldap
        // correctly
        String dn1 = "C=SE,O=PrimeKey,unstructuredName=10.1.1.2,unstructuredAddress=foo.bar.se,cn=test";
        String bcdn1 = X509CertificateTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("unstructuredAddress=foo.bar.se,unstructuredName=10.1.1.2,CN=test,O=PrimeKey,C=SE", bcdn1);
    }
    
    /**
     * Tests the handling of DC components
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void testTestMultipleReversed() throws Exception {
        // We try to examine the that we handle modern dc components for ldap
        // correctly
        String dn1 = "dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G";
        String bcdn1 = X509CertificateTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=Tomas G,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", bcdn1);

        String dn19 = "C=SE, dc=dc1,DC=DC2,O=EJBCA, O=oo, cn=foo, cn=bar";
        assertEquals("CN=bar,CN=foo,O=oo,O=EJBCA,DC=DC2,DC=dc1,C=SE", X509CertificateTools.stringToBCDNString(dn19));
        String dn20 = " C=SE,CN=\"foo, OU=bar\",  O=baz\\\\\\, quux  ";
        // BC always escapes with backslash, it doesn't use quotes.
        assertEquals("Conversion of: " + dn20, "CN=foo\\, OU\\=bar,O=baz\\\\\\, quux,C=SE", X509CertificateTools.stringToBCDNString(dn20));

        String dn21 = "C=SE,O=Foo\\, Inc, OU=Foo\\, Dep, CN=Foo\\'";
        String bcdn21 = X509CertificateTools.stringToBCDNString(dn21);
        assertEquals("CN=Foo\',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE", bcdn21);
        assertEquals("CN=Foo',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE", StringTools.strip(bcdn21));
    }

    /**
     * Tests the insertCNPostfix function
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void testTestInsertCNPostfix() throws Exception {
        // Test the regular case with one CN beging replaced with " (VPN)"
        // postfix
        final X500NameStyle nameStyle = new CeSecoreNameStyle();
        String dn1 = "CN=Tomas G,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
        String cnpostfix1 = " (VPN)";
        String newdn1 = X509CertificateTools.insertCNPostfix(dn1, cnpostfix1, nameStyle);
        assertEquals("CN=Tomas G (VPN),OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", newdn1);

        // Test case when CN doesn't exist
        String dn2 = "OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
        String newdn2 = X509CertificateTools.insertCNPostfix(dn2, cnpostfix1, nameStyle);
        assertEquals("OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", newdn2);

        // Test case with two CNs in DN only first one should be replaced.
        String dn3 = "CN=Tomas G,CN=Bagare,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
        String newdn3 = X509CertificateTools.insertCNPostfix(dn3, cnpostfix1, nameStyle);
        assertEquals("CN=Tomas G (VPN),CN=Bagare,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", newdn3);

        // Test case with two CNs in reversed DN
        String dn4 = "dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G,CN=Bagare";
        String newdn4 = X509CertificateTools.insertCNPostfix(dn4, cnpostfix1, nameStyle);
        assertEquals("DC=com,DC=bigcorp,DC=se,OU=orgunit,OU=users,CN=Tomas G (VPN),CN=Bagare", newdn4);

        // Test case with two CNs in reversed DN
        String dn5 = "UID=tomas,CN=tomas,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
        String cnpostfix5 = " (VPN)";
        String newdn5 = X509CertificateTools.insertCNPostfix(dn5, cnpostfix5, nameStyle);
        assertEquals("UID=tomas,CN=tomas (VPN),OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", newdn5);
    }

    @Test
    public void testQCStatement() throws Exception {
        X509Certificate cert = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, qcRefCert);
        // log.debug(cert);
        assertEquals("rfc822name=municipality@darmstadt.de", QCStatementExtension.getQcStatementAuthorities(cert));
        Collection<String> ids = QCStatementExtension.getQcStatementIds(cert);
        assertTrue(ids.contains(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2.getId()));
        X509Certificate cert2 = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, qcPrimeCert);
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
    public void testEscapeFieldValue() {
        assertEquals(null, X509CertificateTools.escapeFieldValue(null));
        assertEquals("", X509CertificateTools.escapeFieldValue(""));
        assertEquals("CN=", X509CertificateTools.escapeFieldValue("CN="));
        assertEquals("DIRECTORYNAME=DESCRIPTION=Test\\\\test\\,O=PrimeKey", X509CertificateTools.escapeFieldValue("DIRECTORYNAME=DESCRIPTION=Test\\test,O=PrimeKey"));
        assertEquals("CN=123\\+456", X509CertificateTools.escapeFieldValue("CN=123+456"));
        assertEquals("CN=abc\\\"def", X509CertificateTools.escapeFieldValue("CN=abc\"def"));
        assertEquals("CN=abc\\>def", X509CertificateTools.escapeFieldValue("CN=abc>def"));
    }
    
    @Test
    public void testNullInput() {
        assertNull(X509CertificateTools.stringToBcX500Name(null));
        assertNull(X509CertificateTools.stringToBCDNString(null));
        assertNull(X509CertificateTools.reverseDN(null));
        assertFalse(X509CertificateTools.isDNReversed(null));
        assertNull(X509CertificateTools.getPartFromDN(null, null));
        assertEquals(0, X509CertificateTools.getPartsFromDN(null, null).size());
        assertEquals(0, X509CertificateTools.getCustomOids(null).size());
        try {
            assertNull(X509CertificateTools.getSerialNumber(null));
            assertTrue("Should throw", false);
        } catch (IllegalArgumentException e) {
            // NOPMD
        }
        try {
            assertNull(X509CertificateTools.getSerialNumberAsString(null));
            assertTrue("Should throw", false);
        } catch (IllegalArgumentException e) {
            // NOPMD
        }
        try {
            assertNull(X509CertificateTools.getSerialNumberFromString(null));
            assertTrue("Should throw", false);
        } catch (IllegalArgumentException e) {
            // NOPMD
        }
    }
    
    @Test
    public void testPseudonymNameAndRole() throws Exception {
        String dn1 = "c=SE,O=Prime,OU=Tech,Role=Roll,TelephoneNumber=555-666,Name=Kalle,PostalAddress=footown,PostalCode=11122,Pseudonym=Shredder,cn=Tomas Gustavsson";
        String bcdn1 = X509CertificateTools.stringToBCDNString(dn1);
        assertEquals(
                "Role=Roll,Pseudonym=Shredder,TelephoneNumber=555-666,PostalAddress=footown,PostalCode=11122,CN=Tomas Gustavsson,Name=Kalle,OU=Tech,O=Prime,C=SE",
                bcdn1);
    }


    
    @Test
    public void testGenSelfCert() throws Exception {
        KeyPair kp = KeyTools.genKeys("1024", "RSA");
        X509Certificate cert = X509CertificateTools.genSelfCertForPurpose("CN=foo1", 10, null, kp.getPrivate(), kp.getPublic(),
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
        assertTrue(X509CertificateTools.isCA(cert));
        String subjectdn = X509CertificateTools.getSubjectDN(cert);
        assertEquals("CN=foo1", subjectdn);
        String issuerdn = X509CertificateTools.getIssuerDN(cert);
        assertEquals("CN=foo1", issuerdn);       
        // Get signature field
        byte[] sign = cert.getSignature();
        assertEquals(128, sign.length);
    }
    
    @Test
    public void testGenSelfCertDSA() throws Exception {
        KeyPair kp = KeyTools.genKeys("1024", "DSA");
        X509Certificate cert = X509CertificateTools.genSelfCertForPurpose("CN=foo1", 10, null, kp.getPrivate(), kp.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_DSA, true, X509KeyUsage.keyCertSign, true);
        assertNotNull(cert);
        PublicKey pk = cert.getPublicKey();
        assertNotNull(pk);
        assertEquals("DSA", pk.getAlgorithm());
        assertTrue(pk instanceof DSAPublicKey);
        String subjectdn = X509CertificateTools.getSubjectDN(cert);
        assertEquals("CN=foo1", subjectdn);
        String issuerdn = X509CertificateTools.getIssuerDN(cert);
        assertEquals("CN=foo1", issuerdn);
    }
    

    
    /** Test X509CertificateTools methods for reading CertificatePolicy information from a certificate
     * @throws CertificateParsingException 
     * @throws IOException 
     */
    @Test
    public void testCertificatePolicies() throws CertificateParsingException, IOException {
        // The altname test certificate does not have any policy oids
        X509Certificate certwithnone = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, altNameCert);
        List<ASN1ObjectIdentifier> oids = X509CertificateTools.getCertificatePolicyIds(certwithnone);
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
        X509Certificate cert = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, certPoliciesCert);  
        oids = X509CertificateTools.getCertificatePolicyIds(cert);
        assertEquals("Should be 5 Cert Policy OIDs", 5, oids.size());
        assertEquals("1.1.1.2", oids.get(0).getId());
        assertEquals("1.1.1.3", oids.get(1).getId());
        assertEquals("1.1.1.1", oids.get(2).getId());
        assertEquals("1.1.1.4", oids.get(3).getId());
        assertEquals("1.1.1.5", oids.get(4).getId());
        // Get the full policy objects
        List<PolicyInformation> pi = X509CertificateTools.getCertificatePolicies(cert);
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
    public void testAiaOcspUri() throws Exception {
        X509Certificate cert = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, aiaCert);
        assertEquals("http://localhost:8080/ejbca/publicweb/status/ocsp", X509CertificateTools.getAuthorityInformationAccessOcspUrl(cert));
    }
    
    @Test
    public void test25AiaCaIssuerUri() throws Exception {
        // Only 1 CA Issuer in static aiaCert: "http://localhost:8080/caIssuer"!
        X509Certificate cert = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, aiaCert);
        assertEquals("http://localhost:8080/caIssuer", X509CertificateTools.getAuthorityInformationAccessCAIssuerUris( cert).get(0));
    }
    
    @Test
    public void testEscapedCharacters() throws Exception {
        final String input = "O=\\<fff\\>\\\",CN=oid,SN=12345,NAME=name,C=se";
        final String dn = X509CertificateTools.stringToBCDNString(input);
        assertEquals("Conversion of: "+input, "CN=oid,Name=name,SN=12345,O=\\<fff\\>\\\",C=se", dn);
    }
    
    @Test
    public void testUnescapeFieldValue() {
        assertEquals(null, X509CertificateTools.unescapeFieldValue(null));
        assertEquals("", X509CertificateTools.unescapeFieldValue(""));
        assertEquals("CN=", X509CertificateTools.unescapeFieldValue("CN="));
        assertEquals("DESCRIPTION=Test\\test,O=PrimeKey", X509CertificateTools.unescapeFieldValue("DESCRIPTION=Test\\\\test\\,O=PrimeKey"));
        assertEquals("DIRECTORYNAME=DESCRIPTION=Test\\test,O=PrimeKey", X509CertificateTools.unescapeFieldValue("DIRECTORYNAME=DESCRIPTION=Test\\\\test\\,O=PrimeKey"));
        assertEquals("CN=123+456", X509CertificateTools.unescapeFieldValue("CN=123\\+456"));
        assertEquals("abc\"def", X509CertificateTools.unescapeFieldValue("abc\\\"def"));
        assertEquals("abc>def", X509CertificateTools.unescapeFieldValue("abc\\>def"));
        assertEquals("\\>\"abc ", X509CertificateTools.unescapeFieldValue("\\\\\\>\\\"abc\\ "));
    }
    
    /** Document behavior of X509CertificateTools.verify for bad paremters */
    @Test
    public void testVerifyBadParameterBehavior() throws CertificateParsingException, CertPathValidatorException {
        final String errorMessage = "Behavioural change of X509CertificateTools.verify when bad parameters are used.";
        final String infoMessage = "Expected legacy behavior from X509CertificateTools.verify.";
        try {
            X509CertificateTools.verify(null, null);
            fail(errorMessage);
        } catch (CertPathValidatorException e) {
            log.debug(infoMessage, e);
        }
        try {
            X509CertificateTools.verify(null, new ArrayList<X509Certificate>());
            fail(errorMessage);
        } catch (CertPathValidatorException e) {
            log.debug(infoMessage, e);
        }
        try {
            X509CertificateTools.verify(null, new ArrayList<>(Arrays.asList((X509Certificate)null)));
            fail(errorMessage);
        } catch (NullPointerException e) {
            log.debug(infoMessage, e);
        }
        final X509Certificate x509Certificate = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, testcert);
        try {
            X509CertificateTools.verify(x509Certificate, null);
            fail(errorMessage);
        } catch (CertPathValidatorException e) {
            log.debug(infoMessage, e);
        }
        try {
            X509CertificateTools.verify(x509Certificate, new ArrayList<X509Certificate>());
            fail(errorMessage);
        } catch (CertPathValidatorException e) {
            log.debug(infoMessage, e);
        }
        try {
            X509CertificateTools.verify(x509Certificate, new ArrayList<>(Arrays.asList((X509Certificate)null)));
            fail(errorMessage);
        } catch (NullPointerException e) {
            log.debug(infoMessage, e);
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
            X500Name name = X509CertificateTools.stringToBcX500Name(dn, nameStyle, false, order1);
            assertNotNull(name);
            String desiredDN = "JurisdictionLocality=Åmål,JurisdictionState=State,JurisdictionCountry=NL,BusinessCategory=Private Organization,C=SE,ST=Norrland,L=Åmål,O=MyOrg B.V.,OU=XY,SN=1234567890,CN=evssltest6.test.lan";
            assertEquals("Name order should be as defined in order string array", desiredDN, name.toString());
            // Another order
            final String[] order2 = { "jurisdictioncountry", "jurisdictionstate", "jurisdictionlocality","businesscategory","serialnumber","c","dc","st","l","o","ou","t","surname","initials","givenname","gn","sn","name","cn","uid","dn","email","e","emailaddress","unstructuredname","unstructuredaddress","postalcode","postaladdress","telephonenumber","pseudonym","street"};
            name = X509CertificateTools.stringToBcX500Name(dn, nameStyle, false, order2);
            assertNotNull(name);
            String desiredDNNoLap = "CN=evssltest6.test.lan,OU=XY,O=MyOrg B.V.,L=Åmål,ST=Norrland,C=SE,SN=1234567890,BusinessCategory=Private Organization,JurisdictionLocality=Åmål,JurisdictionState=State,JurisdictionCountry=NL";
            assertEquals("Name order should be as defined in order string array", desiredDNNoLap, name.toString());
            name = X509CertificateTools.stringToBcX500Name(dn, nameStyle, true, order2);
            String desiredDNWithLDAP = "JurisdictionCountry=NL,JurisdictionState=State,JurisdictionLocality=Åmål,BusinessCategory=Private Organization,SN=1234567890,C=SE,ST=Norrland,L=Åmål,O=MyOrg B.V.,OU=XY,CN=evssltest6.test.lan"; 
            assertEquals("Name order should be as defined in order string array", desiredDNWithLDAP, name.toString());
            // Ignore LDAP DN order (do not apply)
            name = X509CertificateTools.stringToBcX500Name(dn, nameStyle, true, order2, false);
            assertEquals("Name order should be as defined in order string array", desiredDNWithLDAP, name.toString());
            name = X509CertificateTools.stringToBcX500Name(dn, nameStyle, false, order2, false);
            assertEquals("Name order should be as defined in order string array", desiredDNWithLDAP, name.toString());
            // Don't ignore LDAP DN order (apply it == true), should be the same as without the extra boolean
            name = X509CertificateTools.stringToBcX500Name(dn, nameStyle, true, order2, true);
            assertEquals("Name order should be as defined in order string array", desiredDNWithLDAP, name.toString());
            name = X509CertificateTools.stringToBcX500Name(dn, nameStyle, false, order2, true);
            assertEquals("Name order should be as defined in order string array", desiredDNNoLap, name.toString());
            
            // If the ordering string is missing some components that exist in the DN, these will just be added to the beginning of the resulting DN
            final String[] orderWithMissing = { "street", "pseudonym",
                    "telephonenumber", "postaladdress", "postalcode", "unstructuredaddress", "unstructuredname", "emailaddress", "e",
                    "email", "dn", "uid", "cn", "name", "sn", "gn", "givenname", "initials", "surname", "t", "ou", "o", "l", "st", "dc", "c", "serialnumber", "jurisdictionstate", "jurisdictionlocality"};
            name = X509CertificateTools.stringToBcX500Name(dn, nameStyle, false, orderWithMissing);
            assertNotNull(name);
            desiredDN = "BusinessCategory=Private Organization,JurisdictionCountry=NL,JurisdictionLocality=Åmål,JurisdictionState=State,C=SE,ST=Norrland,L=Åmål,O=MyOrg B.V.,OU=XY,SN=1234567890,CN=evssltest6.test.lan";
            assertEquals("Name order should be as defined in order string array", desiredDN, name.toString());
            // Standard ldap order
            name = X509CertificateTools.stringToBcX500Name(dn, nameStyle, true, null);
            assertNotNull(name);
            desiredDN = "JurisdictionCountry=NL,JurisdictionState=State,JurisdictionLocality=Åmål,BusinessCategory=Private Organization,CN=evssltest6.test.lan,SN=1234567890,OU=XY,O=MyOrg B.V.,L=Åmål,ST=Norrland,C=SE";
            assertEquals("Name order should be as defined DnComponents (forward) order array", desiredDN, name.toString());
            // Standard x500 order
            name = X509CertificateTools.stringToBcX500Name(dn, nameStyle, false, null);
            assertNotNull(name);
            desiredDN = "C=SE,ST=Norrland,L=Åmål,O=MyOrg B.V.,OU=XY,SN=1234567890,CN=evssltest6.test.lan,BusinessCategory=Private Organization,JurisdictionLocality=Åmål,JurisdictionState=State,JurisdictionCountry=NL";
            assertEquals("Name order should be as defined DnComponents (reverse) order array", desiredDN, name.toString());
        } catch (IllegalArgumentException e) {
            fail("Exception " + e.getClass() + " should not been thrown.");
        }
    }
    
    @Test
    public void testMultiValueRDN() {

        {
            String dn = "CN=Enrico Maria+serialNumber=123,C=SE";
            X500Name name = X509CertificateTools.stringToUnorderedX500Name(dn, CeSecoreNameStyle.INSTANCE);
            // This should be encoded as a multi-value RDN, where serialNumber is inside the CN RDN
            // In EJBCA before 7.0 we didn't handle multi-values, so serialNumber was extracted as it's own RDN
            // * Old style not handling multi-values:
            // DER Sequence
            //   DER Set
            //     DER Sequence
            //        ObjectIdentifier(2.5.4.3)
            //        UTF8String(Enrico Maria) 
            //   DER Set
            //     DER Sequence
            //        ObjectIdentifier(2.5.4.5)
            //        PrintableString(123) 
            //   DER Set
            //     DER Sequence
            //        ObjectIdentifier(2.5.4.6)
            //        PrintableString(SE)
            // 
            // * New style handling multi-values
            // DER Sequence
            // DER Set
            //    DER Sequence
            //        ObjectIdentifier(2.5.4.5)
            //        PrintableString(123) 
            //    DER Sequence
            //        ObjectIdentifier(2.5.4.3)
            //        UTF8String(Enrico Maria) 
            // DER Set
            //    DER Sequence
            //        ObjectIdentifier(2.5.4.6)
            //        PrintableString(SE)
            String dump = ASN1Dump.dumpAsString(name);
            log.error(dump);
            // Should contain only two RDNs, CN and C, since serialNumber is "inside" of the CN RDN
            RDN[] rdns = name.getRDNs();
            assertEquals("Since it's a multi-value RDNs, we should only have two RDNs", 2, rdns.length);
            // but, name.getAttributeTypes take multi values into consideration and return all types
            ASN1ObjectIdentifier[] ids = name.getAttributeTypes();
            assertEquals("We should have three RDNs, counting the ids in multi-valued RDNs", 3, ids.length);
            // The String representation of multi-value RDNs is a bit randomg, i.e. SN=123+CN=foo vs CN=bar+UID=123, this
            // is because the multi-values are part of an ASN.1 set, which is "unordered", but always encoded in the same way in ASN.1,
            // so "ordered" according to ASN.1 DERSet encoding
            assertEquals("Multi-valued RDNs should be toString:ed properly with +", "SN=123+CN=Enrico Maria,C=SE", name.toString());

            // Second test, ordered BC X500 name
            name = X509CertificateTools.stringToBcX500Name(dn);
            dump = ASN1Dump.dumpAsString(name);
            log.error(dump);
            rdns = name.getRDNs();
            assertEquals("Since it's a multi-value RDNs, we should only have two RDNs", 2, rdns.length);
            // but, name.getAttributeTypes take multi values into consideration and return all types
            ids = name.getAttributeTypes();
            assertEquals("We should have three RDNs, counting the ids in multi-valued RDNs", 3, ids.length);
            assertEquals("Multi-valued RDNs should be toString:ed properly with +", "SN=123+CN=Enrico Maria,C=SE", name.toString());
            assertEquals("Multi value RDNs should be handled with + sign", "SN=123+CN=Enrico Maria,C=SE", X509CertificateTools.stringToBCDNString(dn));
        }
        {
            // A bit more complex
            String dn = "CN=Enrico Maria+serialNumber=123,C=SE,O=PrimeKey,OU=Tech";
            X500Name name = X509CertificateTools.stringToUnorderedX500Name(dn, CeSecoreNameStyle.INSTANCE);
            // Should contain only two RDNs, CN and C, since serialNumber is "inside" of the CN RDN
            RDN[] rdns = name.getRDNs();
            assertEquals("Since it's a multi-value RDNs, we should only have two RDNs", 4, rdns.length);
            // but, name.getAttributeTypes take multi values into consideration and return all types
            ASN1ObjectIdentifier[] ids = name.getAttributeTypes();
            assertEquals("We should have three RDNs, counting the ids in multi-valued RDNs", 5, ids.length);
            assertEquals("Multi-valued RDNs should be toString:ed properly with +", "SN=123+CN=Enrico Maria,C=SE,O=PrimeKey,OU=Tech", name.toString());

            // Second test, ordered BC X500 name
            name = X509CertificateTools.stringToBcX500Name(dn);
            rdns = name.getRDNs();
            assertEquals("Since it's a multi-value RDNs, we should only have two RDNs", 4, rdns.length);
            // but, name.getAttributeTypes take multi values into consideration and return all types
            ids = name.getAttributeTypes();
            assertEquals("We should have three RDNs, counting the ids in multi-valued RDNs", 5, ids.length);
            assertEquals("Multi-valued RDNs should be toString:ed properly with +", "SN=123+CN=Enrico Maria,OU=Tech,O=PrimeKey,C=SE", name.toString());
            assertEquals("Multi value RDNs should be handled with + sign", "SN=123+CN=Enrico Maria,OU=Tech,O=PrimeKey,C=SE", X509CertificateTools.stringToBCDNString(dn));
        }
        {
            // Another DN
            String dn = "CN=Tomas+UID=12345,O=PK,C=SE";
            X500Name name = X509CertificateTools.stringToUnorderedX500Name(dn, CeSecoreNameStyle.INSTANCE);
            // Should contain only two RDNs, CN and C, since serialNumber is "inside" of the CN RDN
            RDN[] rdns = name.getRDNs();
            assertEquals("Since it's a multi-value RDNs, we should only have two RDNs", 3, rdns.length);
            // but, name.getAttributeTypes take multi values into consideration and return all types
            ASN1ObjectIdentifier[] ids = name.getAttributeTypes();
            assertEquals("We should have three RDNs, counting the ids in multi-valued RDNs", 4, ids.length);
            assertEquals("Multi-valued RDNs should be toString:ed properly with +", "CN=Tomas+UID=12345,O=PK,C=SE", name.toString());

            // Second test, ordered BC X500 name
            name = X509CertificateTools.stringToBcX500Name(dn);
            rdns = name.getRDNs();
            assertEquals("Since it's a multi-value RDNs, we should only have two RDNs", 3, rdns.length);
            // but, name.getAttributeTypes take multi values into consideration and return all types
            ids = name.getAttributeTypes();
            assertEquals("We should have three RDNs, counting the ids in multi-valued RDNs", 4, ids.length);
            assertEquals("Multi-valued RDNs should be toString:ed properly with +", "CN=Tomas+UID=12345,O=PK,C=SE", name.toString());
            assertEquals("Multi value RDNs should be handled with + sign", "CN=Tomas+UID=12345,O=PK,C=SE", X509CertificateTools.stringToBCDNString(dn));
        }
        {        
            String dn = "DN=200590+givenName=Enrico Maria+serialNumber=IT:MEZCAL86T16H523D+surname=Ciaffi,O=Test1,C=IT,O=Test";
            assertEquals("Multi value RDNs should be handled with + sign", "SURNAME=Ciaffi+DN=200590+GIVENNAME=Enrico Maria+SN=IT:MEZCAL86T16H523D,O=Test1,O=Test,C=IT", X509CertificateTools.stringToBCDNString(dn));
        }
    }    
    
    @Test
    public void testDNComponents() throws Exception {
        // We try to examine the general case and som special cases, which we
        // want to be able to handle
        String dn1 = "CN=CommonName, O=Org, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName, GivenName=GivenName, Initials=Initials, C=SE";
        String bcdn1 = X509CertificateTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,OU=OrgUnit,O=Org,C=SE", bcdn1);

        String dn1_1 = "CN=CommonName, O=Org, OU=OrgUnit, SN=SerialNumber, SurName=SurName, GivenName=GivenName, Initials=Initials, C=SE";
        String bcdn1_1 = X509CertificateTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1_1);
        log.debug("bcdn1: " + bcdn1_1);
        assertEquals("CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,OU=OrgUnit,O=Org,C=SE", bcdn1_1);

        dn1 = "CN=CommonName, O=Org, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName, GivenName=GivenName,"
                +" Initials=Initials, C=SE, 1.1.1.1=1111Oid, 2.2.2.2=2222Oid";
        bcdn1 = X509CertificateTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,OU=OrgUnit,"
                +"O=Org,C=SE,2.2.2.2=2222Oid,1.1.1.1=1111Oid", bcdn1);

        try {
            dn1 = "CN=CommonName, 3.3.3.3=3333Oid,O=Org, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName,"+
                    " GivenName=GivenName, Initials=Initials, C=SE, 1.1.1.1=1111Oid, 2.2.2.2=2222Oid";
            // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
            // 3.3.3.3 is not a valid OID 
            X509CertificateTools.stringToBCDNString(dn1);
            fail("should have thrown");
        } catch (IllegalArgumentException e) {
            // 3.3.3.3 is not a valid OID so it should throw
            assertEquals("Exception message is wrong", "string 3.3.3.3 not an OID", e.getMessage());            
        }

        // 3.3.3.3 is not a valid OID so don't try to include it
        dn1 = "CN=CommonName, O=Org, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName,"+
                " GivenName=GivenName, Initials=Initials, C=SE, 1.1.1.1=1111Oid, 2.2.2.2=2222Oid";
        bcdn1 = X509CertificateTools.stringToBCDNString(dn1);
        assertEquals("CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,"
                +"OU=OrgUnit,O=Org,C=SE,2.2.2.2=2222Oid,1.1.1.1=1111Oid", bcdn1);

        try {
            dn1 = "CN=CommonName, 2.3.3.3=3333Oid,O=Org, K=KKK, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName,"
                    +" GivenName=GivenName, Initials=Initials, C=SE, 1.1.1.1=1111Oid, 2.2.2.2=2222Oid";
            // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
            X509CertificateTools.stringToBCDNString(dn1);
            fail("Should throw");
        } catch (IllegalArgumentException e) {
            // K is not a valid OID so it should throw
            assertEquals("Exception message is wrong", "Unknown object id - K - passed to distinguished name", e.getMessage());            
        }
        // Drop the K
        dn1 = "CN=CommonName, 2.3.3.3=3333Oid,O=Org, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName,"
                +" GivenName=GivenName, Initials=Initials, C=SE, 1.1.1.1=1111Oid, 2.2.2.2=2222Oid";
        // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
        bcdn1 = X509CertificateTools.stringToBCDNString(dn1);
        assertEquals("CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,OU=OrgUnit,O=Org,C=SE,2.2.2.2=2222Oid,1.1.1.1=1111Oid,2.3.3.3=3333Oid",
                bcdn1);
    }

    @Test
    public void testStringToBcX500WithEmpty() {
        // Legacy behavior changed converting an empty input into an empty output is kept
        X500Name result = X509CertificateTools.stringToBcX500Name("");
        assertNotNull(result);    
        assertEquals("Empty input should result in empty output", "", result.toString());

        result = X509CertificateTools.stringToBcX500Name("CN=");
        assertNotNull(result);    
        assertEquals("Empty input should result in empty output", "CN=", result.toString());

        // Empty, but with trailing comma is invalid however
        try {
            result = X509CertificateTools.stringToBcX500Name("CN=,");
            fail("DN component with trailing comma should fail");
        } catch (IllegalArgumentException e) {
            // NOPMD: should throw
        }
    }
 
    @Test
    public void testStringToBcX500WithEscapedComma() {
        try {
            assertNotNull(X509CertificateTools.stringToBcX500Name("O=\\,"));
            assertNotNull(X509CertificateTools.stringToBcX500Name("O=f\\,b"));          
        } catch (IllegalArgumentException e) {
            fail("Exception " + e.getClass() + " should not been thrown.");
        }
    }
    
    @Test
    public void testStringToBcX500WithIncompleteLoneValue() {
        //Legal as a name even if it won't be legal as a DN
        X500Name result = X509CertificateTools.stringToBcX500Name("O=");
        assertNotNull(result);    
        assertEquals("O=", result.toString());
    }
    
    @Test
    public void testStringToBcX500WithTrailingComma() {
        // Legacy behavior changed with multi-valued RDNs when we started using IETFUtils.rDNsFromString
        // Previously we (wrongly) converted this into an escaped comma 'CN=\\,'. See ECA-3934
        try {
            X509CertificateTools.stringToBcX500Name("CN=,");
            fail("Should have failed with exception dues to badly formatted directory string");
        } catch (IllegalArgumentException e) {
            assertEquals("wrong exception message", "badly formatted directory string", e.getMessage());
        }
    }


    @Test
    public void testStringToBcX500WithIncompleteValue() {
        X500Name result = X509CertificateTools.stringToBcX500Name("CN=,O=foo");
        assertNotNull(result);
        assertEquals("CN=,O=foo", result.toString());
    }
    
    @Test
    public void testStringToBcX500WithValueAndTrailingComma() {
        // Legacy behavior changed with multi-valued RDNs when we started using IETFUtils.rDNsFromString
        // Previously we (wrongly) converted this into an escaped comma 'CN=f\\,'. See ECA-3934
        try {
            X509CertificateTools.stringToBcX500Name("CN=f,");
            fail("Should have failed with exception dues to badly formatted directory string");
        } catch (IllegalArgumentException e) {
            assertEquals("wrong exception message", "badly formatted directory string", e.getMessage());
        }
    }
    
 
    
    @Test
    public void testGetX500NameComponents() {
        List<String> ret = X509CertificateTools.getX500NameComponents("CN=foo,O=bar,C=SE");
        assertEquals("Should be 3 DN components", 3, ret.size());
        assertEquals("component should be the one we passed in", "CN=foo", ret.get(0));
        assertEquals("component should be the one we passed in", "O=bar", ret.get(1));
        assertEquals("component should be the one we passed in", "C=SE", ret.get(2));
        ret = X509CertificateTools.getX500NameComponents("CN=foo,O=bar\\,inc,C=SE");
        assertEquals("Should be 3 DN components", 3, ret.size());
        assertEquals("component should be the one we passed in", "CN=foo", ret.get(0));
        assertEquals("component should be the one we passed in", "O=bar,inc", ret.get(1));
        assertEquals("component should be the one we passed in", "C=SE", ret.get(2));
        ret = X509CertificateTools.getX500NameComponents("CN=foo,O=bar,C=SE, rfc822Name=foo@example.com");
        assertEquals("Should be 4 DN components", 4, ret.size());
        ret = X509CertificateTools.getX500NameComponents("");
        assertEquals("Should be 0 DN components", 0, ret.size());
        ret = X509CertificateTools.getX500NameComponents(" ");
        assertEquals("Should be 0 DN components", 0, ret.size());
        ret = X509CertificateTools.getX500NameComponents(null);
        assertEquals("Should be 0 DN components", 0, ret.size());
        // This is a bit funky as it is not a X500 name component, but it is how it works..
        ret = X509CertificateTools.getX500NameComponents("foo");
        assertEquals("Should be 0 DN components", 1, ret.size());
        assertEquals("component should be the one we passed in", "foo", ret.get(0));        
    }
    
    @Test
    public void testAltNames() throws Exception {
        log.trace(">testAltNames()");

        // We try to examine the general case and som special cases, which we
        // want to be able to handle
        String alt1 = "rfc822Name=ejbca@primekey.se, dNSName=www.primekey.se, uri=http://www.primekey.se/ejbca,registeredID=1.1.1.3,xmppAddr=tomas@xmpp.domain.com,srvName=_Service.Name,fascN=0419d23210d8210c2c1a843085a16858300842108608823210c3e1";
        assertEquals(X509CertificateTools.getPartFromDN(alt1, X509CertificateTools.EMAIL), "ejbca@primekey.se");
        assertNull(X509CertificateTools.getPartFromDN(alt1, X509CertificateTools.EMAIL1));
        assertNull(X509CertificateTools.getPartFromDN(alt1, X509CertificateTools.EMAIL2));
        assertEquals(X509CertificateTools.getPartFromDN(alt1, X509CertificateTools.DNS), "www.primekey.se");
        assertNull(X509CertificateTools.getPartFromDN(alt1, X509CertificateTools.URI));
        assertEquals(X509CertificateTools.getPartFromDN(alt1, X509CertificateTools.URI1), "http://www.primekey.se/ejbca");
        assertEquals(X509CertificateTools.getPartFromDN(alt1, X509CertificateTools.REGISTEREDID), "1.1.1.3");
        assertEquals(X509CertificateTools.getPartFromDN(alt1, X509CertificateTools.XMPPADDR), "tomas@xmpp.domain.com");
        assertEquals(X509CertificateTools.getPartFromDN(alt1, X509CertificateTools.SRVNAME), "_Service.Name");
        assertEquals(X509CertificateTools.getPartFromDN(alt1, X509CertificateTools.FASCN), "0419d23210d8210c2c1a843085a16858300842108608823210c3e1");

        String alt2 = "email=ejbca@primekey.se, dNSName=www.primekey.se, uniformResourceIdentifier=http://www.primekey.se/ejbca";
        assertEquals(X509CertificateTools.getPartFromDN(alt2, X509CertificateTools.EMAIL1), "ejbca@primekey.se");
        assertEquals(X509CertificateTools.getPartFromDN(alt2, X509CertificateTools.URI), "http://www.primekey.se/ejbca");

        String alt3 = "EmailAddress=ejbca@primekey.se, dNSName=www.primekey.se, uniformResourceIdentifier=http://www.primekey.se/ejbca";
        assertEquals(X509CertificateTools.getPartFromDN(alt3, X509CertificateTools.EMAIL2), "ejbca@primekey.se");

        X509Certificate cert = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, guidcert);
        String upn = X509CertificateTools.getUPNAltName(cert);
        assertEquals(upn, "guid@foo.com");
        String guid = X509CertificateTools.getGuidAltName(cert);
        assertEquals("1234567890abcdef", guid);
        String altName = X509CertificateTools.getSubjectAlternativeName(cert);
        // The returned string does not always have the same order so we can't compare strings directly
        assertTrue(altName.contains("guid=1234567890abcdef"));
        assertTrue(altName.contains("rfc822name=guid@foo.com"));
        assertTrue(altName.contains("upn=guid@foo.com"));
        assertTrue(altName.contains("dNSName=guid.foo.com"));
        assertTrue(altName.contains("iPAddress=10.12.13.14"));
        assertTrue(altName.contains("uniformResourceIdentifier=http://guid.foo.com/"));
        assertFalse(altName.contains("foobar"));
        GeneralNames gns = X509CertificateTools.getGeneralNamesFromAltName(altName);
        assertNotNull(gns);
        
        // Test cert containing permanentIdentifier
        cert = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, permanentIdentifierCert);
        upn = X509CertificateTools.getUPNAltName(cert);
        assertEquals("upn1@example.com", upn);
        String permanentIdentifier = X509CertificateTools.getPermanentIdentifierAltName(cert);
        assertEquals("identifier 10003/1.2.3.4.5.6", permanentIdentifier);

        String customAlt = "rfc822Name=foo@bar.com";
        List<String> oids = X509CertificateTools.getCustomOids(customAlt);
        assertEquals(0, oids.size());
        customAlt = "rfc822Name=foo@bar.com, 1.1.1.1.2=foobar, 1.2.2.2.2=barfoo";
        oids = X509CertificateTools.getCustomOids(customAlt);
        assertEquals(2, oids.size());
        String oid1 = oids.get(0);
        assertEquals("1.1.1.1.2", oid1);
        String oid2 = oids.get(1);
        assertEquals("1.2.2.2.2", oid2);
        String val1 = X509CertificateTools.getPartFromDN(customAlt, oid1);
        assertEquals("foobar", val1);
        String val2 = X509CertificateTools.getPartFromDN(customAlt, oid2);
        assertEquals("barfoo", val2);

        customAlt = "rfc822Name=foo@bar.com, 1.1.1.1.2=foobar, 1.1.1.1.2=barfoo";
        oids = X509CertificateTools.getCustomOids(customAlt);
        assertEquals(1, oids.size());
        oid1 = oids.get(0);
        assertEquals("1.1.1.1.2", oid1);
        List<String> list = X509CertificateTools.getPartsFromDN(customAlt, oid1);
        assertEquals(2, list.size());
        val1 = list.get(0);
        assertEquals("foobar", val1);
        val2 =list.get(1);
        assertEquals("barfoo", val2);

        log.trace("<testAltNames()");
    }
    

    
    @Test
    public void testGetGeneralNamesFromAltName4permanentIdentifier() throws Exception {
        // One permanentIdentifier
        String altName = "permanentIdentifier=def321/1.2.5, upn=upn@u.com";
        GeneralNames gn = X509CertificateTools.getGeneralNamesFromAltName(altName);
        assertNotNull("getGeneralNamesFromAltName failed for " + altName, gn);
        String[] result = new String[] { 
            X509CertificateTools.getGeneralNameString(0, gn.getNames()[0].getName()), 
            X509CertificateTools.getGeneralNameString(0, gn.getNames()[1].getName())
        };
        Arrays.sort(result);
        assertEquals("[permanentIdentifier=def321/1.2.5, upn=upn@u.com]", Arrays.toString(result));
        
        // Two permanentIdentifiers
        gn = X509CertificateTools.getGeneralNamesFromAltName("permanentIdentifier=def321/1.2.5, upn=upn@example.com, permanentIdentifier=abcd 456/1.2.7");    
        result = new String[] { 
            X509CertificateTools.getGeneralNameString(0, gn.getNames()[0].getName()),
            X509CertificateTools.getGeneralNameString(0, gn.getNames()[1].getName()),
            X509CertificateTools.getGeneralNameString(0, gn.getNames()[2].getName())
        };
        Arrays.sort(result);
        assertEquals("[permanentIdentifier=abcd 456/1.2.7, permanentIdentifier=def321/1.2.5, upn=upn@example.com]", Arrays.toString(result));
    }
    
    @Test
    public void testIdOnSIM() throws Exception {
        String otherName = "krb5principal=foo/bar@P.SE, " + RFC4683Tools.SUBJECTIDENTIFICATIONMETHOD +"=2.16.840.1.101.3.4.2.1::8db00be05041ad00149e27ad134c64002af06147932d2859413e28add0f01b58::245C975D648DB3B0B27BB1ABAF3A321416340F50FACCE197D28A3F00B2E93C09, upn=upn@u.com";
        GeneralNames gn = X509CertificateTools.getGeneralNamesFromAltName(otherName);
        GeneralName[] names = gn.getNames();
        String ret = X509CertificateTools.getGeneralNameString(0, names[2].getName());
        assertEquals(names.length, 3);
        assertEquals(RFC4683Tools.SUBJECTIDENTIFICATIONMETHOD +"=2.16.840.1.101.3.4.2.1::8db00be05041ad00149e27ad134c64002af06147932d2859413e28add0f01b58::245C975D648DB3B0B27BB1ABAF3A321416340F50FACCE197D28A3F00B2E93C09", ret);

        String sim = X509CertificateTools.getPartFromDN(ret, RFC4683Tools.SUBJECTIDENTIFICATIONMETHOD);
        // Compare the SIM, we know the input that was used to generate the SIM above
        // MyStrongPassword, 1.2.410.200004.10.1.1.10.1 and SIIValue
        String[] simtokens = StringUtils.split(sim, "::");
        assertNotNull("SIM must be tokenized by ::", simtokens);
        assertEquals("There should be 3 SIM tokens", 3, simtokens.length);
        String hashalg = simtokens[0];
        String r = simtokens[1];
        String pepsifromsim = simtokens[2];
        String pepsi = RFC4683Tools.createPepsi(hashalg, "MyStrongPassword", "1.2.410.200004.10.1.1.10.1", "SIIValue", r);
        assertEquals("Calculated PEPSI and PEPSI from SIM must be equal", pepsifromsim, pepsi);

    }
    
    

    @Test
    public void testGetGeneralNamesFromAltName5DirectoryName() throws Exception {
        // One directoryName
        String altName = "directoryName=CN=Tomas\\,O=PrimeKey\\,C=SE";
        GeneralNames gn = X509CertificateTools.getGeneralNamesFromAltName(altName);
        assertNotNull("getGeneralNamesFromAltName failed for " + altName, gn);
        String[] result = new String[] { 
            X509CertificateTools.getGeneralNameString(4, gn.getNames()[0].getName()), 
        };
        Arrays.sort(result);
        assertEquals("[directoryName=CN=Tomas,O=PrimeKey,C=SE]", Arrays.toString(result));
        
        // Test UTF-8
        altName = "directoryName=CN=اتمنى لك يوما طيبا";
        gn = X509CertificateTools.getGeneralNamesFromAltName(altName);
        assertNotNull("getGeneralNamesFromAltName failed for " + altName, gn);
        result = new String[] { 
            X509CertificateTools.getGeneralNameString(4, gn.getNames()[0].getName()), 
        };
        Arrays.sort(result);
        assertEquals("[directoryName=CN=اتمنى لك يوما طيبا]", Arrays.toString(result));
        
    }
    
    /**
     * Tests some of the other methods of X509CertificateTools
     * 
     * @throws Exception
     *             if error...
     */
    @Test
    public void testCertOps() throws Exception {
        log.trace(">testCertOps()");
        X509Certificate cert = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, testcert);
        assertFalse(X509CertificateTools.isCA(cert));
        X509Certificate gcert = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME,guidcert);
        assertEquals("Wrong issuerDN", X509CertificateTools.getIssuerDN(cert), X509CertificateTools.stringToBCDNString("CN=TestCA,O=AnaTom,C=SE"));
        assertEquals("Wrong subjectDN", X509CertificateTools.getSubjectDN(cert), X509CertificateTools.stringToBCDNString("CN=p12test,O=PrimeTest,C=SE"));
        assertEquals("Wrong subject key id", new String(Hex.encode(X509CertificateTools.getSubjectKeyId(cert))),
                "E74F5690F48D147783847CD26448E8094ABB08A0".toLowerCase());
        assertEquals("Wrong authority key id", new String(Hex.encode(X509CertificateTools.getAuthorityKeyId(cert))),
                "637BF476A854248EA574A57744A6F45E0F579251".toLowerCase());
        assertEquals("Wrong upn alt name", "foo@foo", X509CertificateTools.getUPNAltName(cert));
        assertEquals("Wrong guid alt name", "1234567890abcdef", X509CertificateTools.getGuidAltName(gcert));
        assertEquals("Wrong certificate policy", "1.1.1.1.1.1", X509CertificateTools.getCertificatePolicyId(cert, 0));
        assertNull("Not null policy", X509CertificateTools.getCertificatePolicyId(cert, 1));
        log.trace("<testCertOps()");
    }
    
    @Test
    public void testKrb5PrincipalName() throws Exception {
        String altName = "krb5principal=foo/bar@P.SE, upn=upn@u.com";
        GeneralNames gn = X509CertificateTools.getGeneralNamesFromAltName(altName);
        assertNotNull("getGeneralNamesFromAltName failed for " + altName, gn);

        GeneralName[] names = gn.getNames();
        String ret = X509CertificateTools.getGeneralNameString(0, names[1].getName());
        assertEquals("krb5principal=foo/bar@P.SE", ret);

        altName = "krb5principal=foo@P.SE";
        gn = X509CertificateTools.getGeneralNamesFromAltName(altName);
        names = gn.getNames();
        ret = X509CertificateTools.getGeneralNameString(0, names[0].getName());
        assertEquals("krb5principal=foo@P.SE", ret);

        altName = "krb5principal=foo/A.SE@P.SE";
        gn = X509CertificateTools.getGeneralNamesFromAltName(altName);
        names = gn.getNames();
        ret = X509CertificateTools.getGeneralNameString(0, names[0].getName());
        assertEquals("krb5principal=foo/A.SE@P.SE", ret);

        X509Certificate krbcert = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, krb5principalcert);
        String s = X509CertificateTools.getSubjectAlternativeName(krbcert);
        assertEquals("krb5principal=foo/bar@P.COM", s);
    }
    
    @Test
    public void testGetPermanentIdentifierValues() throws Exception {
        assertEquals("[abc123, 1.2.3.7]", Arrays.toString(X509CertificateTools.getPermanentIdentifierValues("abc123/1.2.3.7")));
        assertEquals("[abc123, null]", Arrays.toString(X509CertificateTools.getPermanentIdentifierValues("abc123/")));
        assertEquals("[abc123, null]", Arrays.toString(X509CertificateTools.getPermanentIdentifierValues("abc123")));
        assertEquals("[null, 1.2.3.8]", Arrays.toString(X509CertificateTools.getPermanentIdentifierValues("/1.2.3.8")));
        assertEquals("[null, null]", Arrays.toString(X509CertificateTools.getPermanentIdentifierValues("/")));
        assertEquals("[null, null]", Arrays.toString(X509CertificateTools.getPermanentIdentifierValues("")));
    }
    
    @Test
    public void testGetSubjectAltNameString() throws Exception {
        log.trace(">testGetSubjectAltNameString()");
        X509Certificate altnameCertificate = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, altNameCert);
        X509Certificate testCertificate = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, altNameCert);
        String altNames = X509CertificateTools.getSubjectAlternativeName(altnameCertificate);
        log.debug(altNames);
        String name = X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.UPN);
        assertEquals("foo@a.se", name);
        assertEquals("foo@a.se", X509CertificateTools.getUPNAltName(altnameCertificate));
        name = X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.URI);
        assertEquals("http://www.a.se/", name);
        name = X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.EMAIL);
        assertEquals("tomas@a.se", name);
        name = X509CertificateTools.getEMailAddress(altnameCertificate);
        assertEquals("tomas@a.se", name);
        name = X509CertificateTools.getEMailAddress(testCertificate);
        assertNull(name);
        name = X509CertificateTools.getEMailAddress(null);
        assertNull(name);
        name = X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.DNS);
        assertEquals("www.a.se", name);
        name = X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.IPADDR);
        assertEquals("10.1.1.1", name);
        X509Certificate altNameCertificateWithXmppAddr = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, altNameCertWithXmppAddr);
        altNames = X509CertificateTools.getSubjectAlternativeName(altNameCertificateWithXmppAddr);
        log.debug("altNames: "+altNames);
        name = X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.UPN);
        assertEquals("foo@a.se", name);
        name = X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.REGISTEREDID);
        assertEquals("1.1.1.2", name);
        name = X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.XMPPADDR);
        assertEquals("tomas@xmpp.domain.com", name);
        name = X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.SRVNAME);
        assertEquals("_Service.Name", name);
        name = X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.FASCN);
        assertEquals("0419d23210d8210c2c1a843085a16858300842108608823210c3e1", name);
        name = X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.URI);
        assertEquals("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6", name);
        X509Certificate altNameCertificateWithSpecialCharacters = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, altNameCertWithSpecialCharacters);
        altNames = X509CertificateTools.getSubjectAlternativeName(altNameCertificateWithSpecialCharacters);
        // Note that the actual values in this particular certificate contains \, and \\, so that's why it looks like it's double escaped
        assertEquals("uniformResourceIdentifier=http://x/A\\\\\\,B\\\\\\\\, srvName=test\\\\\\,with\\\\\\\\special=characters, permanentIdentifier=test\\\\\\,with\\\\\\\\special=characters/", altNames);
        assertEquals("test\\,with\\\\special=characters/", X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.PERMANENTIDENTIFIER));
        log.trace("<testGetSubjectAltNameString()");
    }
    
    @Test
    public void testGetSubjectAltNameStringWithDirectoryName() throws Exception {
        log.trace(">testGetSubjectAltNameStringWithDirectoryName()");

        X509Certificate cer = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, altNameCertWithDirectoryName);
        String altNames = X509CertificateTools.getSubjectAlternativeName(cer);
        log.debug(altNames);

        String name = X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.UPN);
        assertEquals("testDirName@jamador.pki.gva.es", name);
        assertEquals("testDirName@jamador.pki.gva.es", X509CertificateTools.getUPNAltName(cer));

        name = X509CertificateTools.getPartFromDN(altNames, X509CertificateTools.DIRECTORYNAME);
        assertEquals("CN=testDirName|dir|name", name.replace("cn=", "CN="));
        assertEquals(name.substring("CN=".length()), (new X500Name("CN=testDirName|dir|name").getRDNs()[0].getFirst().getValue()).toString());

        String altName = "rfc822name=foo@bar.se, uri=http://foo.bar.se, directoryName=" + LDAPDN.escapeRDN("CN=testDirName, O=Foo, OU=Bar, C=SE")
                + ", dnsName=foo.bar.se";
        GeneralNames san = X509CertificateTools.getGeneralNamesFromAltName(altName);
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
        san = X509CertificateTools.getGeneralNamesFromAltName(altName);
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
        log.trace("<testGetSubjectAltNameStringWithDirectoryName()");
    }

    
    @Test
    public void testGetPermanentIdentifierStringFromSequence() throws Exception {
        assertEquals("abc123/1.2.3.4", X509CertificateTools.getPermanentIdentifierStringFromSequence(permanentIdentifier("abc123", "1.2.3.4")));
        assertEquals("defg456/", X509CertificateTools.getPermanentIdentifierStringFromSequence(permanentIdentifier("defg456", null)));
        assertEquals("/1.2.3.5", X509CertificateTools.getPermanentIdentifierStringFromSequence(permanentIdentifier(null, "1.2.3.5")));
        assertEquals("/", X509CertificateTools.getPermanentIdentifierStringFromSequence(permanentIdentifier(null, null)));
        
        assertEquals("ident with \\/ slash/1.2.3.4", X509CertificateTools.getPermanentIdentifierStringFromSequence(permanentIdentifier("ident with / slash", "1.2.3.4")));
        assertEquals("ident with \\/ slash/", X509CertificateTools.getPermanentIdentifierStringFromSequence(permanentIdentifier("ident with / slash", null)));
        assertEquals("ident with \\\\/ slash/1.2.3.6", X509CertificateTools.getPermanentIdentifierStringFromSequence(permanentIdentifier("ident with \\/ slash", "1.2.3.6")));
        assertEquals("ident with \\\\/ slash/", X509CertificateTools.getPermanentIdentifierStringFromSequence(permanentIdentifier("ident with \\/ slash", null)));
    }
    
    private static DERSequence permanentIdentifier(String identifierValue, String assigner) {
        DERSequence result;
        ASN1EncodableVector v = new ASN1EncodableVector(); // this is the OtherName
        v.add(new ASN1ObjectIdentifier(X509CertificateTools.PERMANENTIDENTIFIER_OBJECTID));

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
    
    /**
     */
    @Test
    public void testGetPartFromDN() throws Exception {
        log.trace(">testGetPartFromDN()");

        // We try to examine the general case and some special cases, which we
        // want to be able to handle
        String dn0 = "C=SE, O=AnaTom, CN=foo";
        assertEquals(X509CertificateTools.getPartFromDN(dn0, "CN"), "foo");
        assertEquals(X509CertificateTools.getPartFromDN(dn0, "O"), "AnaTom");
        assertEquals(X509CertificateTools.getPartFromDN(dn0, "C"), "SE");
        assertEquals(X509CertificateTools.getPartFromDN(dn0, "cn"), "foo");
        assertEquals(X509CertificateTools.getPartFromDN(dn0, "o"), "AnaTom");
        assertEquals(X509CertificateTools.getPartFromDN(dn0, "c"), "SE");

        String dn1 = "c=SE, o=AnaTom, cn=foo";
        assertEquals(X509CertificateTools.getPartFromDN(dn1, "CN"), "foo");
        assertEquals(X509CertificateTools.getPartFromDN(dn1, "O"), "AnaTom");
        assertEquals(X509CertificateTools.getPartFromDN(dn1, "C"), "SE");
        assertEquals(X509CertificateTools.getPartFromDN(dn1, "cn"), "foo");
        assertEquals(X509CertificateTools.getPartFromDN(dn1, "o"), "AnaTom");
        assertEquals(X509CertificateTools.getPartFromDN(dn1, "c"), "SE");

        String dn2 = "C=SE, O=AnaTom, CN=cn";
        assertEquals(X509CertificateTools.getPartFromDN(dn2, "CN"), "cn");

        String dn3 = "C=SE, O=AnaTom, CN=CN";
        assertEquals(X509CertificateTools.getPartFromDN(dn3, "CN"), "CN");

        String dn4 = "C=CN, O=AnaTom, CN=foo";
        assertEquals(X509CertificateTools.getPartFromDN(dn4, "CN"), "foo");

        String dn5 = "C=cn, O=AnaTom, CN=foo";
        assertEquals(X509CertificateTools.getPartFromDN(dn5, "CN"), "foo");

        String dn6 = "CN=foo, O=PrimeKey, C=SE";
        assertEquals(X509CertificateTools.getPartFromDN(dn6, "CN"), "foo");
        assertEquals(X509CertificateTools.getPartFromDN(dn6, "O"), "PrimeKey");
        assertEquals(X509CertificateTools.getPartFromDN(dn6, "C"), "SE");

        String dn7 = "CN=foo, O=PrimeKey, C=cn";
        assertEquals(X509CertificateTools.getPartFromDN(dn7, "CN"), "foo");
        assertEquals(X509CertificateTools.getPartFromDN(dn7, "C"), "cn");

        String dn8 = "CN=foo, O=PrimeKey, C=CN";
        assertEquals(X509CertificateTools.getPartFromDN(dn8, "CN"), "foo");
        assertEquals(X509CertificateTools.getPartFromDN(dn8, "C"), "CN");

        String dn9 = "CN=foo, O=CN, C=CN";
        assertEquals(X509CertificateTools.getPartFromDN(dn9, "CN"), "foo");
        assertEquals(X509CertificateTools.getPartFromDN(dn9, "O"), "CN");

        String dn10 = "CN=foo, CN=bar,O=CN, C=CN";
        assertEquals(X509CertificateTools.getPartFromDN(dn10, "CN"), "foo");
        assertEquals(X509CertificateTools.getPartFromDN(dn10, "O"), "CN");

        String dn11 = "CN=foo,CN=bar, O=CN, C=CN";
        assertEquals(X509CertificateTools.getPartFromDN(dn11, "CN"), "foo");
        assertEquals(X509CertificateTools.getPartFromDN(dn11, "O"), "CN");

        String dn12 = "CN=\"foo, OU=bar\", O=baz\\\\\\, quux,C=C";
        assertEquals("Extraction of CN from: "+dn12, "foo, OU=bar", X509CertificateTools.getPartFromDN(dn12, "CN"));
        assertEquals("Extraction of O from: "+dn12, "baz\\, quux", X509CertificateTools.getPartFromDN(dn12, "O"));
        assertNull(X509CertificateTools.getPartFromDN(dn12, "OU"));

        String dn13 = "C=SE, O=PrimeKey, EmailAddress=foo@primekey.se";
        List<String> emails = X509CertificateTools.getEmailFromDN(dn13);
        assertEquals(emails.get(0), "foo@primekey.se");

        String dn14 = "C=SE, E=foo@primekey.se, O=PrimeKey";
        emails = X509CertificateTools.getEmailFromDN(dn14);
        assertEquals(emails.get(0), "foo@primekey.se");

        String dn15 = "C=SE, E=foo@primekey.se, O=PrimeKey, EmailAddress=bar@primekey.se";
        emails = X509CertificateTools.getEmailFromDN(dn15);
        assertEquals(emails.get(0), "bar@primekey.se");

        String dn16 = "SUBJECTIDENTIFICATIONMETHOD=2.16.840.1.101.3.4.2.1::MyStrongPassword::1.2.410.200004.10.1.1.10.1::SsiValue";
        String sim = X509CertificateTools.getPartFromDN(dn16, "SUBJECTIDENTIFICATIONMETHOD");
        assertEquals(sim, "2.16.840.1.101.3.4.2.1::MyStrongPassword::1.2.410.200004.10.1.1.10.1::SsiValue");
        String dn17 = "subjectIdentificationMethod=2.16.840.1.101.3.4.2.1::MyStrongPassword::1.2.410.200004.10.1.1.10.1::SsiValue";
        sim = X509CertificateTools.getPartFromDN(dn17, "SUBJECTIDENTIFICATIONMETHOD");
        assertEquals(sim, "2.16.840.1.101.3.4.2.1::MyStrongPassword::1.2.410.200004.10.1.1.10.1::SsiValue");

        log.trace("<testGetPartFromDN()");
    }
    
    /**
     */
    @Test
    public void testGetPartsFromDN() throws Exception {

        // We try to examine the general case and som special cases, which we
        // want to be able to handle
        String dn0 = "C=SE, O=AnaTom, CN=foo";
        assertEquals(X509CertificateTools.getPartsFromDN(dn0, "CN").size(), 1);
        assertTrue(X509CertificateTools.getPartsFromDN(dn0, "CN").contains("foo"));
        assertEquals(X509CertificateTools.getPartsFromDN(dn0, "O").size(), 1);
        assertTrue(X509CertificateTools.getPartsFromDN(dn0, "O").contains("AnaTom"));
        assertEquals(X509CertificateTools.getPartsFromDN(dn0, "C").size(), 1);
        assertTrue(X509CertificateTools.getPartsFromDN(dn0, "C").contains("SE"));
        assertEquals(X509CertificateTools.getPartsFromDN(dn0, "cn").size(), 1);
        assertTrue(X509CertificateTools.getPartsFromDN(dn0, "cn").contains("foo"));
        assertEquals(X509CertificateTools.getPartsFromDN(dn0, "o").size(), 1);
        assertTrue(X509CertificateTools.getPartsFromDN(dn0, "o").contains("AnaTom"));
        assertEquals(X509CertificateTools.getPartsFromDN(dn0, "c").size(), 1);
        assertTrue(X509CertificateTools.getPartsFromDN(dn0, "c").contains("SE"));

        String dn1 = "uri=http://www.a.se, C=SE, O=AnaTom, CN=foo";
        assertEquals(X509CertificateTools.getPartsFromDN(dn1, "CN").size(), 1);
        assertTrue(X509CertificateTools.getPartsFromDN(dn1, "CN").contains("foo"));
        assertEquals(X509CertificateTools.getPartsFromDN(dn1, X509CertificateTools.URI).size(), 0);
        assertEquals(X509CertificateTools.getPartsFromDN(dn1, X509CertificateTools.URI1).size(), 1);
        assertTrue(X509CertificateTools.getPartsFromDN(dn1, X509CertificateTools.URI1).contains("http://www.a.se"));

        String dn2 = "uri=http://www.a.se, uri=http://www.b.se, C=SE, O=AnaTom, CN=foo";
        assertEquals(X509CertificateTools.getPartsFromDN(dn2, "CN").size(), 1);
        assertTrue(X509CertificateTools.getPartsFromDN(dn2, "CN").contains("foo"));
        assertEquals(X509CertificateTools.getPartsFromDN(dn2, X509CertificateTools.URI1).size(), 2);
        assertTrue(X509CertificateTools.getPartsFromDN(dn2, X509CertificateTools.URI1).contains("http://www.a.se"));
        assertTrue(X509CertificateTools.getPartsFromDN(dn2, X509CertificateTools.URI1).contains("http://www.b.se"));

        String dn3 = "CN=test\\\"test, dNSName=, dNSName=";
        assertEquals(2, X509CertificateTools.getPartsFromDN(dn3, "dNSName").size());
        assertEquals("", X509CertificateTools.getPartsFromDN(dn3, "dNSName").get(0));
        assertEquals("", X509CertificateTools.getPartsFromDN(dn3, "dNSName").get(1));
        
        String dn4 = "CN=test\\+with\\,escaped=characters";
        assertEquals(1, X509CertificateTools.getPartsFromDN(dn4, "CN").size());
        assertEquals("test+with,escaped=characters", X509CertificateTools.getPartsFromDN(dn4, "CN").get(0));
        
        log.trace("<testGetPartsFromDN()");
    }
    
    @Test
    public void testNameConstraintAreCorrectInCert() throws Exception {
        final String excluded = ".\n" + "example.com";
        final List<Extension> extensions = new ArrayList<>();
        List<String> ncList = NameConstraint.parseNameConstraintsList(excluded);
        GeneralSubtree[] excludedSubtrees = NameConstraint.toGeneralSubtrees(ncList);
        byte[] extdata = new NameConstraints(null, excludedSubtrees).toASN1Primitive().getEncoded();
        extensions.add(new Extension(Extension.nameConstraints, false, extdata));
        final KeyPair testkeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate cacert = X509CertificateTools.genSelfCertForPurpose("C=SE,CN=Test Name Constraints CA", 365, null, testkeys.getPrivate(),
                testkeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null,
                "BC", true, extensions);

        final byte[] ncbytes = cacert.getExtensionValue(Extension.nameConstraints.getId());
        final ASN1OctetString ncstr = (ncbytes != null ? ASN1OctetString.getInstance(ncbytes) : null);
        final ASN1Sequence ncseq = (ncbytes != null ? ASN1Sequence.getInstance(ncstr.getOctets()) : null);
        final NameConstraints nc = (ncseq != null ? NameConstraints.getInstance(ncseq) : null);
        GeneralSubtree[] excludedST = nc.getExcludedSubtrees();
        assertNotNull("Excluded sub tree was null!", excludedST);
        assertEquals("Array size did not match", 2, excludedST.length);
        assertEquals("Domain not match!", "2: ", excludedST[0].getBase().toString());
        assertEquals("Domain not match!", "2: example.com", excludedST[1].getBase().toString());
    }
    
    

    

}
