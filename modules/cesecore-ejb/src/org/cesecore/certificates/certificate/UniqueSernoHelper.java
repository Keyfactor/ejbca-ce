/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import java.io.ByteArrayInputStream;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


/** This class only exists in order to avoid having static non-final variables in CertificateStoreSessionBean (not allowed according to EJB spec).
 * This class holds the variable isUniqueCertificateSerialNumberIndex, which is initialized by calling, once (or several times)
 * CertificateStoreSessionLocal.checkForUniqueCertificateSerialNumberIndex(). Actually calling this method only does something once, called several times does nothing
 * and does not change any values returned by isUniqueCertificateSerialNumberIndex().
 *  
 * @version $Id$
 */
public final class UniqueSernoHelper {

	static private Boolean isUniqueCertificateSerialNumberIndex = null;

    private final static String TEST_CERTIFICATE_B64_1 =
            "MIIB8zCCAVygAwIBAgIESZYC0jANBgkqhkiG9w0BAQUFADApMScwJQYDVQQDDB5D"+
            "QSBmb3IgRUpCQ0EgdGVzdCBjZXJ0aWZpY2F0ZXMwHhcNMTAwNjI2MDU0OTM2WhcN"+
            "MjAwNjI2MDU0OTM2WjA1MTMwMQYDVQQDDCpBbGxvdyBjZXJ0aWZpY2F0ZSBzZXJp"+
            "YWwgbnVtYmVyIG92ZXJyaWRlIDEwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAnnIj"+
            "y8A6CJzASedM5MbZk/ld8R3P0aWfRSW2UUDaskm25oK5SsjwVZD3KEc3IJgyl1/D"+
            "lWdywxEduWwc2nzGGQIDAQABo2AwXjAdBgNVHQ4EFgQUPL3Au/wYZbD3TpNGW1G4"+
            "+Ck4A2swDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQ/TRpUbLxt6j6EC3olHGWJ"+
            "7XZqETAOBgNVHQ8BAf8EBAMCBwAwDQYJKoZIhvcNAQEFBQADgYEAPMWjE5hv3G5T"+
            "q/fzPQlRMCQDoM5EgVwJYQu1S+wns/mKPI/bDv9s5nybKoro70LKpqLb1+f2TaD+"+
            "W2Ro+ni8zYm5+H6okXRIc5Kd4LlD3tjsOF7bS7fixvMCSCUgLxQOt2creOqfDVjm"+
            "i6MA48AhotWmx/rlzQXhnvuKnMI3m54=";
    private final static String TEST_CERTIFICATE_B64_2 =
            "MIIB8zCCAVygAwIBAgIESZYC0jANBgkqhkiG9w0BAQUFADApMScwJQYDVQQDDB5D" +
            "QSBmb3IgRUpCQ0EgdGVzdCBjZXJ0aWZpY2F0ZXMwHhcNMTAwNjI2MDU1MDA4WhcN" +
            "MjAwNjI2MDU1MDA4WjA1MTMwMQYDVQQDDCpBbGxvdyBjZXJ0aWZpY2F0ZSBzZXJp" +
            "YWwgbnVtYmVyIG92ZXJyaWRlIDIwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAn2H4" +
            "IAMYZyXqkSTY4Slq9LKZ/qB5wc+3hbEHNawdOoMBBkhLGi2q49sbCdcI8AZi3med" +
            "sm8+A8Q4NHFRKdOYuwIDAQABo2AwXjAdBgNVHQ4EFgQUhWVwIsv18DIYszvRzqDg" +
            "AkGO8QkwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQ/TRpUbLxt6j6EC3olHGWJ" +
            "7XZqETAOBgNVHQ8BAf8EBAMCBwAwDQYJKoZIhvcNAQEFBQADgYEAM8laLm4bgMTz" +
            "e9TLmwcmhwqevPrfea9jdiNafHCyb+JVppoLVHqAZjPs3Lvlxdt2d75au5+QcJ/Z" +
            "9RgakF8Vq29Tz3xrYYIQe9VtlaUzw/dgsDfZi6V8W57uHLpU65fe5afwfi+5XDZk" +
            "TaTsNgFz8NorE2f7ILSm2FcfIpC+GPI=";

    public static X509Certificate getTestCertificate1() { return getTestCertificate(TEST_CERTIFICATE_B64_1); }
    public static X509Certificate getTestCertificate2() { return getTestCertificate(TEST_CERTIFICATE_B64_2); }

    private static X509Certificate getTestCertificate(final String base64EncodedCertificate) {
        final X509Certificate ret;
        final byte certEncoded1[];
        certEncoded1= org.bouncycastle.util.encoders.Base64.decode(base64EncodedCertificate);
        try {
            final CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            ret = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certEncoded1));
        } catch (CertificateException e) {
            throw new RuntimeException( "Not possible to generate predefined dummy certificate. Should never happen", e );
        } catch (NoSuchProviderException e) {
            throw new RuntimeException( "Not possible to generate predefined dummy certificate. Should never happen", e );
        }
        return ret;
    }

	/** Don't create any of this */
	private UniqueSernoHelper() {};
	
	/** @return isUniqueCertificateSerialNumberIndex, can be null which should be interpreted as uninitialized */
	public static Boolean getIsUniqueCertificateSerialNumberIndex() {
        return isUniqueCertificateSerialNumberIndex;
    }

	/** Sets isUniqueCertificateSerialNumberIndex, can set to null which should be interpreted as uninitialized */
    public static void setIsUniqueCertificateSerialNumberIndex(Boolean isUniqueCertificateSerialNumberIndex) {
        UniqueSernoHelper.isUniqueCertificateSerialNumberIndex = isUniqueCertificateSerialNumberIndex;
    }	
}
