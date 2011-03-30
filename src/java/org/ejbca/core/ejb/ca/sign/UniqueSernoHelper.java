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
package org.ejbca.core.ejb.ca.sign;

import java.io.ByteArrayInputStream;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;

/** This class mostly exists in order to avoid having static non-final variables in SignSessionBean (not allowed according to EJB spec.
 * This class holds the variable isUniqueCertificateSerialNumberIndex, which is initialized by calling, once (or several times)
 * UniqueSernoHelper.testUniqueCertificateSerialNumberIndex(). Actually calling this method only does something once, called several times does nothing
 * and does not change any values returned by isUniqueCertificateSerialNumberIndex().
 *  
 * @version $Id$
 */
public final class UniqueSernoHelper {
    private static final Logger log = Logger.getLogger(UniqueSernoHelper.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

	static private Boolean isUniqueCertificateSerialNumberIndex = null;

	/**
	 * Will test if there is a unique index/constraint for (certificate serial number,issuer DN) first time it is run.
	 * @return returns true if there is a database index for unique certificate serial number / issuer DN.
	 */
	protected static final boolean isUniqueCertificateSerialNumberIndex(final CertificateStoreSession certificateStoreSession) {
		testUniqueCertificateSerialNumberIndex(certificateStoreSession);
		return isUniqueCertificateSerialNumberIndex!=null && isUniqueCertificateSerialNumberIndex.booleanValue();
	}
	
	/** sets variables (but only once) that can be checked with isUniqueCertificateSerialNumberIndex(). This method must be called first (at least once) */
	private static final void testUniqueCertificateSerialNumberIndex(final CertificateStoreSession certificateStoreSession) {
		if (isUniqueCertificateSerialNumberIndex == null) {
			final String userName = "checkUniqueIndexTestUserNotToBeUsed_fjasdfjsdjfsad"; // This name should only be used for this test. Made complex so that no one else will use the same.
			// Loading two dummy certificates. These certificates has same serial number and issuer.
			// It should not be possible to store both of them in the DB.
			final X509Certificate cert1;
			final X509Certificate cert2;
			{
				final byte certEncoded1[];
				final byte certEncoded2[];
				{
					final String certInBase64 =
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
					certEncoded1= Base64.decode(certInBase64);
				}{
					final String certInBase64 =
						"MIIB8zCCAVygAwIBAgIESZYC0jANBgkqhkiG9w0BAQUFADApMScwJQYDVQQDDB5D"+
						"QSBmb3IgRUpCQ0EgdGVzdCBjZXJ0aWZpY2F0ZXMwHhcNMTAwNjI2MDU1MDA4WhcN"+
						"MjAwNjI2MDU1MDA4WjA1MTMwMQYDVQQDDCpBbGxvdyBjZXJ0aWZpY2F0ZSBzZXJp"+
						"YWwgbnVtYmVyIG92ZXJyaWRlIDIwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAn2H4"+
						"IAMYZyXqkSTY4Slq9LKZ/qB5wc+3hbEHNawdOoMBBkhLGi2q49sbCdcI8AZi3med"+
						"sm8+A8Q4NHFRKdOYuwIDAQABo2AwXjAdBgNVHQ4EFgQUhWVwIsv18DIYszvRzqDg"+
						"AkGO8QkwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQ/TRpUbLxt6j6EC3olHGWJ"+
						"7XZqETAOBgNVHQ8BAf8EBAMCBwAwDQYJKoZIhvcNAQEFBQADgYEAM8laLm4bgMTz"+
						"e9TLmwcmhwqevPrfea9jdiNafHCyb+JVppoLVHqAZjPs3Lvlxdt2d75au5+QcJ/Z"+
						"9RgakF8Vq29Tz3xrYYIQe9VtlaUzw/dgsDfZi6V8W57uHLpU65fe5afwfi+5XDZk"+
						"TaTsNgFz8NorE2f7ILSm2FcfIpC+GPI=";
					certEncoded2 = Base64.decode(certInBase64);
				}
				try {
					final CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
					cert1 = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certEncoded1));
					cert2 = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certEncoded2));
				} catch( CertificateException e ) {
					throw new RuntimeException( "Not possible to generate predefined dummy certificate. Should never happen", e );
				} catch (NoSuchProviderException e) {
					throw new RuntimeException( "Not possible to generate predefined dummy certificate. Should never happen", e );
				}
			}
			final Admin admin = Admin.getInternalAdmin();
			final Certificate c1 = certificateStoreSession.findCertificateByFingerprint(admin, CertTools.getFingerprintAsString(cert1));
			final Certificate c2 = certificateStoreSession.findCertificateByFingerprint(admin, CertTools.getFingerprintAsString(cert2));
			if ( (c1 != null) && (c2 != null) ) {
				// already proved that not checking index for serial number.
				isUniqueCertificateSerialNumberIndex = Boolean.valueOf(false);
			}
			if (c1 == null) {// storing initial certificate if no test certificate created.
				try {
				    certificateStoreSession.storeCertificate(admin, cert1, userName, "abcdef0123456789", SecConst.CERT_INACTIVE, 0, 0, "", new Date().getTime());
				} catch (Throwable e) {
					throw new RuntimeException("It should always be possible to store initial dummy certificate.", e);
				}
			}
			isUniqueCertificateSerialNumberIndex = Boolean.valueOf(false);			
			if (c2 == null) { // storing a second certificate with same issuer 
				try { 
					certificateStoreSession.storeCertificate(admin, cert2, userName, "fedcba9876543210", SecConst.CERT_INACTIVE, 0, 0, "", new Date().getTime());
				} catch (Throwable e) {
					log.info("Unique index in CertificateData table for certificate serial number");
					// Exception is thrown when unique index is working and a certificate with same serial number is in the database.
					isUniqueCertificateSerialNumberIndex = Boolean.valueOf(true);
				}
			}
			if (!isUniqueCertificateSerialNumberIndex.booleanValue()) {
				// It was possible to store a second certificate with same serial number. Unique number not working.
				log.info( intres.getLocalizedMessage("signsession.not_unique_certserialnumberindex") );
			}
		}
	}

}
