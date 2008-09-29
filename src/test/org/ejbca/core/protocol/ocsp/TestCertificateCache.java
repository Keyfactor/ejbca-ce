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
package org.ejbca.core.protocol.ocsp;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;

import junit.framework.TestCase;

import org.bouncycastle.ocsp.CertificateID;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/**
 * @author tomas
 * @version $Id$
 */
public class TestCertificateCache extends TestCase {

	protected void setUp() throws Exception {
		CertTools.installBCProvider();
	}

	public void test01CACertificates() throws Exception {
		// Prepare the certificate cache with some test certificates
		Properties prop = new Properties();
		prop.put("ocspSigningCertsValidTime", new Integer(15));
		Collection certs = new ArrayList();
		X509Certificate testrootcert = (X509Certificate)CertTools.getCertfromByteArray(testroot);
		certs.add(testrootcert);
		X509Certificate testrootnewcert = (X509Certificate)CertTools.getCertfromByteArray(testrootnew);
		certs.add(testrootnewcert);
		X509Certificate testsubcert = (X509Certificate)CertTools.getCertfromByteArray(testsub);
		certs.add(testsubcert);
		Certificate testcvccert = CertTools.getCertfromByteArray(testcvc);
		certs.add(testcvccert);
		X509Certificate testscepcert = (X509Certificate)CertTools.getCertfromByteArray(testscepca);
		certs.add(testscepcert);
		prop.put("ocspTestCACerts", certs);
		CertificateCache cache = new CertificateCache(prop);
		
		// Test lookup of not existing cert
		X509Certificate cert = cache.findLatestBySubjectDN("CN=Foo,C=SE");
		assertNull(cert);
		// Old root cert should not be found, we only store the latest to be found by subjectDN
		X509Certificate rootcert = cache.findLatestBySubjectDN(CertTools.getSubjectDN(testrootnewcert));
		assertNotNull(rootcert);
		X509Certificate subcert = cache.findLatestBySubjectDN(CertTools.getSubjectDN(testsubcert));
		// This old subcert should not be possible to verify with the new root cert
		boolean failed = false;
		try {
			subcert.verify(rootcert.getPublicKey());
		} catch (InvalidKeyException e) {
			failed = true;
		}
		assertTrue(failed);
		// CVC certificate should not be part of OCSP certificate cache
		cert = cache.findLatestBySubjectDN(CertTools.getSubjectDN(testcvccert));
		assertNull(cert);
		cert = cache.findLatestBySubjectDN(CertTools.getSubjectDN(testscepcert));
		assertEquals(CertTools.getSubjectDN(testscepcert), CertTools.getSubjectDN(cert));
		
		// Test lookup based on CertID
		cert = cache.findByHash(new CertificateID(CertificateID.HASH_SHA1, testrootcert, BigInteger.valueOf(0)));
		assertNotNull(cert);
		// The old subcert should verify with this old rootcert
		subcert.verify(cert.getPublicKey());
		// But not with the new rootcert
		cert = cache.findByHash(new CertificateID(CertificateID.HASH_SHA1, testrootnewcert, BigInteger.valueOf(0)));
		assertNotNull(cert);
		failed = false;
		try {
			subcert.verify(cert.getPublicKey());
		} catch (InvalidKeyException e) {
			failed = true;
		}
		assertTrue(failed);
		
		// See that it will work when we add the new subcert, to verify with the new rootcert
		X509Certificate testsubcertnew = (X509Certificate)CertTools.getCertfromByteArray(testsubnew);
		certs.add(testsubcertnew);
		prop.put("ocspTestCACerts", certs);
		cache = new CertificateCache(prop);
		subcert = cache.findByHash(new CertificateID(CertificateID.HASH_SHA1, testsubcertnew, BigInteger.valueOf(0)));
		assertNotNull(subcert);
		subcert.verify(cert.getPublicKey());
		subcert = cache.findLatestBySubjectDN(CertTools.getSubjectDN(testsubcertnew));
		assertNotNull(subcert);
		subcert.verify(cert.getPublicKey());
	}


	private static byte[] testroot = Base64
	.decode(("MIICPDCCAaWgAwIBAgIIV++ss+Mrw5MwDQYJKoZIhvcNAQEFBQAwLjERMA8GA1UE"+
			"AwwIVGVzdFJvb3QxDDAKBgNVBAoMA0ZvbzELMAkGA1UEBhMCU0UwHhcNMDgwOTI5"+
			"MTM0MjQwWhcNMTYxMjE2MTM0MjQwWjAuMREwDwYDVQQDDAhUZXN0Um9vdDEMMAoG"+
			"A1UECgwDRm9vMQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC"+
			"gYEAwdqYTCu31Xklrx2isHXUIpSrjD0mGyzPW/qPzolnEsSKAkLW+X8UJ8KcN9ky"+
			"tsJ9sUSHGGmQFtKP4gyhqJymqHKGVjEIxri223svJ5K8gQezC6XDemxXSRR71Yc4"+
			"9OM8kpNNVlFU8rZLMNz+xgY9AtAfIczOzqM16DgBmXBUsrECAwEAAaNjMGEwHQYD"+
			"VR0OBBYEFPPHQ/qJU5mliblHt5kq39l0C82SMA8GA1UdEwEB/wQFMAMBAf8wHwYD"+
			"VR0jBBgwFoAU88dD+olTmaWJuUe3mSrf2XQLzZIwDgYDVR0PAQH/BAQDAgGGMA0G"+
			"CSqGSIb3DQEBBQUAA4GBABbKUK1KKofZ3w0a15HIsT6MK/3qKZp/pE0l8GWplk2t"+
			"YEE1fkAbWolreKHG79HP4a0X/FOxd11qDeGzoGjFsLxrLNlxZCH8GyI/mILTNpba"+
	"5/b9Xrjqj2rTYQOIXeakxCsMbMT+tg7ZHdUPmgcWxtqXlEhOdtZFJd8+u8tDgbsn").getBytes());

	private static byte[] testrootnew = Base64
	.decode(("MIICPDCCAaWgAwIBAgIIC662hmhBnZowDQYJKoZIhvcNAQEFBQAwLjERMA8GA1UE"+
			"AwwIVGVzdFJvb3QxDDAKBgNVBAoMA0ZvbzELMAkGA1UEBhMCU0UwHhcNMDgwOTI5"+
			"MTM0MzM3WhcNMTYxMjE2MTM0MzM3WjAuMREwDwYDVQQDDAhUZXN0Um9vdDEMMAoG"+
			"A1UECgwDRm9vMQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC"+
			"gYEAtIDhCc+3/BvugFO1n30V3g9GfrLstMeEq3kNvEF5saymdPTrHfrFR5uPo5Oq"+
			"NAt7EoxTkfQLBhBHI8hpame/84MMbedynxhzLOiQ2XYLo8VKYghC7lJhx3oW0ksV"+
			"EpNv5R7hVJvfiYkHry9k9I/uQuA2W1VIDTIHj4HSl2rk65cCAwEAAaNjMGEwHQYD"+
			"VR0OBBYEFNrpYRScm6wyswfE29bOIKcBXTw1MA8GA1UdEwEB/wQFMAMBAf8wHwYD"+
			"VR0jBBgwFoAU2ulhFJybrDKzB8Tb1s4gpwFdPDUwDgYDVR0PAQH/BAQDAgGGMA0G"+
			"CSqGSIb3DQEBBQUAA4GBAEmNfSwgrUZlSLWcOWNcLgUKK1ownvxAZevCAlxgpLIV"+
			"PqbpBmgoCYjvAB1O1kuEg52VT+mGSpnZi4LjylDmNosu60E3jI/FsP6e6d2hH7ZY"+
	"BMvj/m5uhSQArLo5R2NRIkmR34tXqOjTsL+3+n3sT2H5++9D1+ZqpAP2Sn1Ba8GB").getBytes());

	private static byte[] testsub = Base64
	.decode(("MIICOzCCAaSgAwIBAgIIFUunDyPOxAIwDQYJKoZIhvcNAQEFBQAwLjERMA8GA1UE"+
			"AwwIVGVzdFJvb3QxDDAKBgNVBAoMA0ZvbzELMAkGA1UEBhMCU0UwHhcNMDgwOTI5"+
			"MTM0MzA5WhcNMTYxMjE2MTM0MjQwWjAtMRAwDgYDVQQDDAdUZXN0U3ViMQwwCgYD"+
			"VQQKDANGb28xCzAJBgNVBAYTAlNFMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"+
			"gQCX+ZIrBqpeTILZZZPVBPB07+De19a0857G5zU7BAtpxIDULX1OsMiGdVBtX/5W"+
			"4Cm9/G2Eo1Eqm+xiP06HlFmfU58XlkUR9v3OLXZ3Rza3n//HcPXsDnLvkcPrUFcs"+
			"LNSg4b2bPPiFtBkghD796+8ltJrNhJfR64AUWfSx/ttLIQIDAQABo2MwYTAdBgNV"+
			"HQ4EFgQUwt1LdwXjTeZ0yldTclKlDA+eHWQwDwYDVR0TAQH/BAUwAwEB/zAfBgNV"+
			"HSMEGDAWgBTzx0P6iVOZpYm5R7eZKt/ZdAvNkjAOBgNVHQ8BAf8EBAMCAYYwDQYJ"+
			"KoZIhvcNAQEFBQADgYEAHG6JVMk/hQN8OdCnGvricq7deGlbWA7WEf5sxY1RekuN"+
			"QTDenb5DWcN6XcuSHZsXJUGn3yEDjYpY6KL95XCw8mzTjmYN0sbIM3QEN0G3euir"+
	"dAOftW06blL0zNiQ6/z4MrGmZgTf9Agf5W6uhsx2BwVCMN7bVWVIm9MlU+SW6YM=").getBytes());

	private static byte[] testsubnew = Base64
	.decode(("MIICOzCCAaSgAwIBAgIIXww57ODOukwwDQYJKoZIhvcNAQEFBQAwLjERMA8GA1UE"+
			"AwwIVGVzdFJvb3QxDDAKBgNVBAoMA0ZvbzELMAkGA1UEBhMCU0UwHhcNMDgwOTI5"+
			"MTM0MzUxWhcNMTYxMjE2MTM0MzM3WjAtMRAwDgYDVQQDDAdUZXN0U3ViMQwwCgYD"+
			"VQQKDANGb28xCzAJBgNVBAYTAlNFMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"+
			"gQCLCUlieZMkY8zN/BmTYnQ708utPv0tQauk94Hoh/Bbg5K2GPXibpNCZWiYlWIF"+
			"ErTqWCMSf5N6M1l0qlWBcb+ez7bzPl6sBsUBUfY1Uu7D7nFAX6i4mPf8VqvDT2yt"+
			"4X31S1/3VjHarLgqHS++GZD5h7q6MsOxHfuljafmW6ikYwIDAQABo2MwYTAdBgNV"+
			"HQ4EFgQUmEEcFdMkrbtCel5Qs2OycgcRF60wDwYDVR0TAQH/BAUwAwEB/zAfBgNV"+
			"HSMEGDAWgBTa6WEUnJusMrMHxNvWziCnAV08NTAOBgNVHQ8BAf8EBAMCAYYwDQYJ"+
			"KoZIhvcNAQEFBQADgYEAVKRhuAV1nj1Oi39yLijm8lbq3UJ6xjMgz4wcURXBlx9T"+
			"Az1pvN1Bpj/JmkNfYpvSmX1UP3suntgNpgGoCFxxTuelmmyH9vpSsWeCjiBK/Il9"+
	"/jhrwrbwF8uoBSkvoE+imcuLD7mbMn66wc1s7akdHXPORxhKs3PJppXjcurxAXM=").getBytes());

	private static byte[] testcvc = Base64
	.decode(("fyGCAWh/ToHgXykBAEIOU0VDVkNUZXN0MDAwMDF/SYGUBgoEAH8ABwICAgEBgYGA"+
			"h2uvpDVvYQygDCpZ91ln37I2UcEAPFSjgsNGRq1tJ6Xl+SueIbdR8zfc62+8yNBH"+
			"3PsI/Ogt48NehSI2Z4CAXMbE4coyB7iQHlXUKpb+oBgXU+7LsDxvgDXtcypZwxJ2"+
			"PePOnkXUL7HY384skrwxqUDU/xrTvD/5M0yEIHcoAn+CAwEAAV8gDlNFQ1ZDVGVz"+
			"dDAwMDAxf0wOBgkEAH8ABwMBAgFTAcNfJQYACAAJAglfJAYBAQEAAQVfN4GANzKf"+
			"g4ItaN47UZDTMHiJ3ZVyPl+kHSKqUKH7HaKOblfGoNjAj80iAm9Igk+c8A7IzGpI"+
			"z17COVI1WexxFk25cOoxcMloCKwWCSXHR5NNvDOGiVlszjv4f5xQ1dw6nQmzy8q/"+
	"aO1xupXZzGSTeMxs3Ex1LYsZGJnHCa/xDf017n4=").getBytes());

	private static byte[] testscepca = Base64
	.decode(("MIICzjCCAbagAwIBAgIILbZXprQLU6EwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"+
			"AwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw"+
			"HhcNMDgwOTI0MTQ0OTE5WhcNMDkwMTEzMTQ0OTE5WjA2MRAwDgYDVQQDDAdTY2Vw"+
			"IENBMRUwEwYDVQQKDAxFSkJDQSBTYW1wbGUxCzAJBgNVBAYTAlNFMIGfMA0GCSqG"+
			"SIb3DQEBAQUAA4GNADCBiQKBgQCh6H9flRL2prEjZDr9sDjmoT7kckILiW6cJ4VG"+
			"aPh2B8IHct+2QUlZ0Bjk0c7Jdq0USaItDl9V3yQRweCrl+WHMAiAwWRJIQAXi1B5"+
			"8xbZJPIvJ0SpPeM9fNGoqlIYZRWoHblOAdCFiUHA/yKgPuH7AN5sYAppm/iP8BEa"+
			"/o9nawIDAQABo2MwYTAdBgNVHQ4EFgQU5J8drR5lZGK1p12hfq2Z+PgWz+4wDwYD"+
			"VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBSSeB41+0/rZ+2/qiX7X4bvrVKjWDAO"+
			"BgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQEFBQADggEBADjUPxvEEijoIJ+/93+0"+
			"3zASkDQoI9vPOh7AIRya9KF5EeiTXNJghTs078n7TGPP21y7TDnE1CU218B6QPMd"+
			"+L0c+WMUtr/6i4lI2Nh/wvKbBLEPKutrnFQbZY4MlTXS3Iu15VqawppFf+tVVuZQ"+
			"KHx0ynzxToAJRCuryOBl/iRrBaXNyoMOYcooJhHTO/g/0/0enAPnWz39bl4CAgCi"+
			"NfseeJcdbQFcjCyruIf2NL+8l8AuZXyLuMQE6/yqxUdNv7gZvrpk5Z+c9ZcseLTl"+
			"3GHFTxIySlmZCblZbJzQxO5pRz27B2vPJqicA0cmoBxUQK3NHGO+WyQ+ZpZX5vl/"+
	"+xc=").getBytes());
}
