/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.xkms;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;

/**
 * Class containing constants common for unit tests.
 * 
 * @author Philip Vendil
 * $Id$
 */
public class Constants {
	
	private static byte[] certroottest = Base64.decode((
			 "MIIDCzCCAfOgAwIBAgIIK5kLeM4VChowDQYJKoZIhvcNAQEFBQAwEzERMA8GA1UE"
			+"AxMIY2VydHRlc3QwHhcNMDYwMTMxMTAxNTE1WhcNMjYwMjE1MTAyNTE1WjATMREw"
			+"DwYDVQQDEwhjZXJ0dGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB"
			+"ALInKM0KfuSpFawo9wvEx2kb+UZ6KQ4L4UPLL6Vo/h/Wu+fPrKZo6UKApGqL68Wz"
			+"5RSoDrhCV3DPKzCCbvtIjUHQ2kmqdEdq3LeUopYV4D4dy6ENin4g7fJk3+ChWgSM"
			+"bq5WGwng45DZAQ9U4FS5z6vGf5062gdCeOfvGShj/hFYgNPDJvipB+c+vchFcqBv"
			+"XwrOXFZa5tKgXcx3zNn7dPefM02Z4fBwvS3yhvq62WLQ1R2RuqNeI4rm9dlbtBEk"
			+"Zb/VU25fkv+ZnGp3ekD0TgNi5bowsZiEClzWODvIpXS/TBhcXgp63/e/jwd/KNc4"
			+"m0XovQzgb5wWRSorS5lFiT0CAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNV"
			+"HQ8BAf8EBAMCAYYwHQYDVR0OBBYEFFJgR2sUAaXmkBfpgNjBqGgycUxBMB8GA1Ud"
			+"IwQYMBaAFFJgR2sUAaXmkBfpgNjBqGgycUxBMA0GCSqGSIb3DQEBBQUAA4IBAQCf"
			+"2q0hWIXSOwbO5az2TMI4pwzmL+gz7GsAeCZ46TFSn8qIDQ4I8sMOB4vaIsAxUCUO"
			+"UCSkakgQTlrCORL45H8GZ7Z0Clu60tjJtIuoRRi8lsaZWtmKXw3P2cBSyFakSq64"
			+"vDJCGHadGzeHqYRiAHFs98MbLWd4X3fxLvsWEtEjaMiL3ocd4FRAv9UMGL6KUzIJ"
			+"wpl+xgBtp/lyzIMokRdgYNTLsFkrtR0DgG+nVXg+PJRJXz7UWJfZ0WFUz4+o+DgZ"
			+"BYk5MNpAssbi6z4F6eVtqN3RcLZ3KhN6HR4t3+NDNdCRyW2GJk8swEnsbYUOeOGe"
			+"RafwgiudJEFS+OLJ9fWf").getBytes());
	
	private static byte[] certintertest = Base64.decode((
			"MIIDDzCCAfegAwIBAgIISqSAWg1vgP4wDQYJKoZIhvcNAQEFBQAwEzERMA8GA1UE"
			+"AxMIY2VydHRlc3QwHhcNMDYwMTMxMTAyMzIwWhcNMjUxMDE4MTAzMzIwWjAXMRUw"
			+"EwYDVQQDEwxjZXJ0dGVzdHN1YjIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK"
			+"AoIBAQCZKBvVMID5uukn6bZ8JD4cXug3hb+UlmEVLJj7Sm6wcF3TYFhDlwPIeCXj"
			+"qn9ZIULxpmNNda1E4ZcqpHYcxbBu8bhYmffeEtzIWOXd1MQ8WWlGbB1i8bNpZHOq"
			+"2ZhbV8qtGRg8JRVdi8MGKsDq74KjjcduV9jb8gK1R5iah2YrNU+7JNDutN3sLTHR"
			+"NDnW2wTIJfd+S+mh5hcgroNXbLT50CEdmjNBucSGzHHwWIgiL/7PZlchDLVkdiza"
			+"A5suAjuSIr4tSKnxXDWrrkcBu9R5pOUPYS00eaMXDW3p+OesRYwMkmG74JS6aw8/"
			+"JY8r52AmvXJgc5Gjkma6LkXn1NuxAgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8w"
			+"DgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBT7WnnEHd6xvC8/Dhvo/pIhVkMiIDAf"
			+"BgNVHSMEGDAWgBRSYEdrFAGl5pAX6YDYwahoMnFMQTANBgkqhkiG9w0BAQUFAAOC"
			+"AQEAULha8ZiRIUx8FdayL/fsPwicGwZko3DuGhnY97aUSvcSx2JTdAFM0wWXdEL5"
			+"gWq4451wBqhnV62yma1QR8v/O8ypmsNt7nKBGgZ7jRzq/GGFUCJvvTZmAQa/iz9L"
			+"KNiKOouUOaDkA8d00qroJMBkiDE4rt1OCMFPjfjxh4ozEXilx1Bg15IFW3B7TQRw"
			+"vv3cpYx0HDFDLYloDEVOWmmBb5gVm1JS3zqVxJU9dwGWi8+5yrsnnY7Cd6m6GKui"
			+"a17PcoX3yiBwHQQQNh8kmXVqhSMrVUNBZuauR8AjwVnW0yR8f2buaGnx6Bzg66Y7"
			+"7jZRFYdRZw7zQ3ki6BzVrdI2qg==").getBytes());
			
					
	
	private static byte[] certtestuser = Base64.decode((
			 "MIICjDCCAXSgAwIBAgIIO9I75BAR2iQwDQYJKoZIhvcNAQEFBQAwFzEVMBMGA1UE"
			+"AxMMY2VydHRlc3RzdWIyMB4XDTA2MDEzMTEwMjQwNloXDTI2MDEyNjEwMzQwNlow"
			+"FzEVMBMGA1UEAxMMY2VydHRlc3R1c2VyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB"
			+"iQKBgQCsXEslTgDUcYYLVvg7ip+ED0ahi1575XJdukhA89Vhmdr2dr3anANAhQ3P"
			+"HmumX023fxc/FPeFm0YsmWAFdgVvo4OgNqn8uHnUZtDyBz2x1BcSZPl4BemiegWR"
			+"AH49b7DY9ov0WrCn+f2G4/bi/+B47Bg/2xTCB4db82/uljAJBwIDAQABo2AwXjAM"
			+"BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDAdBgNVHQ4EFgQU+QezAWJBLplL"
			+"X48jAQvthJAc580wHwYDVR0jBBgwFoAU+1p5xB3esbwvPw4b6P6SIVZDIiAwDQYJ"
			+"KoZIhvcNAQEFBQADggEBAEQ0buiAhEARQrYWu2W0Z8K+NdP3H8CbgZqnrgVwPGHa"
			+"jlcczpEEqM2B8jWbACGqZs9098DwW3NaNK+vRscdClTWcFLjvL/c8egFSbsVuTR2"
			+"jeUXpOgalwa5lL/NICaHBFvCeXZam1frND6NQzIZeoJyIS3Dz3wKPj8JwP0wa/I9"
			+"MqkwZfrYkOlAfBVE5AxYK3PHCrGn5DE8PoPYu4nqqmjrql6RkpLyXa2gP0R8nM/M"
			+"nwGu3CfmzCHelPimFoR/hgyI/WShzUJ8I294RtLCJGHyKBYp4putP2x8vVA3rKLx"
			+"tk0aFncO0UPPFCcuufxAkDEDYXYELl6oS45ho8ANOZc=").getBytes());
	
	
	private static byte[] userkey = Base64.decode((
			 "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKxcSyVOANRxhgtW"
			+"+DuKn4QPRqGLXnvlcl26SEDz1WGZ2vZ2vdqcA0CFDc8ea6ZfTbd/Fz8U94WbRiyZ"
			+"YAV2BW+jg6A2qfy4edRm0PIHPbHUFxJk+XgF6aJ6BZEAfj1vsNj2i/RasKf5/Ybj"
			+"9uL/4HjsGD/bFMIHh1vzb+6WMAkHAgMBAAECgYEAgO/h/xwlHsd14RHETLZcsivD"
			+"SKG7oq94KIlr97rwSz0PQgR97gV7oU5nkCNPoHv25WgbecMzjy0jB8YMwMkTMr0r"
			+"acXbi4GeCLL3iyVcfElCx5D+D09VoHnW1otCTxMTLFvNnbewnNUecTf3DJNgd43S"
			+"8Clxw66R3Y4w1mzwjnECQQDxYtLhQ3OmfIduvUni1XqJ+68LsktIg3bPGPNV5REa"
			+"90585NTf/KvO+sJDVHTsKrEe9+FSp4UTwNRbQCEb1t69AkEAtsupiYxVY9ujymKu"
			+"hLfpZKi5qjohG+hGoqrHSHJKXpevrhmTOkFALVVCT+fC2scHNloZxXVjd0VtXucE"
			+"5FgVEwJBAMyqHOEwfstnhLFJP29b0AVUZ8vEBX7bMI5RumhWy5UQoPTWVQQBSW86"
			+"QCI0ZtqjLAB07hBVx0jDU4p3KltfaQUCQFTwfB4rNH6LUCe6BSgsoWohsOx1yG7E"
			+"VxY9Tw7N9NrRl1PKFIysR1sJVB/3LKcmdqZ95Z3Id2izvSetJ6vHdjsCQDDXaW1R"
			+"q6Y2mFTmc2afDFzxkHvHOoMf9tnj7KwjZEuqGckUCbKqvk1MX/9cB3KLo9t+wqCW"
			+"jk+w4V4pCK643qQ=").getBytes());
	
	public static String pkcs10_1 = 
			 "MIIBkzCB/QIBADBUMQswCQYDVQQGEwJTRTETMBEGA1UECBMKU29tZS1TdGF0ZTEh"
			+"MB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ0wCwYDVQQDEwRUZXN0"
			+"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDczgi13kcTGTMmOdMU/QzvH6JV"
			+"QxL23dqdYpsV//XHO2bjKlgqqc3MpGH4QQkz/80rzFi4EwuqBpOnXo0P09I2jztk"
			+"IG4TSM+RwOfvaAMDJ1B6eeih6JX+v0A5PaWJlx1nshUuikcYJK3iNVepy39li0m3"
			+"OBwub9NnnVWXuClUGwIDAQABoAAwDQYJKoZIhvcNAQEEBQADgYEAz4NpjNraufWg"
			+"ZDv5J1muOHwZvOO9Is1L8WvMLG+jgH8Q2rPpDq8buIIWDy6VK8ghr7xhZzEZznTX"
			+"5HLSLB1a6KvktiVSKB0nmAmDU28xXLWWwkA7/68J6DvAipk00bHdxuEJ4+Mg8UJ0"
			+"Mr+aXDlmZUfghzlB70dDUy/Np/YJVb8=";
	
	public static String pkcs10_2 = 
		"-----BEGIN CERTIFICATE REQUEST-----\n"
		+"MIIBkzCB/QIBADBUMQswCQYDVQQGEwJzZTETMBEGA1UECBMKU29tZS1TdGF0ZTEh\n"
		+"MB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ0wCwYDVQQDEwRURVNU\n"
		+"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6zGAfzcf8+ECqvI6r2z22fI9h\n"
		+"pVTPWkY+vpw6w6ilzhqeMJslAQG5WogOc+NpWrGLAd8UCN2AicQE1p5dFKN8URF0\n"
		+"3eyNIXTTveQqzcAYaFHAuD2Ua1a3W9vbnPAm2NSiD3keeFMgXZqqFtnEqU/4XvA6\n"
		+"ClrEMu5/W20N3fKyVwIDAQABoAAwDQYJKoZIhvcNAQEEBQADgYEASbGs+s5PjTYW\n"
		+"vYQ0OOLYuNZcV2uj56FVP4jjaxed6SNC3XNrsJcqoBIUT14OTGvo+kt/Du3X5src\n"
		+"sLtaUfVr74y1FhDq55fqAY5+k0IpJVYGlOVsAAcx5O2jUKbxZHBSQnyVBLKczITY\n"
		+"PfoNI8s9NXa/fIfqp56llOPzDy3OcHc=\n"
		+"-----END CERTIFICATE REQUEST-----";

	public static X509Certificate getUserCert() throws CertificateException, NoSuchProviderException{
		CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
		return (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certtestuser));
	}
	
	public static X509Certificate getIntermediateCert() throws CertificateException, NoSuchProviderException{
		CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
		return (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certintertest));
	}
	
	public static X509Certificate getRootCert() throws CertificateException, NoSuchProviderException{
		CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
		return (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certroottest));
	}
	
	public static PrivateKey getUserKey() throws Exception{
        PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(userkey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(pkKeySpec);
	}

	public static KeyStore getUserKeyStore() throws Exception {
		List<Certificate> list = new ArrayList<Certificate>();
		list.add(Constants.getRootCert());
		list.add(Constants.getIntermediateCert());

		return KeyTools.createP12("TEST",Constants.getUserKey(),Constants.getUserCert(),list);
	}


	
}
