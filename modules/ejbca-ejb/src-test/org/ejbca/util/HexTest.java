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
package org.ejbca.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.cert.Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Before;
import org.junit.Test;

/** Tests base64 encoding and decoding
 * 
 * @author tomasg
 * @version $Id$
 */
public class HexTest {
    private static final Logger log = Logger.getLogger(HexTest.class);

    @Before
    public void setUp() throws Exception {
        log.trace(">setUp()");
        CryptoProviderTools.installBCProviderIfNotAvailable();
        log.trace("<setUp()");
    }

    @Test
	public void test01HexSmall() throws Exception {
		// Testcert is on long line of base 64 encoded stuff
		byte[] certBytes = Base64.decode(testcert_oneline.getBytes());
		assertNotNull(certBytes);
		// This should be a cert
		Certificate cert = CertTools.getCertfromByteArray(certBytes);
		assertNotNull(cert);
		byte[] hexBytes = Hex.decode(hexCert.getBytes());
		assertEquals(new String(Base64.encode(certBytes)),new String(Base64.encode(hexBytes)));
		Certificate cert1 = CertTools.getCertfromByteArray(hexBytes);
		assertEquals(CertTools.getSubjectDN(cert), CertTools.getSubjectDN(cert1));
		byte[] hexBytes2 = Hex.encode(cert1.getEncoded());
		assertEquals(new String(hexBytes2), hexCert);
		
	}
	
    private static String testcert_oneline = ("MIIDATCCAmqgAwIBAgIIczEoghAwc3EwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
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
            + "QUOBOvc=");
    
    private static String hexCert = "308203013082026aa00302010202087331288210307371300d06092a864886f70d0101050500302f310f300d06035504031306546573744341310f300d060355040a1306416e61546f6d310b3009060355040613025345301e170d3033303932343036343830345a170d3035303932333036353830345a30333110300e060355040313077031327465737431123010060355040a13095072696d6554657374310b300906035504061302534530819d300d06092a864886f70d010101050003818b00308187028181009cf02d7e953adffd21e889c199eb0df05612e3b84cbeafec96248138c53456ace534d5ee843f1adc5ca919f9cf5ef8c93f9617f4e46ed7101f4cd6a8dac4872edae4349401bfa8c24483186e38e8f3850569bdaa861689c2a26091034abb62c7cb9805533b710fc248b853e86b2a759fd24bfe0a850efea4f355270c69877857020111a38201223082011e300f0603551d130101ff04053003010100300f0603551d0f0101ff0405030307a000303b0603551d250434303206082b0601050507030106082b0601050507030206082b0601050507030406082b0601050507030506082b06010505070307301d0603551d0e04160414e74f5690f48d147783847cd26448e8094abb08a0301f0603551d23041830168014637bf476a854248ea574a57744a6f45e0f57925130220603551d11041b3019a017060a2b060104018237140203a0090c07666f6f40666f6f30120603551d20040b300930070605290101010130450603551d1f043e303c303aa038a0368634687474703a2f2f3132372e302e302e313a383038302f656a6263612f776562646973742f63657274646973743f636d643d63726c300d06092a864886f70d01010505000381810053808270ba1250319724038ef611a1bf1422c23183dab54a08b4787a6a31d66950e6b80ef6c49e97a8c793071e6aae00e79faa5c08d056cbb2efa5099dcf277185fc7fdf2e49829c8f1a3f89f9f578731b2fc7462dde5b73618d059926845204a03bdb7e7f63a3ba61952f22caf1766210b87aca3c5dbf93efe0594143813af7";
}
