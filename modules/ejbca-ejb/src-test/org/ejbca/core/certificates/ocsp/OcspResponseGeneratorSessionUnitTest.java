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
package org.ejbca.core.certificates.ocsp;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Date;
import java.util.Properties;

import javax.ejb.Timer;
import javax.ejb.TimerService;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.X509CAInfo.X509CAInfoBuilder;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.ocsp.cache.OcspDataConfigCache;
import org.cesecore.certificates.ocsp.cache.OcspDataConfigCacheEntry;
import org.cesecore.certificates.ocsp.cache.OcspSigningCache;
import org.cesecore.certificates.ocsp.cache.OcspSigningCacheEntry;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding.ResponderIdType;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.CertTools;
import org.easymock.EasyMock;
import org.ejbca.core.ejb.ocsp.OcspDataSessionLocal;
import org.ejbca.core.ejb.ocsp.OcspResponseGeneratorSessionBean;
import org.ejbca.core.ejb.ocsp.OcspResponseInformation;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;

import static org.easymock.EasyMock.anyLong;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.runners.MethodSorters;

/**
 * Tests for the OcspResponseGenerator that don't involve creating a CA.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class OcspResponseGeneratorSessionUnitTest {

    private static final String REQUEST_IP = "192.0.2.123";
    private static final BigInteger REQUEST_SERIAL = new BigInteger("112233445566778899AABBCCDDEEF00", 16);
    private static final String ISSUER_PRIVKEY =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCW5gMA+50dUrEO\n" +
            "AxL4BlF5SnaVAJkuxVpO2oF03cddTFjV6sYwTH2kyt5Rkohf/q15XmEOnFjg2Nt3\n" +
            "dBymV/N3kDJyn1AeX4tssZVUpcvvLHr+Ah0CwAhAddtkSfxFE4j6/8KO1Wqy6DoG\n" +
            "wvJuoGVqvNSRmeKc+9GZ7imK0q+PZ9lyKajOCr6AzmLGvk3apFYoSnn6KL3Twd7Z\n" +
            "9j1Qu43+JWq5ZPTGFQIUBwoCdgjqxEHarjNEr/0TdoTlx/QOHVtJebyeGz1fd8pL\n" +
            "kHLOJ3zj4Y13X0m2dMuqmk7Qi6KVacQWqqOqvcnnWP919jKychpHEqPCB01n/mda\n" +
            "fVgDHc0TAgMBAAECggEABsSOLJnHCYJPRUJHXtm5sbzwkJeURzq8EClQq73UATqO\n" +
            "tBlxhh0IIun5CqON0PBf4L+mOWeIZ5089Us/NbQKzA6q6eUnTMAa8BG5kYWrczCw\n" +
            "MNBGHid1YfQR65o94ZiSCN/hCVLyaXps5Sdn2XpW0hth//MXl37b1GbldL/PoUOE\n" +
            "z6fGbu0ST1pIE9jOAdVGT3Nb6lFjHXpxPsy9mMopciCPqCDYFvdPxtXZaIhDD4vi\n" +
            "cLDY/i2hRSXKHGnPIA/ydKeDNI+OiRPPXOXqf6KJom/xhW3NcmCHTpbuspftzkiE\n" +
            "0OuBwG5Fp5wvBDVIlohjGcF+uaUKSnUqdlFnZBDxMQKBgQDIPc58sElaSeRXmPwD\n" +
            "+euF1EvIQ8aYeCSgEQlQ1f0pyN8MwjNaS4BvT3OYXWcg/dWTxyyULUTcJbqV+pmP\n" +
            "RzuUQtxtaJ7zM9zTrHWZfTV5n0w/XPkaQN9R+dehl8qQ9fBhGmUQRBDeBfPU5p4w\n" +
            "esLfRlei0Xc2OUze7SaIlGJp7wKBgQDA6swY5PRv9uCSKgYtUDUdQaz/I3yOUYzA\n" +
            "GWbwD+3AGMPrDoyvdMSklJcjhEgEc3+MaFcll6AhU09rgRtjoHeI9k0x0piHbf/W\n" +
            "rucb9CDgDgpsAI/bQJMQcN7IfpuGfEJ6uVribindm3F6px+eP7p39ORNe9GIgdQ7\n" +
            "idwXIOYDHQKBgQDE907yhbFRt9d9dwWGn8JVvRLiJhDmj19vd/KS6jsBbA5DjY9X\n" +
            "5WarlxqcqFu2Lxl0KHooMzNF3XLg7kU4k5f+aZpLoJqhncU9DaoL1gbQ4KnutfRu\n" +
            "J5vEFh9OW3ItD05pJb59toZk7rP/Gu5Fv6uKVrYDeUlrNAfyTJIXzOXVTwKBgQCv\n" +
            "h3O42umFzk068L26ERaizhUH+FPmclDsoLBGkVezx1TL1Osw4b/iN8jk6gFU+3n8\n" +
            "WRuh+roaWGEU4d334hOhLOnEAWgDIZT80xs5FgGrm1rkNgauaazl8qziJECCNyGN\n" +
            "5ITLLY0uM7cm8FUWecnCR7JKxfQ6jlZ67c6xxJ9ECQKBgA+4DPnClXA7m2Jsl0aw\n" +
            "nm4GzoRGne1/XWgRUoqru1spGjGkvkRBBx3EVJ7dy/tQEbMi7CoLb8c7pbhtVnZ2\n" +
            "mKybIDHcPBLqReNbKG4s+5Om8hmpl8yu/2Y8xMy8dpl1mu1ypJi8d4d8IQ1DpIpn\n" +
            "Kd6IydCTZBh3ToZjYrLh3EaR\n" +
            "-----END PRIVATE KEY-----";
    // Simple root CA
    private static final String ISSUER_CERT =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDWzCCAkOgAwIBAgIQTUjjmEs8FvOFIFymhvlN6TANBgkqhkiG9w0BAQsFADAp\n" +
            "MQswCQYDVQQGEwJTRTEaMBgGA1UEAwwRQ0EgZm9yIFVuaXQgVGVzdHMwHhcNMjIw\n" +
            "MTE3MTczNDExWhcNNDcwMTE4MTczNDEwWjApMQswCQYDVQQGEwJTRTEaMBgGA1UE\n" +
            "AwwRQ0EgZm9yIFVuaXQgVGVzdHMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
            "AoIBAQCW5gMA+50dUrEOAxL4BlF5SnaVAJkuxVpO2oF03cddTFjV6sYwTH2kyt5R\n" +
            "kohf/q15XmEOnFjg2Nt3dBymV/N3kDJyn1AeX4tssZVUpcvvLHr+Ah0CwAhAddtk\n" +
            "SfxFE4j6/8KO1Wqy6DoGwvJuoGVqvNSRmeKc+9GZ7imK0q+PZ9lyKajOCr6AzmLG\n" +
            "vk3apFYoSnn6KL3Twd7Z9j1Qu43+JWq5ZPTGFQIUBwoCdgjqxEHarjNEr/0TdoTl\n" +
            "x/QOHVtJebyeGz1fd8pLkHLOJ3zj4Y13X0m2dMuqmk7Qi6KVacQWqqOqvcnnWP91\n" +
            "9jKychpHEqPCB01n/mdafVgDHc0TAgMBAAGjfzB9MA8GA1UdEwEB/wQFMAMBAf8w\n" +
            "HwYDVR0jBBgwFoAUeSHrCfCMFVqGWiKb7oD3lwM7rfcwHQYDVR0OBBYEFHkh6wnw\n" +
            "jBVahloim+6A95cDO633MBoGA1UdEAQTMBGBDzIwNDIwMTEyMTczNDExWjAOBgNV\n" +
            "HQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggEBAI14SVbqLf0t8iXKJSg+6ubH\n" +
            "N7JBmn0+Hh/5l6GMd2kxzN2mmUHVanc7osYqAXcRp3JB+byo5P3I3XsdQqn51WVJ\n" +
            "7ZZENlHP4QQgVIPrUMhNZfE1EjlmVbPozpfhPxgj+PYUbJ0yM63FC19u1W/IT7dj\n" +
            "6CFpi3VEK4A9AZRHr4Qo/Z5WQyzYr6RYlF82AfAs0tHfh46wXeXpTqaxq/vxBme7\n" +
            "eTntVr3lMoUYR5r/yCwmvvDGH19MXSjXYGPJlsQLK10Uul6F5lcOvUoJRi9uy1lF\n" +
            "U2RWBSRSaV1R5jlDvr4lB9O+CAmtUs2AsgAWomgPnvVUScDZt5nK7x5OFLeE85o=\n" +
            "-----END CERTIFICATE-----\n";
    // Complex chain with same Subject DN, but with correct SKID/AKID - Root CA
    private static final String SAMEISSUER_ROOTCA_CERT =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIFQzCCAyugAwIBAgIUQgkTyYXUYxl8Yoak81Y6KZA/hUAwDQYJKoZIhvcNAQEL\n" +
            "BQAwKTELMAkGA1UEBhMCU0UxGjAYBgNVBAMMEUNBIGZvciBVbml0IFRlc3RzMB4X\n" +
            "DTIyMDExODA4NTYzOFoXDTQ3MDExOTA4NTYzN1owKTELMAkGA1UEBhMCU0UxGjAY\n" +
            "BgNVBAMMEUNBIGZvciBVbml0IFRlc3RzMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A\n" +
            "MIICCgKCAgEA6KV2OrILLR2mdu0TIUYCG5EHQ9Jnh8YZgLoUMMpQfAWQiapkpLUy\n" +
            "352QppBVzIOb9o0t7qoelmCDu3X4uJTYeMCqmP2OoB35fOZpjlMY49ZBLyQSPaIm\n" +
            "7EPj+f9t46ylOnpyShmWIbSQnL8tiL4sVYrmhRYFb/rhmnm3TzuSe8M3r9cd+UC/\n" +
            "3+Cd42AqCptY58tavl0N9h9VFkY55YSKpZOFQQD/GPP0qESIAo4HARzr5CCd+CLf\n" +
            "UKY+u23IJ16HAlHRo4zbKs8sCGleJpyk6bEA8K42/4gQBVTojWwnR8THkobCEQMy\n" +
            "d8fMzxmbSGkQY48Mqi+/HVsZeepOXyJne7DL30tXKAMyE0bOyMHqIXnpDJTmYvRU\n" +
            "rGo+xkWfATFyJA19WF0yLTBJO2oUu575vJ9ptnGgE8UEmNkbVaoR/BRmbwFlkcoQ\n" +
            "rtOcpgJ3WTvi/1ACpSQl+43RXjftxf4OqGK5uD8fkTnMjfc3x4pE8J1C/sJl85MB\n" +
            "uPHJDgUQ+38JBuA4RohcxM+n1kJy0FWbKXT8CfgZ5zl3b6+tTzlIVrKsNB+gxR0A\n" +
            "mN0VXEshaxNEId5S0W4zxCPiwyWXljz/pAObIb2UAW9Pwf1/l5XpDRGQIMmU7bOV\n" +
            "Y4cZBevSPpZhbIjdvgOqvpzt3yQmGgtMrFT/3Sg+uX+6vMvmg7TZvW0CAwEAAaNj\n" +
            "MGEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBQOvxzOkEHZfMfA+OKHvxtW\n" +
            "yy7K5zAdBgNVHQ4EFgQUDr8czpBB2XzHwPjih78bVssuyucwDgYDVR0PAQH/BAQD\n" +
            "AgGGMA0GCSqGSIb3DQEBCwUAA4ICAQCeROxmA9jmRVL6n80gWBzuhyqiPh7Tc0/J\n" +
            "w4ifD/szZfomWMZPDVSHmLzZCWmLsRJ4rC8L6uOme+np+ol/UxxdsgFvJV7ke8op\n" +
            "/1FdH2jGKWo8JtlkyfK3v/EhmSgr6yFx1CBAjCL0XcV2Mj0hWajz+HP4IChZUKh3\n" +
            "ywk3ZVrPD0/GWLKsb9CHax/YVx/L9TF14lw0y9cIkNoOjfo1Ykj9Z6jGFJupSYfx\n" +
            "qVWxN2kxUpvs1AKTpYAEQ1mN0/Gs/2WrWXTI+A6uQwBDegB+eox+Oq6XX4swUjZu\n" +
            "0DV5+CSFoQi0f8MUl9YaiB6DBd0R0iA1pnZklV390VKg4tGgjEH1fXlmJkKEsCnF\n" +
            "rmcuaoePUlZ1Mu69UqNbkazD3qF7mLUSVhOWKeTVOzkHWheZNl210dUNEaulXw5Y\n" +
            "v6pzBGcp4ofuKeUZ1ZOcb8egEnquAIaM2KLnRf2a0E2BrerXKeOEwCp/TBiWZ/56\n" +
            "1KbTCfLYTNu4rG3ywN0Y0fA+IH5cWh1Fz4pxbguzYBM8moHDnmHVpdVFQRq6MwS/\n" +
            "JUsXwNBK1n5Vf6Xloz04egs1qZJiNeMZrYkw1G/PSfrL7825S7/PSSJPkAD94Q3q\n" +
            "yv27LuJ8QTuqa4EG3JH3xM3vNGQNRiJ2qipPq5tUiMLia/Z3ZSuQXYV5cwQmxLlV\n" +
            "jFhpdYef7w==\n" +
            "-----END CERTIFICATE-----\n";
    // Complex chain with same Subject DN, but with correct SKID/AKID - Sub CA
    private static final String SAMEISSUER_SUBCA_CERT =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDWzCCAkOgAwIBAgIQYXkBN99oZ6yTgXaPihhetDANBgkqhkiG9w0BAQsFADAp\n" +
            "MQswCQYDVQQGEwJTRTEaMBgGA1UEAwwRQ0EgZm9yIFVuaXQgVGVzdHMwHhcNMjIw\n" +
            "MTE4MDk0ODM3WhcNNDcwMTE5MDk0ODM2WjApMQswCQYDVQQGEwJTRTEaMBgGA1UE\n" +
            "AwwRQ0EgZm9yIFVuaXQgVGVzdHMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
            "AoIBAQCW5gMA+50dUrEOAxL4BlF5SnaVAJkuxVpO2oF03cddTFjV6sYwTH2kyt5R\n" +
            "kohf/q15XmEOnFjg2Nt3dBymV/N3kDJyn1AeX4tssZVUpcvvLHr+Ah0CwAhAddtk\n" +
            "SfxFE4j6/8KO1Wqy6DoGwvJuoGVqvNSRmeKc+9GZ7imK0q+PZ9lyKajOCr6AzmLG\n" +
            "vk3apFYoSnn6KL3Twd7Z9j1Qu43+JWq5ZPTGFQIUBwoCdgjqxEHarjNEr/0TdoTl\n" +
            "x/QOHVtJebyeGz1fd8pLkHLOJ3zj4Y13X0m2dMuqmk7Qi6KVacQWqqOqvcnnWP91\n" +
            "9jKychpHEqPCB01n/mdafVgDHc0TAgMBAAGjfzB9MA8GA1UdEwEB/wQFMAMBAf8w\n" +
            "HwYDVR0jBBgwFoAUDr8czpBB2XzHwPjih78bVssuyucwHQYDVR0OBBYEFHkh6wnw\n" +
            "jBVahloim+6A95cDO633MBoGA1UdEAQTMBGBDzIwNDIwMTEzMDk0ODM3WjAOBgNV\n" +
            "HQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggEBADBwTQXIZJ5nCi0RYTzoNQzD\n" +
            "suW4mydB65IY+i4MV3O2r6MVvxF58tdP/EzIqCjH4PaYwmcW9AAFcVJXWg9l6yJL\n" +
            "AoEsA7PbmnE1dAQdaKAQA/FSF4Kl2e7QvOXon64xT9L1Cf4oOt5FADh4IESGWASW\n" +
            "IVJ8NQw0b6OabYKsjijOFaHxj4K9aJWsQCyB3mah/Jh2i2MtUAZ2QnLc8rS6c2l1\n" +
            "+lTieQ0cIv3CaA51u4PU4cWFDJs7jW4CquQR/eay0m7fSH+SGiHSWr+59HTTZoz1\n" +
            "Lv24f5LbofR5TiHPXmTX0hg6beohc+n2g6jBzpjprymNuuVvCwlpyhVTFGJLxas=\n" +
            "-----END CERTIFICATE-----\n";
    // Complex chain with same Subject DN, but with correct SKID/AKID - OCSP Signer cert
    private static final String SAMEISSUER_OCSPSIGNER_CERT =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDZDCCAkygAwIBAgIQA2wYNyF6qEB/wqGo2eBk7jANBgkqhkiG9w0BAQsFADAp\n" +
            "MQswCQYDVQQGEwJTRTEaMBgGA1UEAwwRQ0EgZm9yIFVuaXQgVGVzdHMwHhcNMjIw\n" +
            "MTE4MTgxMzU2WhcNNDcwMTE5MDk0ODM2WjApMQswCQYDVQQDDAJTRTEaMBgGA1UE\n" +
            "AwwRQ0EgZm9yIFVuaXQgVGVzdHMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
            "AoIBAQC0OURvapf5QXTc3nd6Cy7WEQEuY5+vfX1BV77kThmgvMNVyNr32yz1VCyW\n" +
            "p6Vn89GxCj+pyZTWZOncpa7ve0e0HH/egW7RennbGa1Ty5zrpa8dNg2N3c/472dC\n" +
            "fcHa+Dhnkthva/PIRZ3zKzM7zt4RD9P2nLfq3v033RmjrkiuTU6WBqtlXmxJEEGo\n" +
            "Y9ZrIE58x5Cv+uV5CO8wb6jkn+ylJGPhRikVAwp7NRMzZt8l/vWFS+4nQia3lSjl\n" +
            "HkBt/0oa3NdEttQqEyFL24DqJEIBgWIIKDKNBThGveemW83r7g7nPhUyf+iB4CqH\n" +
            "g6EwrYKnp3DbpbAbtTucx7sI5zU9AgMBAAGjgYcwgYQwDAYDVR0TAQH/BAIwADAf\n" +
            "BgNVHSMEGDAWgBR5IesJ8IwVWoZaIpvugPeXAzut9zAPBgkrBgEFBQcwAQUEAgUA\n" +
            "MBMGA1UdJQQMMAoGCCsGAQUFBwMJMB0GA1UdDgQWBBS//S1XmIngbpo/DdUDmrCr\n" +
            "NwPMyzAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggEBAIEq4DY+7zWw\n" +
            "rQtnvX0UlYlD+hHHvfJ2JtJ7pRNGKgeGwBlGUEsbyZOz9ol9LkFKfCQhzGDLLpFu\n" +
            "1Yo0vs4oJ4Hu93pCZekhW9Pq9Ywzdi1v2qOzqnDbqW7vPeE2KqazbHzVui5aDbDk\n" +
            "+H13uWkjSiuVa711sx9Z0N6hrHexNLhzJuB+w+zxbrxqAnxSkDT5zzmWGxj6Dsdv\n" +
            "/wBBCjh0R5TsN0i96ge21vNiMrDPOFK658eARW/HsjwymOaPtlAK+0feKK7b0DAm\n" +
            "rndfDnOsGqNDkbx9JFKaDqpfv2K6HgplaZR5JEuUqhV76zp4cfya8hf/KidDB8sf\n" +
            "kAar4YVdjmA=\n" +
            "-----END CERTIFICATE-----\n";
    private static final String SAMEISSUER_OCSPSIGNER_PRIVKEY =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0OURvapf5QXTc\n" +
            "3nd6Cy7WEQEuY5+vfX1BV77kThmgvMNVyNr32yz1VCyWp6Vn89GxCj+pyZTWZOnc\n" +
            "pa7ve0e0HH/egW7RennbGa1Ty5zrpa8dNg2N3c/472dCfcHa+Dhnkthva/PIRZ3z\n" +
            "KzM7zt4RD9P2nLfq3v033RmjrkiuTU6WBqtlXmxJEEGoY9ZrIE58x5Cv+uV5CO8w\n" +
            "b6jkn+ylJGPhRikVAwp7NRMzZt8l/vWFS+4nQia3lSjlHkBt/0oa3NdEttQqEyFL\n" +
            "24DqJEIBgWIIKDKNBThGveemW83r7g7nPhUyf+iB4CqHg6EwrYKnp3DbpbAbtTuc\n" +
            "x7sI5zU9AgMBAAECggEACRetjfXMWovfST25EebKs2FIFGQm0YwCJn/hNolWg39F\n" +
            "LJ4K/BUU+NXzv5sQKNqKfQUwbpC9agP32i+1ZR7XYIJ36gzQ1OU6DMrdbYbuMQ5a\n" +
            "yMgUxCWey+dKJ/bfxvwdyQ3wePidjpWtO8WKxWzw/l6Jz11F7dCCaSUwxAsI3trx\n" +
            "DBMgIkkTH/+aTcsruh+QTkeN66NVveqJIIhZxv1ZpXW2r3mrGlRI/BYNZd4PZXo+\n" +
            "WG/74uEqSzyWD27Vh2C4Grda7+pjSsaC6tgtcy8QRkS2lrARGcvReIpZV/IzIa89\n" +
            "UwHCoTRwdefJ1ht28sf0emLqs9Bd1AWGFgAg+r/x8QKBgQDn4LB8E2q6MSxwaq/0\n" +
            "XITICoxM46N8PyikMkGHH07Ni42D0Bh+Ug3IWgN38FWaLJU49RfVblAISf63oKJQ\n" +
            "7/K8F0fIWlUS8mKJg/DfmBlJATllinyY0J3r6HPeMuJ012iFexNvq7NlLBSAm+WD\n" +
            "g7/SaiUQCbrRAQnlpPPwpE9XsQKBgQDG+PD5VFK0DjhNtcc5jpnkT4RiSErWt9hG\n" +
            "rXdVMy4JjuY+hIcHbupKj0OEzU6VKh2VTr9LgS0hFmWVYOGs2gEpZgMehYX0Tjdm\n" +
            "rBgbilsSf/nFp9yJZ0SSYMstoYaYNcQxRjIlcTEgjx244mm6HQwzIICY1QjyVxDi\n" +
            "MJA4I8FlTQKBgQCGM2qxROOeQ1t+7KBNg0ZuKHyu+4jhHgS9k0CNnbcUC1KqGUQz\n" +
            "x/WmIUKkpfpFMsxinKdgpWm4gmrjiBqpUVZhOfAXqwBV6ObSxAQixHrN3+GCPTaD\n" +
            "kynzISP+U+Dw0sLxjhvfo7Y+Ndbf4FpjVVstwrUUpSz0Te+Wc3OjsNUi4QKBgGNh\n" +
            "qAsBASYKDDlUWCP5hAgzZ24nqanBvfbfYcFehNolU/9Z9o/R6JhBInpMibmbhZcz\n" +
            "8/xkkwP5yddowo+xe+8PkvNFwfiasLVJs+jdnEuLPFhrVY4T1H5AdnteOHoCMPJj\n" +
            "m1x0QxN+KFxWSnS5WYSX8WNk1Mkmj7pKg15nDYvpAoGAZvI4sdmLqeiQpT1/LgDI\n" +
            "e9zLTjFneAdsg/QFoWpfZLWOQRkV9CujCtJk+VhlwN6eSn5Nny3Zo7nPttr/B4tx\n" +
            "nqdumxf2cI+Fz3VxidZioczTWqJTLVajZxKqyiD+kEfMCtREZKlJy5px5yOSojze\n" +
            "++0HOijyblGyk3d0rutr+58=\n" +
            "-----END PRIVATE KEY-----\n";
    private static final String ISSUER_CERT_DN = "CN=CA for Unit Tests,C=SE";
    private static final int ISSUER_CAID = ISSUER_CERT_DN.hashCode();
    private static final int CRYPTOTOKEN_ID = 1111;
    private static final String OCSP_SIGN_KEY_ALIAS = "ocspSignKey";
    private static final int KEYBINDING_ID = 2222;

    private static final Logger log = Logger.getLogger(OcspResponseGeneratorSessionUnitTest.class);

    private TestOcspResponseGeneratorSessionBean ocspResponseGeneratorSession = new TestOcspResponseGeneratorSessionBean();
    private TransactionLogger transactionLogger = EasyMock.createNiceMock(TransactionLogger.class);
    private AuditLogger auditLogger = EasyMock.createNiceMock(AuditLogger.class);
    private CaSessionLocal caSessionMock = EasyMock.createStrictMock(CaSessionLocal.class);
    private CertificateStoreSessionLocal certificateStoreSessionMock = EasyMock.createStrictMock(CertificateStoreSessionLocal.class);
    private CryptoTokenSessionLocal cryptoTokenSessionMock = EasyMock.createStrictMock(CryptoTokenSessionLocal.class);
    private InternalKeyBindingDataSessionLocal internalKeyBindingDataSessionMock = EasyMock.createStrictMock(InternalKeyBindingDataSessionLocal.class);
    private GlobalConfigurationSessionLocal globalConfigurationSessionMock = EasyMock.createNiceMock(GlobalConfigurationSessionLocal.class);
    private TimerService timerServiceMock = EasyMock.createStrictMock(TimerService.class);
    private OcspDataSessionLocal ocspDataSessionMock = EasyMock.createStrictMock(OcspDataSessionLocal.class);
    private CertificateStatus status;
    
    @Before
    public void beforeTest() {
        status = CertificateStatus.OK;
        status.setExpirationDate(System.currentTimeMillis() + 60 * 1000);
        ocspResponseGeneratorSession.setMockedCaSession(caSessionMock);
        ocspResponseGeneratorSession.setMockedCertificateStoreSession(certificateStoreSessionMock);
        ocspResponseGeneratorSession.setMockedCryptoTokenSession(cryptoTokenSessionMock);
        ocspResponseGeneratorSession.setMockedInternalKeyBindingDataSession(internalKeyBindingDataSessionMock);
        ocspResponseGeneratorSession.setMockedGlobalConfigurationSession(globalConfigurationSessionMock);
        ocspResponseGeneratorSession.setMockedTimerService(timerServiceMock);
        ocspResponseGeneratorSession.setOcspDataSessionLocal(ocspDataSessionMock);
        // Clear caches from previous test runs
        ocspResponseGeneratorSession.clearOcspRequestSignerRevocationStatusCache();
        OcspSigningCache.INSTANCE.stagingStart();
        OcspSigningCache.INSTANCE.stagingCommit(null);
    }

    @Test
    public void testWithRandomBytes() throws OCSPException {
        log.trace(">testWithRandomBytes");
        final int MAX_REQUEST_SIZE = 100000;
        SecureRandom random = new SecureRandom();
        byte[] fakeRequest = new byte[MAX_REQUEST_SIZE + 1];
        random.nextBytes(fakeRequest);
        boolean caught = false;
        TransactionCounter.INSTANCE.getTransactionNumber();
        try {
            ocspResponseGeneratorSession.getOcspResponse(fakeRequest, null, null, null, null, auditLogger, transactionLogger, false, false, false);
        } catch (MalformedRequestException e) {
            caught = true;
        }
        assertTrue("MalformedRequestException was not thrown for a request > 100000 bytes.", caught);
        log.trace("<testWithRandomBytes");
    }

    @Test
    public void getOCSPResponseWichExistingMsCompatibleCA() throws Exception {
        log.trace(">getOCSPResponseWichExistingMsCompatibleCA");
        OcspDataConfigCache.INSTANCE.setCaModeCompatiblePresent(true);
        OcspDataConfigCache.INSTANCE.stagingCommit();
        final byte[] req = makeOcspRequest(getIssuerCert(), REQUEST_SERIAL, OIWObjectIdentifiers.idSHA1, null);
        expectLoggerChecks();
        expectOcspConfigRead();
        expectCacheReload();
        expect(certificateStoreSessionMock.getStatus(ISSUER_CERT_DN, REQUEST_SERIAL)).andReturn(status).once();
        replay(auditLogger, transactionLogger, caSessionMock, certificateStoreSessionMock, cryptoTokenSessionMock,
                internalKeyBindingDataSessionMock, globalConfigurationSessionMock, timerServiceMock, ocspDataSessionMock);
        final OcspResponseInformation respInfo = ocspResponseGeneratorSession.getOcspResponse(req, null, REQUEST_IP, null, null, auditLogger, transactionLogger, false, false, false);
        assertGoodResponse(respInfo);
        log.trace("<getOCSPResponseWichExistingMsCompatibleCA");
    }

    @Test(expected = MalformedRequestException.class)
    public void emptyRequest() throws Exception {
        log.trace(">emptyRequest");
        ocspResponseGeneratorSession.getOcspResponse(new byte[0], null, REQUEST_IP, null, null, auditLogger, transactionLogger, false, false, false);
        log.trace("<emptyRequest");
    }

    @Test
    public void basicCachedRequest() throws Exception {
        log.trace(">basicRequest");
        final byte[] req = makeOcspRequest(getIssuerCert(), REQUEST_SERIAL, OIWObjectIdentifiers.idSHA1, null);
        expectLoggerChecks();
        expect(certificateStoreSessionMock.getStatus(ISSUER_CERT_DN, REQUEST_SERIAL)).andReturn(status).once();
        replay(caSessionMock, auditLogger, transactionLogger, globalConfigurationSessionMock, certificateStoreSessionMock, ocspDataSessionMock);
        prepareOcspCache();
        final OcspResponseInformation respInfo = ocspResponseGeneratorSession.getOcspResponse(req, null, REQUEST_IP, null, null, auditLogger, transactionLogger, false, false, false);
        assertGoodResponse(respInfo);
        log.trace("<basicRequest");
    }
    
    private void setupOcspResponseCache() {
        ConfigurationHolder.updateConfiguration(OcspConfiguration.UNTIL_NEXT_UPDATE, "60000");
        OcspDataConfigCacheEntry entry = new OcspDataConfigCacheEntry(getIssuerCert(), ISSUER_CAID, true, false, false);
        OcspDataConfigCache.INSTANCE.stagingAdd(entry);
        OcspDataConfigCache.INSTANCE.stagingCommit();
        OcspResponseData ocspResponseData = new OcspResponseData(null, ISSUER_CERT_DN.hashCode(), REQUEST_SERIAL.toString(), 0, System.currentTimeMillis(), null);
        expect(ocspDataSessionMock.findOcspDataByCaIdSerialNumber(ISSUER_CERT_DN.hashCode(), REQUEST_SERIAL.toString())).andReturn(ocspResponseData).once();
        ocspDataSessionMock.storeOcspData(anyObject(OcspResponseData.class));
        EasyMock.expectLastCall();
        final X509CAInfo caInfo = new X509CAInfoBuilder()
                .setSubjectDn(ISSUER_CERT_DN)
                .setCaId(ISSUER_CAID)
                .setStatus(CAConstants.CA_ACTIVE)
                .setCertificateChain(Collections.singletonList(getIssuerCert()))
                .setCrlPublishers(Collections.emptyList())
                .build();
        expect(caSessionMock.getCAInfoInternal(ISSUER_CAID)).andReturn(caInfo).once();
    }
    
    @Test
    public void zzza_basicCachedRequestWithPresigning() throws Exception {
        log.trace(">basicRequest");
        final byte[] req = makeOcspRequest(getIssuerCert(), REQUEST_SERIAL, OIWObjectIdentifiers.idSHA1, null);
        expectLoggerChecks();
        expect(certificateStoreSessionMock.getStatus(ISSUER_CERT_DN, REQUEST_SERIAL)).andReturn(status).once();
        
        setupOcspResponseCache();
        replay(caSessionMock, auditLogger, transactionLogger, globalConfigurationSessionMock, certificateStoreSessionMock, ocspDataSessionMock);
        prepareOcspCache();
        final OcspResponseInformation respInfo = ocspResponseGeneratorSession.getOcspResponse(req, null, REQUEST_IP, null, null, auditLogger, transactionLogger, true, false, false);
        assertGoodResponse(respInfo);
        verify(ocspDataSessionMock);
        log.trace("<basicRequest");
    }
    
    @Test
    public void zzzb_basicCachedRequestWithPresigningExpiredCert() throws Exception {
        log.trace(">basicRequest");
        final byte[] req = makeOcspRequest(getIssuerCert(), REQUEST_SERIAL, OIWObjectIdentifiers.idSHA1, null);
        expectLoggerChecks();
        status.setExpirationDate(System.currentTimeMillis() - 3600 * 1000); // expired
        expect(certificateStoreSessionMock.getStatus(ISSUER_CERT_DN, REQUEST_SERIAL)).andReturn(status).once();
        
        setupOcspResponseCache();
        replay(caSessionMock, auditLogger, transactionLogger, globalConfigurationSessionMock, certificateStoreSessionMock, ocspDataSessionMock);
        prepareOcspCache();
        final OcspResponseInformation respInfo = ocspResponseGeneratorSession.getOcspResponse(req, null, REQUEST_IP, null, null, auditLogger, transactionLogger, true, false, false);
        assertNull(respInfo);
        log.trace("<basicRequest");
    }

    @Test
    public void uncachedRequest() throws Exception {
        log.trace(">uncachedRequest");
        final byte[] req = makeOcspRequest(getIssuerCert(), REQUEST_SERIAL, OIWObjectIdentifiers.idSHA1, null);
        expectLoggerChecks();
        expectOcspConfigRead();
        expect(certificateStoreSessionMock.getStatus(ISSUER_CERT_DN, REQUEST_SERIAL)).andReturn(status).once();
        replay(auditLogger, transactionLogger, caSessionMock, certificateStoreSessionMock, cryptoTokenSessionMock,
                internalKeyBindingDataSessionMock, globalConfigurationSessionMock, timerServiceMock);
        prepareOcspCache();
        final OcspResponseInformation respInfo = ocspResponseGeneratorSession.getOcspResponse(req, null, REQUEST_IP, null, null, auditLogger, transactionLogger, false, false, false);
        assertGoodResponse(respInfo);
        log.trace("<uncachedRequest");
    }

    @Test
    public void uncachedIkbRequestWithSameSubjectDn() throws Exception {
        log.trace(">uncachedIkbRequestWithSameSubjectDn");
        final byte[] req = makeOcspRequest(getSameDnSubCert(), REQUEST_SERIAL, OIWObjectIdentifiers.idSHA1, null);
        expectLoggerChecks();
        expectOcspConfigRead();
        expect(certificateStoreSessionMock.getStatus(ISSUER_CERT_DN, REQUEST_SERIAL)).andReturn(status).once();
        replay(auditLogger, transactionLogger, caSessionMock, certificateStoreSessionMock, cryptoTokenSessionMock,
                internalKeyBindingDataSessionMock, globalConfigurationSessionMock, timerServiceMock);
        prepareOcspCache();
        final OcspResponseInformation respInfo = ocspResponseGeneratorSession.getOcspResponse(req, null, REQUEST_IP, null, null, auditLogger, transactionLogger, false, false, false);
        assertGoodResponse(respInfo);
        log.trace("<uncachedIkbRequestWithSameSubjectDn");
    }
    
    @Test
    public void nonceOk() throws Exception {
        log.trace(">nonceOk");
        byte[] req = makeOcspRequest(getIssuerCert(), REQUEST_SERIAL, OIWObjectIdentifiers.idSHA1, new DEROctetString(new byte[32]).getEncoded());
        expectLoggerChecks();
        expectOcspConfigRead();
        expect(certificateStoreSessionMock.getStatus(ISSUER_CERT_DN, REQUEST_SERIAL)).andReturn(status).once();
        replay(auditLogger, transactionLogger, caSessionMock, certificateStoreSessionMock, cryptoTokenSessionMock,
                internalKeyBindingDataSessionMock, globalConfigurationSessionMock, timerServiceMock);
        prepareOcspCache();
        final OcspResponseInformation respInfo = ocspResponseGeneratorSession.getOcspResponse(req, null, REQUEST_IP, null, null, auditLogger, transactionLogger, false, false, false);
        assertGoodResponse(respInfo);
        log.trace("<nonceOk");
    }

    @Test
    public void tooLargeNonce() throws Exception {
        log.trace(">tooLargeNonce");
        byte[] req = makeOcspRequest(getIssuerCert(), REQUEST_SERIAL, OIWObjectIdentifiers.idSHA1, new DEROctetString(new byte[33]).getEncoded());
        expectLoggerChecks();
        expectOcspConfigRead();
        expect(certificateStoreSessionMock.getStatus(ISSUER_CERT_DN, REQUEST_SERIAL)).andReturn(status).once();
        replay(auditLogger, transactionLogger, caSessionMock, certificateStoreSessionMock, cryptoTokenSessionMock,
                internalKeyBindingDataSessionMock, globalConfigurationSessionMock, timerServiceMock);
        prepareOcspCache();
        final OcspResponseInformation respInfo = ocspResponseGeneratorSession.getOcspResponse(req, null, REQUEST_IP, null, null, auditLogger, transactionLogger, false, false, false);
        assertEquals(OCSPResp.MALFORMED_REQUEST, respInfo.getStatus());
        log.trace("<tooLargeNonce");
    }

    @Test
    public void badNonceEncodingOk() throws Exception {
        log.trace(">badNonceEncodingOk");
        // A Nonce extension that is not an OctetString 
        byte[] req = makeOcspRequest(getIssuerCert(), REQUEST_SERIAL, OIWObjectIdentifiers.idSHA1, new byte[32]);
        expectLoggerChecks();
        expectOcspConfigRead();
        expect(certificateStoreSessionMock.getStatus(ISSUER_CERT_DN, REQUEST_SERIAL)).andReturn(status).once();
        replay(auditLogger, transactionLogger, caSessionMock, certificateStoreSessionMock, cryptoTokenSessionMock,
                internalKeyBindingDataSessionMock, globalConfigurationSessionMock, timerServiceMock);
        prepareOcspCache();
        final OcspResponseInformation respInfo = ocspResponseGeneratorSession.getOcspResponse(req, null, REQUEST_IP, null, null, auditLogger, transactionLogger, false, false, false);
        assertGoodResponse(respInfo);
        log.trace("<badNonceEncodingOk");
    }

    @Test
    public void badNonceEncodingTooLarge() throws Exception {
        log.trace(">badNonceEncodingTooLarge");
        // A Nonce extension that is not an OctetString 
        byte[] req = makeOcspRequest(getIssuerCert(), REQUEST_SERIAL, OIWObjectIdentifiers.idSHA1, new byte[33]);
        expectLoggerChecks();
        expectOcspConfigRead();
        expect(certificateStoreSessionMock.getStatus(ISSUER_CERT_DN, REQUEST_SERIAL)).andReturn(status).once();
        replay(auditLogger, transactionLogger, caSessionMock, certificateStoreSessionMock, cryptoTokenSessionMock,
                internalKeyBindingDataSessionMock, globalConfigurationSessionMock, timerServiceMock);
        prepareOcspCache();
        final OcspResponseInformation respInfo = ocspResponseGeneratorSession.getOcspResponse(req, null, REQUEST_IP, null, null, auditLogger, transactionLogger, false, false, false);
        assertEquals(OCSPResp.MALFORMED_REQUEST, respInfo.getStatus());
        log.trace("<badNonceEncodingTooLarge");
    }

    // Helper methods

    private void expectLoggerChecks() {
        expect(auditLogger.isEnabled()).andReturn(false);
        expect(transactionLogger.isEnabled()).andReturn(false);
    }

    private void expectOcspConfigRead() {
        final GlobalOcspConfiguration mockedOcspConfig = new GlobalOcspConfiguration();
        mockedOcspConfig.setOcspSigningCacheUpdateEnabled(false);
        expect(globalConfigurationSessionMock.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID)).andReturn(mockedOcspConfig).anyTimes();
    }

    private void expectCacheReload() throws Exception {
        final Timer dummyTimer = EasyMock.createNiceMock(Timer.class);
        expect(timerServiceMock.getTimers()).andReturn(Collections.emptyList()).once();
        expect(timerServiceMock.createSingleActionTimer(anyLong(), anyObject())).andReturn(dummyTimer).once(); // return value is only used by EJBCA for trace logging
        expect(dummyTimer.getNextTimeout()).andReturn(new Date(System.currentTimeMillis() + 3600));
        replay(dummyTimer);
        expect(caSessionMock.getAllCaIds()).andReturn(Collections.singletonList(ISSUER_CAID)).once();
        final Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, OCSP_SIGN_KEY_ALIAS);
        final X509CAInfo caInfo = new X509CAInfoBuilder()
                .setSubjectDn(ISSUER_CERT_DN)
                .setCaId(ISSUER_CAID)
                .setStatus(CAConstants.CA_ACTIVE)
                .setCaToken(new CAToken(CRYPTOTOKEN_ID, caTokenProperties))
                .setCertificateChain(Collections.singletonList(getIssuerCert()))
                .setCrlPublishers(Collections.emptyList())
                .build();
        expect(caSessionMock.getCAInfoInternal(ISSUER_CAID)).andReturn(caInfo).once();
        final CryptoToken cryptoTokenMock = EasyMock.createStrictMock(CryptoToken.class);
        expect(cryptoTokenSessionMock.getCryptoToken(CRYPTOTOKEN_ID)).andReturn(cryptoTokenMock).once();
        expect(cryptoTokenMock.getPrivateKey(OCSP_SIGN_KEY_ALIAS)).andReturn(getIssuerPrivKey()).once();
        expect(cryptoTokenMock.getSignProviderName()).andReturn(BouncyCastleProvider.PROVIDER_NAME).once();
        replay(cryptoTokenMock);
        // Status check of CA itself
        // Note: getRevocationStatusWhenCasPrivateKeyIsCompromised gets called twice. That is inefficient, and could be improved.
        expect(certificateStoreSessionMock.getStatus(ISSUER_CERT_DN, getIssuerCert().getSerialNumber())).andReturn(CertificateStatus.OK).once();
        // Don't return any OCSP keybindings
        expect(internalKeyBindingDataSessionMock.getIds(OcspKeyBinding.IMPLEMENTATION_ALIAS)).andReturn(Collections.emptyList()).once();

    }

    private Object extractStatus(final OcspResponseInformation respInfo) throws Exception {
        assertNotNull(respInfo);
        assertEquals(OCSPResp.SUCCESSFUL, respInfo.getStatus());
        final OCSPResp ocspResp = new OCSPResp(respInfo.getOcspResponse());
        final BasicOCSPResp brep = (BasicOCSPResp) ocspResp.getResponseObject();
        SingleResp[] singleResps = brep.getResponses();
        SingleResp singleResp = singleResps[0];
        return singleResp.getCertStatus();
    }

    private void assertGoodResponse(final OcspResponseInformation respInfo) throws Exception {
        assertNull("Status was not GOOD (=null). ", extractStatus(respInfo));
    }
 
    private void prepareOcspCache() {
        final X509Certificate issuerCert = getIssuerCert();
        final OcspKeyBinding ocspKeyBinding = new OcspKeyBinding();
        ocspKeyBinding.setName("Dummy Key Binding");
        ocspKeyBinding.setMaxAge(3600);
        ocspKeyBinding.setUntilNextUpdate(3600);
        ocspKeyBinding.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        OcspSigningCache.INSTANCE.addSingleEntry(new OcspSigningCacheEntry(issuerCert, CertificateStatus.OK, Collections.singletonList(issuerCert), issuerCert,
                getIssuerPrivKey(), BouncyCastleProvider.PROVIDER_NAME, ocspKeyBinding, ResponderIdType.KEYHASH));
    }

    private byte[] makeOcspRequest(final X509Certificate issuerCert, final BigInteger serialNumber, final ASN1ObjectIdentifier digestAlgo, byte[] nonce) {
        try {
            final X509CertificateHolder issuerCertHolder = new X509CertificateHolder(issuerCert.getEncoded());
            final DigestCalculator digestCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(digestAlgo));
            final CertificateID certId = new CertificateID(digestCalc, issuerCertHolder, serialNumber);
            final OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(certId).build();
            if (nonce != null) {
                Extension[] extensions = new Extension[1];
                // Max size of nonce is 32 bytes
                extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonce);
                gen.setRequestExtensions(new Extensions(extensions));
            }
            return gen.build().getEncoded();
        } catch (IOException | GeneralSecurityException | OperatorCreationException | OCSPException e) {
            throw new IllegalStateException(e);
        }
    }

    private X509Certificate getCert(final String pemData) {
        try {
            return CertTools.getCertfromByteArray(pemData.getBytes(StandardCharsets.US_ASCII), X509Certificate.class);
        } catch (CertificateParsingException e) {
            throw new IllegalStateException(e);
        }
    }


    private X509Certificate getIssuerCert() {
        return getCert(ISSUER_CERT);
    }

    private X509Certificate getSameDnRootCert() {
        return getCert(SAMEISSUER_ROOTCA_CERT);
    }

    private X509Certificate getSameDnSubCert() {
        return getCert(SAMEISSUER_SUBCA_CERT);
    }

    private X509Certificate getSameDnOcspSignerCert() {
        return getCert(SAMEISSUER_OCSPSIGNER_CERT);
    }

    private PrivateKey getPrivKey(final String pemData) {
        try {
            final PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(KeyTools.getBytesFromPEM(pemData, CertTools.BEGIN_PRIVATE_KEY, CertTools.END_PRIVATE_KEY));
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(pkKeySpec);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private PrivateKey getIssuerPrivKey() {
        return getPrivKey(ISSUER_PRIVKEY);
    }

    private PrivateKey getSameDnOcspSignerPrivKey() {
        return getPrivKey(SAMEISSUER_OCSPSIGNER_PRIVKEY);
    }

    private class TestOcspResponseGeneratorSessionBean extends OcspResponseGeneratorSessionBean {
        @Override
        protected void setMockedCaSession(final CaSessionLocal caSession) { super.setMockedCaSession(caSession); }
        @Override
        protected void setMockedCertificateStoreSession(final CertificateStoreSessionLocal certificateStoreSession) { super.setMockedCertificateStoreSession(certificateStoreSession); }
        @Override
        protected void setMockedCryptoTokenSession(final CryptoTokenSessionLocal cryptoTokenSession) { super.setMockedCryptoTokenSession(cryptoTokenSessionMock); }
        @Override
        protected void setMockedInternalKeyBindingDataSession(final InternalKeyBindingDataSessionLocal internalKeyBindingDataSession) { super.setMockedInternalKeyBindingDataSession(internalKeyBindingDataSession); }
        @Override
        protected void setMockedGlobalConfigurationSession(final GlobalConfigurationSessionLocal globalConfigurationSession) { super.setMockedGlobalConfigurationSession(globalConfigurationSession); }
        @Override
        protected void setMockedTimerService(final TimerService timerService) { super.setMockedTimerService(timerService); }
        @Override
        protected void setOcspDataSessionLocal(final OcspDataSessionLocal ocspDataSessionLocal) { super.setOcspDataSessionLocal(ocspDataSessionLocal); }
    }
}
