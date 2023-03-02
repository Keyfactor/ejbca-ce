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

package com.keyfactor.util.keys;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConfigurationCache;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;

import org.apache.log4j.Logger;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

/**
 * Tests the KeyTools class.
 */
public class KeyToolsTest {

    private static Logger log = Logger.getLogger(KeyToolsTest.class);

    private static final byte[] ks3 = Base64.decode(("MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCAyYwgDCABgkqhkiG9w0BBwGggCSABIID"
            + "DjCCAwowggMGBgsqhkiG9w0BDAoBAqCCAqkwggKlMCcGCiqGSIb3DQEMAQMwGQQU" + "/h0pQXq7ZVjYWlDvzEwwmiJ8O8oCAWQEggJ4MZ12+kTVGd1w7SP4ZWlq0bCc4MsJ"
            + "O0FFSX3xeVp8Bx16io1WkEFOW3xfqjuxKOL6YN9atoOZdfhlOMhmbhglm2PJSzIg" + "JSDHvWk2xKels5vh4hY1iXWOh48077Us4wP4Qt94iKglCq4xwxYcSCW8BJwbu93F"
            + "uxE1twnWXbH192nMhaeIAy0v4COdduQamJEtHRmIJ4GZwIhH+lNHj/ARdIfNw0Dm" + "uPspuSu7rh6rQ8SrRsjg63EoxfSH4Lz6zIJKF0OjNX07T8TetFgznCdGCrqOZ1fK"
            + "5oRzXIA9hi6UICiuLSm4EoHzEpifCObpiApwNj3Kmp2uyz2uipU0UKhf/WqvmU96" + "yJj6j1JjZB6p+9sgecPFj1UMWhEFTwxMEwR7iZDvjkKDNWMit+0cQyeS7U0Lxn3u"
            + "m2g5e6C/1akwHZsioLC5OpFq/BkPtnbtuy4Kr5Kwb2y7vSiKpjFr7sKInjdAsgCi" + "8kyUV8MyaIfZdtREjwqBe0imfP+IPVqAsl1wGW95YXsLlK+4P1bspAgeHdDq7Q91"
            + "bJJQAS5OTD38i1NY6MRtt/fWsShVBLjf2FzNpw6siHHl2N7BDNyO3ALtgfp50e0Z" + "Dsw5WArgKLiXfwZIrIKbYA73RFc10ReDqnJSF+NXgBo1/i4WhZLHC1Osl5UoKt9q"
            + "UoXIUmYhAwdAT5ZKVw6A8yp4e270yZTXNsDz8u/onEwNc1iM0v0RnPQhNE5sKEZH" + "QrMxttiwbKe3YshCjbruz/27XnNA51t2p1M6eC1HRab4xSHAyH5NTxGJ8yKhOfiT"
            + "aBKqdTH3P7QzlcoCUDVDDe7aLMaZEf+a2Te63cZTuUVpkysxSjAjBgkqhkiG9w0B" + "CRQxFh4UAHAAcgBpAHYAYQB0AGUASwBlAHkwIwYJKoZIhvcNAQkVMRYEFCfeHSg6"
            + "EdeP5A1IC8ydjyrjyFSdAAQBAAQBAAQBAAQBAASCCBoAMIAGCSqGSIb3DQEHBqCA" + "MIACAQAwgAYJKoZIhvcNAQcBMCcGCiqGSIb3DQEMAQYwGQQURNy47tUcttscSleo"
            + "8gY6ZAPFOl0CAWSggASCB8jdZ+wffUP1B25Ys48OFBMg/itT0EBS6J+dYVofZ84c" + "x41q9U+CRMZJwVNZbkqfRZ+F3tLORSwuIcwyioa2/JUpv8uJCjQ2tru5+HtqCrzR"
            + "Huh7TfdiMqvjkKpnXi69DPPjQdCSPwYMy1ahZrP5KgEZg4S92xpU2unF1kKQ30Pq" + "PTEBueDlFC39rojp51Wsnqb1QzjPo53YvJQ8ztCoG0yk+0omELyPbc/qMKe5/g5h"
            + "Lx7Q+2D0PC/ZHtoDkCRfMDKwgwALFsSj2uWNJsCplspmc7YgIzSr/GqqeSXHp4Ue" + "dwVJAswrhpkXZTlp1rtl/lCSFl9akwjY1fI144zfpYKpLqfoHL1uI1c3OumrFzHd"
            + "ZldZYgsM/h3qjgu8qcXqI0sKVXsffcftCaVs+Bxmdu9vpY15rlx1e0an/O05nMKU" + "MBU2XpGkmWxuy0tOKs3QtGzHUJR5+RdEPURctRyZocEjJgTvaIMq1dy/FIaBhi+d"
            + "IeAbFmjBu7cv9C9v/jMuUjLroycmo7QW9jGgyTOQ68J+6w2/PtqiqIo3Ry9WC0SQ" + "8+fVNOGLr5O2YPpw17sDQa/+2gjozngvL0OHiABwQ3EbXAQLF046VYkTi5R+8iGV"
            + "3jlTvvStIKY06E/s/ih86bzwJWAQENCazXErN69JO+K3IUiwxac+1AOO5WyR9qyv" + "6m/yHdIdbOVE21M2RARbI8UiDpRihCzk4duPfj/x2bZyFqLclIMhbTd2UOQQvr+W"
            + "4etpMJRtyFGhdLmNgYAhYrbUgmdL1kRkzPzOs77PqleMpfkii7HPk3HlVkM7NIqd" + "dN0WQaQwGJuh5f1ynhyqtsaw6Gu/X56H7hpziAh0eSDQ5roRE7yy98h2Mcwb2wtY"
            + "PqVFTmoKuRWR2H5tT6gCaAM3xiSC7RLa5SF1hYQGaqunqBaNPYyUIg/r03dfwF9r" + "AkOhh6Mq7Z2ktzadWTxPl8OtIZFVeyqIOtSKBHhJyGDGiz3+SSnTnSX81NaTSJYZ"
            + "7YTiXkXvSYNpjpPckIKfjpBw0T4pOva3a6s1z5p94Dkl4kz/zOmgveGd3dal6wUV" + "n3TR+2cyv51WcnvB9RIp58SJOc+CvCvYTvkEdvE2QtRw3wt4ngGJ5pxmC+7+8fCf"
            + "hRDzw9LBNz/ry88y/0Bidpbhwr8gEkmHuaLp43WGQQsQ+cWYJ8AeLZMvKplbCWqy" + "iuks0MnKeaC5dcB+3BL55OvcTfGkMtz0oYBkcGBTbbR8BKJZgkIAx7Q+/rCaqv6H"
            + "HN/cH5p8iz5k+R3MkmR3gi6ktelQ2zx1pbPz3IqR67cTX3IyTX56F2aY54ueY17m" + "7hFwSy4aMen27EO06DXn/b6vPKj73ClE2B/IPHO/H2e8r04JWMltFWuStV0If5x0"
            + "5ZImXx068Xw34eqSWvoMzr97xDxUwdlFgrKrkMKNoTDhA4afrZ/lwHdUbNzh6cht" + "jHW/IfIaMo3NldN/ihO851D399FMsWZW7YA7//RrWzBDiLvh+RfwkMOfEpbujy0G"
            + "73rO/Feed2MoVXvmuKBRpTNyFuBVvFDwIzBT4m/RaVf5m1pvprSk3lo43aumdN9f" + "NDETktVZ/CYaKlYK8rLcNBKJicM5+maiQSTa06XZXDMY84Q0xtCqJ/aUH4sa/z8j"
            + "KukVUSyUZDJk/O82B3NA4+CoP3Xyc9LAUKucUvoOmGt2JCw6goB/vqeZEg9Tli0Q" + "+aRer720QdVRkPVXKSshL2FoXHWUMaBF8r//zT6HbjTNQEdxbRcBNvkUXUHzITfl"
            + "YjQcEn+FGrF8+HVdXCKzSXSgu7mSouYyJmZh42spUFCa4j60Ks1fhQb2H1p72nJD" + "n1mC5sZkU68ITVu1juVl/L2WJPmWfasb1Ihnm9caJ/mEE/i1iKp7qaY9DPTw5hw4"
            + "3QplYWFv47UA/sOmnWwupRuPk7ISdimuUnih8OYR75rJ0z6OYexvj/2svx9/O5Mw" + "654jFF2hAq69jt7GJo6VZaeCRCAxEU7N97l3EjqaKJVrpIPQ+3yLmqHit/CWxImB"
            + "iIl3sW7MDEHgPdQy3QiZmAYNLQ0Te0ygcIHwtPyzhFoFmjbQwib2vxDqWaMQpUM1" + "/W96R/vbCjA7tfKYchImwAPCyRM5Je2FHewErG413kZct5tJ1JqkcjPsP7Q8kmgw"
            + "Ec5QNq1/PZOzL1ZLr6ryfA4gLBXa6bJmf43TUkdFYTvIYbvH2jp4wpAtA152YgPI" + "FL19/Tv0B3Bmb1qaK+FKiiQmYfVOm/J86i/L3b8Z3jj8dRWEBztaI/KazZ/ZVcs/"
            + "50bF9jH7y5+2uZxByjkM/kM/Ov9zIHbYdxLw2KHnHsGKTCooSSWvPupQLBGgkd6P" + "M9mgE6MntS+lk9ucpP5j1LXo5zlZaLSwrvSzE3/bbWJKsJuomhRbKeZ+qSYOWvPl"
            + "/1RqREyZHbSDKzVk39oxH9EI9EWKlCbrz5EHWiSv0+9HPczxbO3q+YfqcY8plPYX" + "BvgxHUeDR+LxaAEcVEX6wd2Pky8pVwxQydU4cEgohrgZnKhxxLAvCp5sb9kgqCrh"
            + "luvBsHpmiUSCi/r0PNXDgApvTrVS/Yv0jTpX9u9IWMmNMrnskdcP7tpEdkw8/dpf" + "RFLLgqwmNEhCggfbyT0JIUxf2rldKwd6N1wZozaBg1uKjNmAhJc1RxsABAEABAEA"
            + "BAEABAEABAEABAEABAEABAEABAEABAEABAEAAAAAAAAAMDwwITAJBgUrDgMCGgUA" + "BBSS2GOUxqv3IT+aesPrMPNn9RQ//gQUYhjCLPh/h2ULjh+1L2s3f5JIZf0CAWQA"
            + "AA==").getBytes());

    private static final byte[] keys1024bit = Base64.decode(("MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAKA5rNhYbPuVcArT"
            + "mkthfrW2tX1Z7SkCD01sDYrkiwOcodFmS1cSyz8eHM51iwHA7CW0WFvfUjomBT5y" + "gRQfIsf5M5DUtYcKM1hmGKSPzvmF4nYv+3UBUesCvBXVRN/wFZ44SZZ3CVvpQUYb"
            + "GWjyC+Dgol5n8oKOC287rnZUPEW5AgMBAAECgYEAhMtoeyLGqLlRVFfOoL1cVGTr" + "BMp8ail/30435y7GHKc74p6iwLcd5uEhROhc3oYz8ogHV5W+w9zxKbGjU7b+jmh+"
            + "h/WFao+Gu3sSrZ7ieg95fSuQsBlJp3w+eCAOZwlEu/JQQHDtURui25SPVblZ9/41" + "u8VwFjk9YQx+nT6LclECQQDYlC9bOr1SWL8PBlipXB/UszMsTM5xEH920A+JPF4E"
            + "4tw+AHecanjr5bXSluRbWSWUjtl5LV2edqAP9EsH1/A1AkEAvWOctUvTlm6fWHJq" + "lZhsWVvOhDG7cn5gFu34J8JJd5QHov0469CpSamY0Q/mPE/y3kDllmyYvnQ+yobB"
            + "ZRg39QJBAINCM/0/eVQ58vlBKGTkL2pyfNYhapB9pjK04GWVD4o4j7CICfXjVYvq" + "eSq7RoTSX4NMnCLjyrRqQpHIxdxoE+0CQQCz7MzWWGF+Cz6LUrf7w0E8a8H5SR4i"
            + "GfnEDvSxIR2W4yWWLShEsIoEF4G9LHO5XOMJT3JOxIEgf2OgGQHmv2l5AkBThYUo" + "ni82jZuue3YqXXHY2lz3rVmooAv7LfQ63yzHECFsQz7kDwuRVWWRsoCOURtymAHp"
            + "La09g2BE+Q5oUUFx").getBytes());

    /** self signed cert done with above private key */
    private static final byte[] certbytes = Base64.decode(("MIICNzCCAaCgAwIBAgIIIOqiVwJHz+8wDQYJKoZIhvcNAQEFBQAwKzENMAsGA1UE"
            + "AxMEVGVzdDENMAsGA1UEChMEVGVzdDELMAkGA1UEBhMCU0UwHhcNMDQwNTA4MDkx" + "ODMwWhcNMDUwNTA4MDkyODMwWjArMQ0wCwYDVQQDEwRUZXN0MQ0wCwYDVQQKEwRU"
            + "ZXN0MQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAgbf2" + "Sv34lsY43C8WJjbUd57TNuHJ6p2Es7ojS3D2yxtzQg/A8wL1OfXes344PPNGHkDd"
            + "QPBaaWYQrvLvqpjKwx/vA1835L3I92MsGs+uivq5L5oHfCxEh8Kwb9J2p3xjgeWX" + "YdZM5dBj3zzyu+Jer4iU4oCAnnyG+OlVnPsFt6ECAwEAAaNkMGIwDwYDVR0TAQH/"
            + "BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0GA1UdDgQWBBQArVZXuGqbb9yhBLbu" + "XfzjSuXfHTAfBgNVHSMEGDAWgBQArVZXuGqbb9yhBLbuXfzjSuXfHTANBgkqhkiG"
            + "9w0BAQUFAAOBgQA1cB6wWzC2rUKBjFAzfkLvDUS3vEMy7ntYMqqQd6+5s1LHCoPw" + "eaR42kMWCxAbdSRgv5ATM0JU3Q9jWbLO54FkJDzq+vw2TaX+Y5T+UL1V0o4TPKxp"
            + "nKuay+xl5aoUcVEs3h3uJDjcpgMAtyusMEyv4d+RFYvWJWFzRTKDueyanw==").getBytes());

    private static final String storepwd = "foo123";
    private static final String pkAlias = "privateKey";

    private static final byte[] ecPublicKey = Base64.decode(("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAnXBeTH4xcl2c8VBZqtfgCTa+5sc" + 
            "wV+deHQeaRJQuM5DBYfee9TQn+mvBfYPCTbKEnMGeoYq+BpLCBYgaqV6hw==").getBytes());

    private static final String JWK_KEY_IDENTIFIER = "fAhtTrQfRIB0C31iCdPUe9ZJ_8wx4Ov-wn5MdUxCwoQ";
    private static final String JWK_PUBLIC_KEY = "{\"kid\":\"fAhtTrQfRIB0C31iCdPUe9ZJ_8wx4Ov-wn5MdUxCwoQ\",\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig"+
            "\",\"n\":\"j4g81S3nhh3vW2eGIYiwLsJC7cHGMunzMsAl6N4zyzDh0DgrtWn3Bawi32DZFAydbvlCRuLDjqw7m6AX7UUVVgUqCLg68B7uPQ2v7oC9swpLi4"+
            "lQ0C6zTqPdAsKTs7ZFd-4cluSFlBC6xkgqzP4dDvh6hJVHLI9SbbizTraGa9cnwjCuMIVxFbv1UNqM2fevmyjXUcMjdco5laeYcHh5LwAgFjedkagXRj35qAn"+
            "SDG727mUN0BFDdT-tGpmNkv7BXKd6aLzt5KvgxnNIMrMSlSoa0Pcot6iA7hd8Z_Tm5Jm0DmzAfPqYacGGCocN89x9cpoZEODSXimUfSqVL_3bNw\",\"e\":"+
            "\"AQAB\",\"x5c\":[\"MIICmTCCAYECBgF2ZxeHxzANBgkqhkiG9w0BAQsFADAQMQ4wDAYDVQQDDAVFSkJDQTAeFw0yMDEyMTUxNTQ3NDRaFw0zMDEyMTUxNT"+
            "Q5MjRaMBAxDjAMBgNVBAMMBUVKQkNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj4g81S3nhh3vW2eGIYiwLsJC7cHGMunzMsAl6N4zyzDh0Dgr"+
            "tWn3Bawi32DZFAydbvlCRuLDjqw7m6AX7UUVVgUqCLg68B7uPQ2v7oC9swpLi4lQ0C6zTqPdAsKTs7ZFd+4cluSFlBC6xkgqzP4dDvh6hJVHLI9SbbizTraGa9"+
            "cnwjCuMIVxFbv1UNqM2fevmyjXUcMjdco5laeYcHh5LwAgFjedkagXRj35qAnSDG727mUN0BFDdT+tGpmNkv7BXKd6aLzt5KvgxnNIMrMSlSoa0Pcot6iA7hd8"+
            "Z/Tm5Jm0DmzAfPqYacGGCocN89x9cpoZEODSXimUfSqVL/3bNwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAGVYzPvxozq/cSknbSUjddkG6rIM5/n4QHx4o/F4"+
            "KW0Bg2lXvN0ZSSTht5T+6Y4LhSvlcySQiq5zumCC+xPIkNP7ec1CKL9xjzinHDBckh1OxVhQpH157X2hYXAxA+3tIdNIJwd8KYsRXaR+YeyhjOCTNBzZtm0nuT"+
            "P9eSI3hw3v3uWPtbWeqhjjun8uDYLjW1Ptt+jGLd0VTnqK10n+VAYjLRKQF87+euCVFfPcBzwWwM8JbONKIUGj1MR8R8p4/rzmJ7jbyiEfDwtOKNMIwGUnGHfq"+
            "gPQkkiE4LY8a4MzdJuSPcT6FXDjvARjk22iEg+LrXOesDQGY/0xwVxs810\"],\"x5t\":\"W_cCMb00oHfX1snRC29oWQeH_IM\",\"x5t#S256\":\"gmvc8"+
            "frXsa_8ejoDdHSKfAJCA1C3s1hChQNOA2lw1XY\"}";

    @BeforeClass
    public static void beforeClass() throws Exception {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
    }

    @Test
    public void testGetCertChain() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        ByteArrayInputStream fis = new ByteArrayInputStream(ks3);
        store.load(fis, storepwd.toCharArray());
        Certificate[] certs = KeyTools.getCertChain(store, pkAlias);
        log.debug("Number of certs: " + certs.length);
        assertEquals("Wrong number of certs returned", 3, certs.length);
        for (int i = 0; i < certs.length; i++) {
            X509Certificate cert = (X509Certificate) certs[i];
            log.debug("SubjectDN: " + cert.getSubjectDN().toString());
            if (i == 0) {
                assertEquals("Wrong subjectDN", cert.getSubjectDN().toString(), "CN=fooca,C=SE");
            }
            if (i == 1) {
                assertEquals("Wrong subjectDN", cert.getSubjectDN().toString(), "CN=TestSubCA,O=AnaTom,C=SE");
            }
            if (i == 2) {
                assertEquals("Wrong subjectDN", cert.getSubjectDN().toString(), "CN=TestCA,O=AnaTom,C=SE");
            }
        }
    }

    @Test
    public void testGenKeysRSA() throws Exception {
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        assertNotNull("keys must not be null", keys);
        String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
        assertNotNull("b64private must not be null", b64private);
        // log.debug(b64private);
        X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        assertNotNull("cert must not be null", cert);
        String b64cert = new String(Base64.encode(cert.getEncoded()));
        assertNotNull("b64cert cannot be null", b64cert);
        // log.debug(b64cert);
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);
        // Test that fails
        PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(keys1024bit);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey pk = keyFactory.generatePrivate(pkKeySpec);
        try {
        	KeyTools.testKey(pk, keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);
        	assertTrue(false);
        } catch (InvalidKeyException e) {
        	assertEquals("Signature was not correctly verified.", e.getMessage());
        }
        
        AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(keys.getPublic());
        assertTrue((paramspec instanceof RSAKeyGenParameterSpec));
        RSAKeyGenParameterSpec rsaspec = (RSAKeyGenParameterSpec)paramspec;
        assertEquals(512, rsaspec.getKeysize());
        
        assertTrue(KeyTools.isPrivateKeyExtractable(keys.getPrivate()));
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (PrintStream ps = new PrintStream(out)) {
            KeyTools.printPublicKeyInfo(keys.getPublic(), ps);
        }
        String str = out.toString();
        assertTrue(str.contains("RSA key"));
    }

    @Test
    public void testCreateP12() throws Exception {
        Certificate cert = CertTools.getCertfromByteArray(certbytes, Certificate.class);
        PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(keys1024bit);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey pk = keyFactory.generatePrivate(pkKeySpec);
        KeyStore ks = KeyTools.createP12("Foo", pk, cert, (X509Certificate) null);
        assertNotNull("ks must not be null", ks);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // If password below is more than 7 chars, strong crypto is needed
        ks.store(baos, "foo123".toCharArray());
        assertTrue("baos size must not be 0", baos.size() > 0);
        Certificate cert1 = ks.getCertificate("Foo");
        assertNotNull(cert1);
        byte[] bytes = KeyTools.getSinglePemFromKeyStore(ks, "foo123".toCharArray());
        assertNotNull(bytes);
        String str = new String(bytes);
        assertTrue(str.contains("-----BEGIN PRIVATE KEY-----"));
        assertTrue(str.contains("-----BEGIN CERTIFICATE-----"));
    }

    @Test
    public void testCreateBcfks() throws Exception {
        Certificate cert = CertTools.getCertfromByteArray(certbytes, Certificate.class);
        PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(keys1024bit);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey pk = keyFactory.generatePrivate(pkKeySpec);
        KeyStore ks = KeyTools.createBcfks("Foo", pk, cert, null);
        assertNotNull("ks must not be null", ks);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // If password below is more than 7 chars, strong crypto is needed
        ks.store(baos, "foo123".toCharArray());
        assertTrue("baos size must not be 0", baos.size() > 0);
        Certificate cert1 = ks.getCertificate("Foo");
        assertNotNull(cert1);
        KeyStore keyStore = KeyStore.getInstance("BCFKS", BouncyCastleProvider.PROVIDER_NAME);
        keyStore.load(new ByteArrayInputStream(baos.toByteArray()), "foo123".toCharArray());
        assertNotNull(keyStore);
        log.info("Type of keystore: "  + keyStore.getType());
    }

    @Test
    public void testCreateJKS() throws Exception {
        Certificate cert = CertTools.getCertfromByteArray(certbytes, Certificate.class);
        PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(keys1024bit);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey pk = keyFactory.generatePrivate(pkKeySpec);
        KeyStore ks = KeyTools.createJKS("Foo", pk, "foo123", (X509Certificate)cert, null);
        assertNotNull("ks must not be null", ks);
        Certificate cert1 = ks.getCertificate("Foo");
        assertNotNull(cert1);
        byte[] bytes = KeyTools.getSinglePemFromKeyStore(ks, "foo123".toCharArray());
        assertNotNull(bytes);
        String str = new String(bytes);
        assertTrue(str.contains("-----BEGIN PRIVATE KEY-----"));
        assertTrue(str.contains("-----BEGIN CERTIFICATE-----"));        
    }

    @Test
    public void testGenKeysECDSANist() throws Exception {
        KeyPair keys = KeyTools.genKeys("secp384r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        assertNotNull("keys must not be null", keys);
        String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
        assertNotNull("b64private must not be null", b64private);
        // log.debug(b64private);
        X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, true);
        // log.debug(cert);
        assertNotNull("cert must not be null", cert);
        String b64cert = new String(Base64.encode(cert.getEncoded()));
        assertNotNull("b64cert cannot be null", b64cert);
        // log.info(b64cert);
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);
    }

    @Test
    public void testGenKeysECDSAFail() throws Exception {
    	try {
    		KeyTools.genKeys("fooBar", AlgorithmConstants.KEYALGORITHM_ECDSA);
    		assertTrue("This statement should throw", false);
    	} catch (InvalidAlgorithmParameterException e) {
    	}
    	try {
        	KeyTools.genKeys(null, null, AlgorithmConstants.KEYALGORITHM_ECDSA);
    		assertTrue("This statement should throw", false);
    	} catch (InvalidAlgorithmParameterException e) {
    	}
    }
    
    @Test
    public void testGenKeysDSA() throws Exception {
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_DSA);
        assertNotNull("keys must not be null", keys);
        assertEquals("Length must be 512", 512, KeyTools.getKeyLength(keys.getPublic()));
        String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
        assertNotNull("b64private must not be null", b64private);
        // log.debug(b64private);
        X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_DSA, true);
        assertNotNull("cert must not be null", cert);
        String b64cert = new String(Base64.encode(cert.getEncoded()));
        assertNotNull("b64cert cannot be null", b64cert);
        // log.debug(b64cert);
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);
        // Test that fails
        KeyPair keys1 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_DSA);
        try {
        	KeyTools.testKey(keys1.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);
        	assertTrue(false);
        } catch (InvalidKeyException e) {
        	assertEquals("Signature was not correctly verified.", e.getMessage());
        }
        
        AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(keys.getPublic());
        assertTrue((paramspec instanceof DSAParameterSpec));
        DSAParameterSpec dsaspec = (DSAParameterSpec)paramspec;
        assertEquals(512, dsaspec.getP().bitLength());
        
        assertTrue(KeyTools.isPrivateKeyExtractable(keys.getPrivate()));
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (PrintStream ps = new PrintStream(out)) {
            KeyTools.printPublicKeyInfo(keys.getPublic(), ps);
        }
        String str = out.toString();
        assertTrue(str.contains("DSA key"));
    }

    @Test
    public void testGenKeysECDSAAlgorithmSpec() throws Exception {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        keygen.initialize(ecSpec);
        KeyPair keys = keygen.generateKeyPair();
        assertEquals("EC", keys.getPublic().getAlgorithm());
        String spec = AlgorithmTools.getKeySpecification(keys.getPublic());
        assertEquals("secp256r1", spec);
        AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(keys.getPublic());

        KeyPair keys2 = KeyTools.genKeys(null, paramspec, AlgorithmConstants.KEYALGORITHM_ECDSA);
        assertEquals("ECDSA", keys2.getPublic().getAlgorithm());
        ECPublicKey pk1 = (ECPublicKey) keys.getPublic();
        ECPublicKey pk2 = (ECPublicKey) keys2.getPublic();
        // Verify that it's the same key size
        int len1 = KeyTools.getKeyLength(pk1);
        int len2 = KeyTools.getKeyLength(pk2);
        assertEquals(len1, len2);
        // Verify that the domain parameters are the same
        ECParameterSpec ecs1 = pk1.getParams();
        ECParameterSpec ecs2 = pk2.getParams();
        assertEquals(ecs1.getCofactor(), ecs2.getCofactor());
        assertEquals(ecs1.getOrder(), ecs2.getOrder());
        assertEquals(ecs1.getCurve(), ecs2.getCurve());
        // Verify that it is not the same key though
        assertFalse(pk1.getW().equals(pk2.getW()));
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);
    }

    @Test
    public void testGenKeysEdDSA() throws Exception {
        // EdDSA keys does not need any parameters to generate, but parameters can be provided
        {
            EdDSAParameterSpec spec = new EdDSAParameterSpec(EdDSAParameterSpec.Ed25519);
            KeyPair kp = KeyTools.genKeys(null, spec, AlgorithmConstants.KEYALGORITHM_ED25519);
            assertNotNull("Shold be able to generate Ed25519 key", kp);
            assertEquals("Ed25519", kp.getPublic().getAlgorithm());
            assertEquals("Length of Ed25519 should be 255", 255, KeyTools.getKeyLength(kp.getPublic()));
            KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_ED25519, 
                    CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_ED25519));
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            assertEquals("Ed25519", publicKey.getAlgorithm());
            assertEquals("Length of Ed25519 should be 255", 255, KeyTools.getKeyLength(publicKey));
            KeyTools.testKey(kp.getPrivate(), kp.getPublic(), CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_ED25519));
        }
        {
            KeyPair kp = KeyTools.genKeys(null, null, AlgorithmConstants.KEYALGORITHM_ED448);
            assertNotNull("Shold be able to generate Ed448 key", kp);
            assertEquals("Ed448", kp.getPublic().getAlgorithm());
            assertEquals("Length of Ed448 should be 448", 448, KeyTools.getKeyLength(kp.getPublic()));
            KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_ED448, 
                    CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_ED448));
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            assertEquals("Ed448", publicKey.getAlgorithm());
            assertEquals("Length of Ed448 should be 448", 448, KeyTools.getKeyLength(publicKey));
            KeyTools.testKey(kp.getPrivate(), kp.getPublic(), CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_ED448));
        }
    }
    
    @Test
    public void testGenKeysFalcon() throws Exception {
        {
            KeyPair keys = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_FALCON512);
            assertNotNull("keys must not be null", keys);
            String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
            assertNotNull("b64private must not be null", b64private);
            String spec = AlgorithmTools.getKeySpecification(keys.getPublic());
            assertEquals("FALCON-512", spec);
            X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                    AlgorithmConstants.SIGALG_FALCON512, true);
            assertNotNull("cert must not be null", cert);
            String b64cert = new String(Base64.encode(cert.getEncoded()));
            assertNotNull("b64cert cannot be null", b64cert);
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_FALCON512));
            KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_FALCON512, 
                    CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_FALCON512));
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keys.getPublic().getEncoded());
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            assertEquals("FALCON-512", publicKey.getAlgorithm());
            assertEquals("Strength of FALCON-512 should be 128", 128, KeyTools.getKeyLength(publicKey));
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_FALCON512));
        }
        {
            FalconParameterSpec spec = FalconParameterSpec.falcon_512;
            KeyPair kp = KeyTools.genKeys(null, spec, AlgorithmConstants.KEYALGORITHM_FALCON512);
            assertNotNull("Should be able to generate Falcon key", kp);
            assertEquals("FALCON-512", kp.getPublic().getAlgorithm());
            assertEquals("Strength of falcon-512 should be 128", 128, KeyTools.getKeyLength(kp.getPublic()));
            String s = AlgorithmTools.getKeySpecification(kp.getPublic());
            assertEquals("FALCON-512", s);
        }
        {
            KeyPair keys = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_FALCON1024);
            assertNotNull("keys must not be null", keys);
            String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
            assertNotNull("b64private must not be null", b64private);
            String spec = AlgorithmTools.getKeySpecification(keys.getPublic());
            assertEquals("FALCON-1024", spec);
            X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                    AlgorithmConstants.SIGALG_FALCON1024, true);
            assertNotNull("cert must not be null", cert);
            String b64cert = new String(Base64.encode(cert.getEncoded()));
            assertNotNull("b64cert cannot be null", b64cert);
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_FALCON1024));
            KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_FALCON1024, 
                    CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_FALCON1024));
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keys.getPublic().getEncoded());
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            assertEquals("FALCON-1024", publicKey.getAlgorithm());
            assertEquals("Strength of FALCON-1024 should be 256", 256, KeyTools.getKeyLength(publicKey));
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_FALCON1024));
        }
        {
            FalconParameterSpec spec = FalconParameterSpec.falcon_1024;
            KeyPair kp = KeyTools.genKeys(null, spec, AlgorithmConstants.KEYALGORITHM_FALCON1024);
            assertNotNull("Should be able to generate Falcon key", kp);
            assertEquals("FALCON-1024", kp.getPublic().getAlgorithm());
            assertEquals("Strength of falcon-1024 should be 256", 256, KeyTools.getKeyLength(kp.getPublic()));
            String s = AlgorithmTools.getKeySpecification(kp.getPublic());
            assertEquals("FALCON-1024", s);
        }
    }

    @Test
    public void testGenKeysDilithium() throws Exception {
        {
            KeyPair keys = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_DILITHIUM2);
            assertNotNull("keys must not be null", keys);
            String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
            assertNotNull("b64private must not be null", b64private);
            String spec = AlgorithmTools.getKeySpecification(keys.getPublic());
            assertEquals("DILITHIUM2", spec);
            X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                    AlgorithmConstants.SIGALG_DILITHIUM2, true);
            assertNotNull("cert must not be null", cert);
            String b64cert = new String(Base64.encode(cert.getEncoded()));
            assertNotNull("b64cert cannot be null", b64cert);
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_DILITHIUM2));
            KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_DILITHIUM2, 
                    CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_DILITHIUM2));
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keys.getPublic().getEncoded());
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            assertEquals("DILITHIUM2", publicKey.getAlgorithm());
            assertEquals("Strength of DILITHIUM2 should be 128", 128, KeyTools.getKeyLength(publicKey));
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_DILITHIUM2));
        }
        {
            DilithiumParameterSpec spec = DilithiumParameterSpec.dilithium2;
            KeyPair kp = KeyTools.genKeys(null, spec, AlgorithmConstants.KEYALGORITHM_DILITHIUM2);
            assertNotNull("Should be able to generate Dilithium key", kp);
            assertEquals("DILITHIUM2", kp.getPublic().getAlgorithm());
            assertEquals("Strength of DILITHIUM2 should be 128", 128, KeyTools.getKeyLength(kp.getPublic()));
            String s = AlgorithmTools.getKeySpecification(kp.getPublic());
            assertEquals("DILITHIUM2", s);
        }

        {
            KeyPair keys = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_DILITHIUM3);
            assertNotNull("keys must not be null", keys);
            String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
            assertNotNull("b64private must not be null", b64private);
            String spec = AlgorithmTools.getKeySpecification(keys.getPublic());
            assertEquals("DILITHIUM3", spec);
            X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                    AlgorithmConstants.SIGALG_DILITHIUM3, true);
            assertNotNull("cert must not be null", cert);
            String b64cert = new String(Base64.encode(cert.getEncoded()));
            assertNotNull("b64cert cannot be null", b64cert);
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_DILITHIUM3));
            KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_DILITHIUM3, 
                    CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_DILITHIUM3));
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keys.getPublic().getEncoded());
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            assertEquals("DILITHIUM3", publicKey.getAlgorithm());
            assertEquals("Strength of DILITHIUM3 should be 192", 192, KeyTools.getKeyLength(publicKey));
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_DILITHIUM3));
        }
        {
            DilithiumParameterSpec spec = DilithiumParameterSpec.dilithium3;
            KeyPair kp = KeyTools.genKeys(null, spec, AlgorithmConstants.KEYALGORITHM_DILITHIUM3);
            assertNotNull("Should be able to generate Dilithium key", kp);
            assertEquals("DILITHIUM3", kp.getPublic().getAlgorithm());
            assertEquals("Strength of DILITHIUM3 should be 192", 192, KeyTools.getKeyLength(kp.getPublic()));
            String s = AlgorithmTools.getKeySpecification(kp.getPublic());
            assertEquals("DILITHIUM3", s);
        }

        {
            KeyPair keys = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_DILITHIUM5);
            assertNotNull("keys must not be null", keys);
            String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
            assertNotNull("b64private must not be null", b64private);
            String spec = AlgorithmTools.getKeySpecification(keys.getPublic());
            assertEquals("DILITHIUM5", spec);
            X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                    AlgorithmConstants.SIGALG_DILITHIUM5, true);
            assertNotNull("cert must not be null", cert);
            String b64cert = new String(Base64.encode(cert.getEncoded()));
            assertNotNull("b64cert cannot be null", b64cert);
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_DILITHIUM5));
            KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_DILITHIUM5, 
                    CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_DILITHIUM5));
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keys.getPublic().getEncoded());
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            assertEquals("DILITHIUM5", publicKey.getAlgorithm());
            assertEquals("Strength of DILITHIUM5 should be 256", 256, KeyTools.getKeyLength(publicKey));
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.KEYALGORITHM_DILITHIUM5));
        }
        {
            DilithiumParameterSpec spec = DilithiumParameterSpec.dilithium5;
            KeyPair kp = KeyTools.genKeys(null, spec, AlgorithmConstants.KEYALGORITHM_DILITHIUM5);
            assertNotNull("Should be able to generate Dilithium key", kp);
            assertEquals("DILITHIUM5", kp.getPublic().getAlgorithm());
            assertEquals("Strength of DILITHIUM5 should be 256", 256, KeyTools.getKeyLength(kp.getPublic()));
            String s = AlgorithmTools.getKeySpecification(kp.getPublic());
            assertEquals("DILITHIUM5", s);
        }
    }

	@Test
	public void testGenKeysGOSTAlgorithmSpec() throws Exception {
	    AlgorithmConfigurationCache.INSTANCE.setGost3410Enabled(true);
        log.trace(">testGenKeysGOSTAlgorithmSpec");
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("ECGOST3410", BouncyCastleProvider.PROVIDER_NAME);
        
        final String keyspec = "GostR3410-2001-CryptoPro-B";
        AlgorithmParameterSpec ecSpec = ECGOST3410NamedCurveTable.getParameterSpec(keyspec); 
        keygen.initialize(ecSpec);
        
        KeyPair keys = keygen.generateKeyPair();
        assertEquals(AlgorithmConstants.KEYALGORITHM_ECGOST3410, keys.getPublic().getAlgorithm());
        
        String spec = AlgorithmTools.getKeySpecification(keys.getPublic());
        assertEquals(keyspec, spec);
        
        ECPublicKey ecpub = (ECPublicKey) keys.getPublic();
        java.security.spec.ECParameterSpec sunsp = ecpub.getParams();
        sunsp.getCurve(); // return value not tested
        
        // Nothing to do here, the gost parameter seem to behave similarly to EC parameter
        AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(keys.getPublic());
        
        KeyPair keys2 = KeyTools.genKeys(null, paramspec, AlgorithmConstants.KEYALGORITHM_ECGOST3410);
        KeyPair keys3 = KeyTools.genKeys(keyspec, AlgorithmConstants.KEYALGORITHM_ECGOST3410);
        
        assertEquals(AlgorithmConstants.KEYALGORITHM_ECGOST3410, keys2.getPublic().getAlgorithm());
        assertEquals(AlgorithmConstants.KEYALGORITHM_ECGOST3410, keys3.getPublic().getAlgorithm());
        
        ECPublicKey pk1 = (ECPublicKey)keys.getPublic();
        ECPublicKey pk2 = (ECPublicKey)keys2.getPublic();
        ECPublicKey pk3 = (ECPublicKey)keys3.getPublic();
        
        // Verify that it's the same key size
        int len1 = KeyTools.getKeyLength(pk1);
        int len2 = KeyTools.getKeyLength(pk2);
        int len3 = KeyTools.getKeyLength(pk3);
        
        assertEquals(len1, len2);
        assertEquals(len1, len3);

        // Verify that the domain parameters are the same
        ECParameterSpec ecs1 = pk1.getParams();
        ECParameterSpec ecs2 = pk2.getParams();
        ECParameterSpec ecs3 = pk3.getParams();
        
        assertEquals(ecs1.getCofactor(), ecs2.getCofactor());
        assertEquals(ecs1.getOrder(), ecs2.getOrder());
        assertEquals(ecs1.getCurve(), ecs2.getCurve());
        
        assertEquals(ecs1.getCofactor(), ecs3.getCofactor());
        assertEquals(ecs1.getOrder(), ecs3.getOrder());
        assertEquals(ecs1.getCurve(), ecs3.getCurve());
        
        // Verify that it is not the same key though
        assertFalse(pk1.getW().equals(pk2.getW()));
        assertFalse(pk1.getW().equals(pk3.getW()));
        
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);
        
        byte[] signature = KeyTools.signData(keys2.getPrivate(),
                AlgorithmConstants.KEYALGORITHM_ECGOST3410,
                "Hello world ! How cool is ejbca ??".getBytes());
        
        assertTrue(KeyTools.verifyData(keys2.getPublic(),
                AlgorithmConstants.KEYALGORITHM_ECGOST3410,
                "Hello world ! How cool is ejbca ??".getBytes(),
                signature));
        
        
        ECPublicKeySpec ecspec = new ECPublicKeySpec(pk2.getW(), pk2.getParams());
        KeyFactory.getInstance("ECGOST3410").generatePublic(ecspec); // return value not tested
        KeyFactory.getInstance("EC").generatePublic(ecspec); // return value not tested
        
        log.trace("<testGenKeysGOSTAlgorithmSpec");
    }
	
	@Test
    public void testGenKeysDSTU4145AlgorithmSpec() throws Exception {
        assumeTrue(AlgorithmConfigurationCache.INSTANCE.isDstu4145Enabled());
        log.trace(">testGenKeysDSTU4145AlgorithmSpec");
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSTU4145", BouncyCastleProvider.PROVIDER_NAME);

        final String keyspec = "2.5";
        AlgorithmParameterSpec ecSpec = ECGOST3410NamedCurveTable.getParameterSpec(keyspec); 
        keygen.initialize(ecSpec);
        
        KeyPair keys = keygen.generateKeyPair();
        assertEquals(AlgorithmConstants.KEYALGORITHM_DSTU4145, keys.getPublic().getAlgorithm());
        
        String spec = AlgorithmTools.getKeySpecification(keys.getPublic());
        assertEquals(keyspec, spec);
        
        ECPublicKey ecpub = (ECPublicKey) keys.getPublic();
        java.security.spec.ECParameterSpec sunsp = ecpub.getParams();
        sunsp.getCurve(); // return value not tested
        
        // Nothing to do here, the gost parameter seem to behave similarly to EC parameter
        AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(keys.getPublic());
        
        KeyPair keys2 = KeyTools.genKeys(null, paramspec, AlgorithmConstants.KEYALGORITHM_DSTU4145);
        KeyPair keys3 = KeyTools.genKeys(keyspec, AlgorithmConstants.KEYALGORITHM_DSTU4145);
        
        assertEquals(AlgorithmConstants.KEYALGORITHM_DSTU4145, keys2.getPublic().getAlgorithm());
        assertEquals(AlgorithmConstants.KEYALGORITHM_DSTU4145, keys3.getPublic().getAlgorithm());
        
        ECPublicKey pk1 = (ECPublicKey)keys.getPublic();
        ECPublicKey pk2 = (ECPublicKey)keys2.getPublic();
        ECPublicKey pk3 = (ECPublicKey)keys3.getPublic();
        
        // Verify that it's the same key size
        int len1 = KeyTools.getKeyLength(pk1);
        int len2 = KeyTools.getKeyLength(pk2);
        int len3 = KeyTools.getKeyLength(pk3);
        
        assertEquals(len1, len2);
        assertEquals(len1, len3);

        // Verify that the domain parameters are the same
        ECParameterSpec ecs1 = pk1.getParams();
        ECParameterSpec ecs2 = pk2.getParams();
        ECParameterSpec ecs3 = pk3.getParams();
        
        assertEquals(ecs1.getCofactor(), ecs2.getCofactor());
        assertEquals(ecs1.getOrder(), ecs2.getOrder());
        assertEquals(ecs1.getCurve(), ecs2.getCurve());
        
        assertEquals(ecs1.getCofactor(), ecs3.getCofactor());
        assertEquals(ecs1.getOrder(), ecs3.getOrder());
        assertEquals(ecs1.getCurve(), ecs3.getCurve());
        
        // Verify that it is not the same key though
        assertFalse(pk1.getW().equals(pk2.getW()));
        assertFalse(pk1.getW().equals(pk3.getW()));
        
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);
        
        byte[] signature = KeyTools.signData(keys2.getPrivate(),
                AlgorithmConstants.KEYALGORITHM_DSTU4145,
                "Hello world ! How cool is ejbca ??".getBytes());
        
        assertTrue(KeyTools.verifyData(keys2.getPublic(),
                AlgorithmConstants.KEYALGORITHM_DSTU4145,
                "Hello world ! How cool is ejbca ??".getBytes(),
                signature));
        
        
        ECPublicKeySpec ecspec = new ECPublicKeySpec(pk2.getW(), pk2.getParams());
        KeyFactory.getInstance("DSTU4145").generatePublic(ecspec); // return value not tested
        KeyFactory.getInstance("EC").generatePublic(ecspec); // return value not tested
        
        log.trace("<testGenKeysDSTU4145AlgorithmSpec");
    }

    /**
     * Tests {@link KeyTools#getBytesFromPEM} and {@link KeyTools#getBytesFromPublicKeyFile}
     */
    @Test
    public void testGetBytes() throws Exception {
        final Certificate cert = CertTools.getCertfromByteArray(certbytes, Certificate.class);
        
        final byte[] der = cert.getPublicKey().getEncoded();
        final byte[] pem = CertTools.getPEMFromPublicKey(der);
        
        // Test getting DER from PEM
        final String pemString = new String(pem, StandardCharsets.US_ASCII);
        byte[] result = KeyTools.getBytesFromPEM(pemString, CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY);
        assertArrayEquals("getBytesFromPEM did not work.", der, result);
        
        final String badPem = pemString.substring(0, pemString.length()-10);
        result = KeyTools.getBytesFromPEM(badPem, CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY);
        assertNull("Result should be null on corrupt data", result);
        
        // Test getBytesFromPublicKeyFile
        result = KeyTools.getBytesFromPublicKeyFile(der);
        assertArrayEquals("getBytesFromPublicKeyFile on a DER file should be a no-op.", der, result);
        
        result = KeyTools.getBytesFromPublicKeyFile(pem);
        assertArrayEquals("getBytesFromPublicKeyFile on a PEM should also work.", der, result);
        
        final byte[] invalid = Arrays.copyOf(der, der.length-1);
        try {
            result = KeyTools.getBytesFromPublicKeyFile(invalid);
            fail("getBytesFromPublicKeyFile on corrupt data should throw");
        } catch (CertificateParsingException e) {
            // NOPMD expected
        }
    }

    @Test
    public void testBlackListedEcCurves() throws Exception {
        for (final String blackListedEcCurve : AlgorithmConstants.BLACKLISTED_EC_CURVES) {
            try {
                KeyTools.genKeys(blackListedEcCurve, AlgorithmConstants.KEYALGORITHM_ECDSA);
                fail("Block listed algorithm " + blackListedEcCurve + " now works. Please update block list.");
            } catch (InvalidAlgorithmParameterException e) {
                log.debug(e.getMessage(), e);
            }
        }
    }

    @Test
    public void testNotBlackListedEcCurves() throws Exception {
        final StringBuilder sb = new StringBuilder();
        @SuppressWarnings("unchecked")
        final Enumeration<String> ecNamedCurvesStandard = ECNamedCurveTable.getNames();
        while (ecNamedCurvesStandard.hasMoreElements()) {
            final String namedEcCurve = ecNamedCurvesStandard.nextElement();
            if (AlgorithmConstants.BLACKLISTED_EC_CURVES.contains(namedEcCurve)) {
                continue;
            }
            try {
                KeyTools.genKeys(namedEcCurve, AlgorithmConstants.KEYALGORITHM_ECDSA);
                log.debug("Succeeded to generate EC key pair using " + namedEcCurve);
            } catch (InvalidAlgorithmParameterException | IllegalStateException | IllegalArgumentException e) {
                log.debug("Failed to generate EC key pair using " + namedEcCurve, e);
                sb.append(namedEcCurve + " ");
            }
        }
        assertTrue("Failed to generate EC key pair using " + sb.toString(), sb.length()==0);
    }

    @Test
    public void testGetBytesFromCtLogKeyEmpty() {
        try {
            KeyTools.getBytesFromCtLogKey(new byte[] {});
            fail("Should throw");
        } catch (CertificateParsingException e) {
            assertEquals("Public key file is empty", e.getMessage());
        }
    }

    @Test
    public void testGetBytesFromCtLogKeyBadAscii() {
        try {
            KeyTools.getBytesFromCtLogKey(new byte[] { -12 });
            fail("Should throw");
        } catch (CertificateParsingException e) {
            assertEquals("Public key could not be parsed as either PEM, DER or base64.", e.getMessage());
        }
    }

    @Test
    public void testGetBytesFromCtLogKeyBadB64Key() {
        try {
            KeyTools.getBytesFromCtLogKey("AQIDBA==".getBytes(StandardCharsets.US_ASCII));
            fail("Should throw");
        } catch (CertificateParsingException e) {
            assertEquals("The base64 encoded data does not represent a public key.", e.getMessage());
        }
    }

    @Test
    public void testGetBytesFromOauthKeyEmpty() {
        try {
            KeyTools.getBytesFromOauthKey(new byte[] {});
            fail("Should throw");
        } catch (CertificateParsingException e) {
            assertEquals("Public key file is empty", e.getMessage());
        }
    }

    @Test
    public void testGetBytesFromOauthKeyInvalid() {
        try {
            KeyTools.getBytesFromOauthKey(new byte[] {'x'});
            fail("Should throw");
        } catch (CertificateParsingException e) {
            assertEquals("Key could neither be parsed as PEM, DER, certificate or JWK", e.getMessage());
        }
    }

    @Test
    public void testGetBytesFromOauthKeyJwk() throws CertificateParsingException {
        final byte[] keyBytes = KeyTools.getBytesFromOauthKey(JWK_PUBLIC_KEY.getBytes(StandardCharsets.US_ASCII));
        assertNotNull("Should get an encoded key", keyBytes);
        final PublicKey pubKey = KeyTools.getPublicKeyFromBytes(keyBytes);
        assertNotNull("Bytes should represent a public key", pubKey);
    }

    @Test
    public void testGetBytesFromOauthKeyCertificate() throws CertificateParsingException {
        final byte[] keyBytes = KeyTools.getBytesFromOauthKey(certbytes);
        assertNotNull("Should get an encoded key", keyBytes);
        final PublicKey pubKey = KeyTools.getPublicKeyFromBytes(keyBytes);
        assertNotNull("Bytes should represent a public key", pubKey);
    }

    @Test
    public void testGetKeyIdFromJwkKeyBadKey() {
        assertNull("For malformed keys, the Key ID should be null", KeyTools.getKeyIdFromJwkKey(new byte[] {'x'}));
    }

    @Test
    public void testGetKeyIdFromJwkKey() {
        assertEquals("Wrong Key Identifier as returned", JWK_KEY_IDENTIFIER, KeyTools.getKeyIdFromJwkKey(JWK_PUBLIC_KEY.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    public void testGetBytesFromCtLogKeyGoodKeys() throws CertificateParsingException {
        assertArrayEquals("Binary public key was not parsed correctly", ecPublicKey, KeyTools.getBytesFromCtLogKey(ecPublicKey));
        final byte[] b64Key = Base64.encode(ecPublicKey);
        assertArrayEquals("Base64 public key was not parsed correctly", ecPublicKey, KeyTools.getBytesFromCtLogKey(b64Key));
        final byte[] pemKey = CertTools.getPEMFromPublicKey(ecPublicKey);
        assertArrayEquals("PEM public key was not parsed correctly", ecPublicKey, KeyTools.getBytesFromCtLogKey(pemKey));
    }

    @Test
    public void testKeyspecToKeyalg() {
        assertEquals("RSA", KeyTools.keyspecToKeyalg("1024"));
        assertEquals("RSA", KeyTools.keyspecToKeyalg("RSA1024"));
        assertEquals("DSA", KeyTools.keyspecToKeyalg("DSA1024"));
        assertEquals("FALCON-512", KeyTools.keyspecToKeyalg("FALCON-512"));
        assertEquals("FALCON-1024", KeyTools.keyspecToKeyalg("FALCON-1024"));
        assertEquals("DILITHIUM2", KeyTools.keyspecToKeyalg("DILITHIUM2"));
        assertEquals("DILITHIUM3", KeyTools.keyspecToKeyalg("DILITHIUM3"));
        assertEquals("DILITHIUM5", KeyTools.keyspecToKeyalg("DILITHIUM5"));
        assertEquals("Ed25519", KeyTools.keyspecToKeyalg("Ed25519"));
        assertEquals("Ed448", KeyTools.keyspecToKeyalg("Ed448"));
        assertEquals("ECDSA", KeyTools.keyspecToKeyalg("prime156v1"));
        assertEquals("ECDSA", KeyTools.keyspecToKeyalg("foo"));

    }
}
