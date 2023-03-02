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

package com.keyfactor.util.crypto.algorithm;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConfigurationCache;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.pqc.jcajce.interfaces.DilithiumKey;
import org.bouncycastle.pqc.jcajce.interfaces.FalconKey;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

/**
 * Tests for AlgorithmTools. Mostly tests border cases.
 */
public class AlgorithmToolsTest {
    private static final Logger log = Logger.getLogger(AlgorithmToolsTest.class);

    private static final String PRESIGN_VALIDATION_KEY_RSA_PRIV =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
                    "MIIEogIBAAKCAQEAy0d3OgaScTQrYT2ujMYESueWv4Iz7OnuuX17tYvlSYpEc75I\n" +
                    "xPexlt0hXFneqi7MC787tXfD7ZJCNbXT1YP9bd4+pOhBONR3Mwg01Ig1sZ9826Vo\n" +
                    "1NR4YxO+NFi1noV8qUVsGV5NBs7i/R6lJIcO05KFa1JCYShETl+V9RMg6zEekJNS\n" +
                    "9Ds6lzFuudwOnz/8ldZ85iZxG7ssbDI5zz3FDJ1HOSofJ8llP6D97nYJBf/kXmPu\n" +
                    "G3KE9pF9Cto3KkPViDbTmuwx2RfISvdqbJESTvcPhk4K7J+yx2XwIFjzAT6SGP4I\n" +
                    "NDnNGXt79PUyefXWzIqyafOXDD/JPkaMCEN/0wIDAQABAoIBAFGvOxK/F1OUEiZ2\n" +
                    "IdEBtTHgU+xKxtDZxAsXiIGQYKenfxA/k4BKxDsKSuCQYHBkc6v4wWaPZNTvY9mv\n" +
                    "Yhs3ebwPhX7AsYzDm86O6qPIxELHAuZEVpbHdkTh5xmj1/+GRmzCr8iV4z/sHLx3\n" +
                    "9wZxmxybkS9qE7B0/NW9hUXA1QaMs13uPsaQnYStoeyaGTp8fqNImTxUOWkYFS1C\n" +
                    "D7guA5Pq3SoUm9PEy5dv0GyE5oXEDnLOmQIzdftilzleY4Zxe8BiqWf4k5FJiLQI\n" +
                    "T1PUQaqtf3Ei6WykQnUuX5iHyS8hkKbOfQFc88uEjKUVAPUMyMcSLWB9mPwDJfB0\n" +
                    "d0KXriECgYEA+SMRzeAUL+MmE+PsAFeQtFiRKFsLBU3SrUyIQYRwNl4upV7CAvdZ\n" +
                    "J1ipPkDxvuJt12Tpcw3I6VRsWy2Sdu881ue2/AJ7wj0HrYGnNkr1Zqv76LbeXWTI\n" +
                    "8E/aFIu0Z+is+F/iigyVe//roMN+l5S/HX6TeJKxV+pS5ahplS5TtwMCgYEA0OEA\n" +
                    "9rfKV6up2SqRU8TiBisjl/pePEQZkKgpnYQcOyGBAQL5Zk60Cqa/Xm04NCTPJPyK\n" +
                    "Qm5aD1y7c0526vIj0LJrs9X5AmqBN5f4SMbx/L0g8gAMCvjn4wwS2qX7K0mc92Ff\n" +
                    "9/qJizxq8cJO5RC6H3t9OWgZuasWBMRGye4yEvECgYBdL3ncWIEUfFDkxa6jXh1Y\n" +
                    "53u77XnMzRQNEAAzCVdzbnziC/RjaaMmLWp4R5BkhorxMuSCzVglthclb4FGDSvj\n" +
                    "ch4mWsNxnqQ9iK5Dh3wMoC2EGMpJgoYKJMP8RVkAOK5h5HN2kUhkbg/zPMwf5For\n" +
                    "rQl54tyEdrf1AK4lR4O2gwKBgA6CElcQnPVJ7xouYrm2yxwykt5TfYgiEsSBaaKP\n" +
                    "MobI5PT1B+2bOdYjjtc4LtcwV1LyV4gVshuvDTYNFSVsfCBaxDBRhGIuk5sQ6yXi\n" +
                    "65vqZwdoCW4Zq8GRbR3SuYdgLY7hLJFEzZjmMWdpX6F5b/QP17rNCDxlLbpXB7Ou\n" +
                    "37uBAoGAFQSOOBpuihRekEHhkQdu8p1HrPxEhXPrzWvLrOjIezRU9/3oU32cfKS/\n" +
                    "LflobGIhsqsQzdAtpfZdEZmRq6hPQ4tw+6qaql5a5164AteOrq6UjMLuuxJyGVNQ\n" +
                    "qB53/QNbrXSLAf100bBgotfutynTW4f37t0IPGG7i+44wEdj6gU=\n" +
                    "-----END RSA PRIVATE KEY-----\n";

    private static final String PRESIGN_VALIDATION_KEY_EC_SECP256R1_PRIV =
            "-----BEGIN EC PRIVATE KEY-----\n" +
                    "MHcCAQEEIEGrpEiJQlvnnPWqPVOT7LVD+h2RNw1orVXdu/HumkWqoAoGCCqGSM49\n" +
                    "AwEHoUQDQgAEjFHZzIXCz4W+BGV3V3lAoXMqISc4I39tgH5ErOWKMdU6pzpKWlXi\n" +
                    "gx9+SNtdz0OucKFLuGs9J0xHLJhTcLkuyQ==\n" +
                    "-----END EC PRIVATE KEY-----\n";

    private static final String PRESIGN_VALIDATION_KEY_EC_SECP384R1_PRIV =
            "-----BEGIN EC PRIVATE KEY-----\n" +
                    "MIGkAgEBBDCoT+vJRt9bVUD2zk5r2s6MAfoQOZW1mPAGazJIyTxjF+QpFJuSsTt9\n" +
                    "MHK5e3JKswOgBwYFK4EEACKhZANiAASXpPMP3vBs9isr8ssU91Ex93XIiwyMQ77l\n" +
                    "r5FLJamnT5+eL7RwEPiK/rfFrJJS7glgbBAmzDlkxlw67EAd2gz3tyW9UoxF8jpe\n" +
                    "ojP8Ay3AJ3Ms1cAT+uYp+ySa1LPNsOk=\n" +
                    "-----END EC PRIVATE KEY-----";

    private static final String PRESIGN_VALIDATION_KEY_DSA_PRIV =
            "-----BEGIN DSA PRIVATE KEY-----\n" +
                    "MIIBvAIBAAKBgQD9f1OBHXUSKVLfSpwu7OTn9hG3UjzvRADDHj+AtlEmaUVdQCJR\n" +
                    "+1k9jVj6v8X1ujD2y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gEexAiwk+7qdf+t8Yb\n" +
                    "+DtX58aophUPBPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/IiAxmd0UgBxwIVAJdg\n" +
                    "UI8VIwvMspK5gqLrhAvwWBz1AoGBAPfhoIXWmz3ey7yrXDa4V7l5lK+7+jrqgvlX\n" +
                    "TAs9B4JnUVlXjrrUWU/mcQcQgYC0SRZxI+hMKBYTt88JMozIpuE8FnqLVHyNKOCj\n" +
                    "rh4rs6Z1kW6jfwv6ITVi8ftiegEkO8yk8b6oUZCJqIPf4VrlnwaSi2ZegHtVJWQB\n" +
                    "TDv+z0kqAoGBAJRiL6UUbPHmkKbfYeCUAgKfQhDkOydXe5A6+s84M0fnNqdxj6Dx\n" +
                    "s3xdkycSp/nHb1heQY37cAEhp0z6WnMwksDtlq7aIZeqMCxkvaz57bDUumVzMkV1\n" +
                    "T/wuZztd3gz7p70NyDkt/1JfwlKGcC+wNVMF4T1a/Y7xLloTq3yH32h7AhRTckHA\n" +
                    "LPjKPKEFrG18K7yFkH5xGg==\n" +
                    "-----END DSA PRIVATE KEY-----\n";

    private static final String PRESIGN_VALIDATION_KEY_ED25519_PRIV =
            "-----BEGIN PRIVATE KEY-----\n" +
                    "MC4CAQAwBQYDK2VwBCIEIErU1sdUkfufFIiIjeyB6XCqEKR4dFtTYejBjH/jeM4O\n" +
                    "-----END PRIVATE KEY-----\n";

    private static final String PRESIGN_VALIDATION_KEY_ED448_PRIV =
            "-----BEGIN PRIVATE KEY-----\n" +
                    "MEcCAQAwBQYDK2VxBDsEOaEFdMTDqYgfCBO+L1X1gkY/MtsRCkkqRIRaf/w0sZL8\n" +
                    "MHdS7JohG5RxniPplORiTi/F/bIkJ8GZ7g==\n" +
                    "-----END PRIVATE KEY-----\n";

    public static final String PRESIGN_VALIDATION_KEY_FALCON512_PRIV =
            "-----BEGIN PRIVATE KEY-----\n" + 
                    "MIIIqwIBADAHBgUrzg8DAQSCCJswggiXAgEABIIBgOiPwhPgQPvy/efP/vuwNhRQ\n" + 
                    "fg+e/hAwAxeQRAwhwhROfggf/vvAfAhPQgQAOehPgRxexByRhfwABufgRwOggge/\n" + 
                    "gfQweefffxQvRvvvxAvAegvPPQgeuOQRtxQAxARPuwOvPQQ/h/gPgPetQ/QPQg+g\n" + 
                    "R/v/vwAPvyRuwxggBQPuw//AAfg/QCegCBu/QCxBRA+wPxOeQ//iAug/wRPBQhAf\n" + 
                    "wPwfQ/Q+vu//fxPABewQhAQf/OQwvQg/ePh/v/BfROw/Ov+/PP/CfxRvwvfwhA+R\n" + 
                    "wuggA/gBPvPu/f/heRwQQQxAwwPfQ/AAwgxhSQefgPw/POhvPu+gAwQ/AwiPwvvv\n" + 
                    "+9fPPAPAQOwAvBA/PvwwQPw/wByOgffAOwQRCOgwOQf/AhPPivQAufQAAugAQwBR\n" + 
                    "wQOvvuwPPPP+vQhvxf/wQAue+PfvAP+tx/A/g+fRwgyAQvwCvvfOfAQewhfyQBvf\n" + 
                    "u/wfgBQeQQgRPSSBwwu/Av/RPvgvQwRffhAfgRfPgQSCAYAEEcH0T3wYIAHwYAIM\n" + 
                    "DvvwL4D778MP0gTngb4EYT34L3cHoXwL8ED8QL70AXUAP0MIL38Tv79HoX8L4EHo\n" + 
                    "DsDzz0IQgYYb/4T/sH0L3sT4EAcED4cAckH4L0P/zf8AIL7UQAD//4D//4kEAIQD\n" + 
                    "4EMD4DsEIP4T4AILfwUgH4P8YQQD0L8AEQD0LwL33zwAb0EPkILn/0EIET8Pv8YD\n" + 
                    "4DYTsEYAoAIDocD8gAEIfrvz38T4D0Dv7sP8UHwIH7sYAMH0b0IYH7/8X8cAIMH4\n" + 
                    "DkAIMLv0MALz/8PnYj4oIAD8QMD8H//8YH8P8AD8ADMIAQHv73kgPgIMEDrwAXz8\n" + 
                    "gToED/oMQf/rv0D/zkL74EAQTz3/z4IL4YD3z0H/kEMH0gIMD0YAcMf/rwPrv7zc\n" + 
                    "QT/8X4EAEQAT77oH30EYnYEP8IIH0AHwT7zr38UMD3/0Hv4AEYQEgAwAXwEUfoII\n" + 
                    "P4MAL3wAMQX0AL/oEMMQIUgL4H74X0Anz4D7r8jn8EUP78EEggIA5CP88O8O30fO\n" + 
                    "HRfgEfIM3/8F4/zuTwD4BBr++jLxJRzmLTXP5vEMFQwe7ODSAv738QsA0fUD8f8m\n" + 
                    "/f4K4tYAp/n0xvXnGN4ZNirgAOPx3vfuAiPuCPQN3AQrzucaCP4GAwbu9gkZ1ODb\n" + 
                    "MdgQEPDyFSMLCRsQBw0WE+wd1PUG/OgZGgPWPRjt0u0UztcFAAjsEQLOLwr0AfYZ\n" + 
                    "HM/x+dEEHQcL9B3wG/gV7trr/fbaIvz7+/8a7OTsDuj7DR4OEPcbGf7VARXJwfsC\n" + 
                    "Ie0HDQflSPTrLe7n8O0r0fASGwzOBOy9LR3T4Oko3RP44w0D1CgZH/bj6SITGA4N\n" + 
                    "Dx8uIAApGQf0ChPU5i3q6/fgAvn+8hDs6BME6fHyIQDnDf/1Gw0T0BQiEf5H9vMM\n" + 
                    "C//s6cD66+Xw7/Hu7Srs6/cw2+YHPAMF7/dNwRkX+Q0J/N8pDjT1AAUUAfryJOn6\n" + 
                    "5+b3Bhw1AAQF7vPvFRIN5SQxBigd9vDv1MzwBxwUDPsJ7Nr4I/fk/OfH2eQH/tEc\n" + 
                    "IM38De4tCSb+B9gkNRju/evn0SjXDSH7/wbSH9RH+A4n/PD3Duf1NPfx/C0HCwUs\n" + 
                    "2g0tAxP2+QIYECfwNuTiI+7T+Pbxxub4GQgA9S7e/hbxyQoP/Azf/QEhHkAWCe0N\n" + 
                    "8QrrFxsFASYU+OAUz/fhCfXPHwPd7AAwggOEBIIDgAyiN8OuFHMicllYG+z2qnnV\n" + 
                    "B6RcHr+StEoFo0mCVbzm8ukVmZVxp/urjkt+YAfX0QCvPt0adkzYCD0MWAcMzRRY\n" + 
                    "GJNWHC8NfoQgx4BoOewJVWmDI69wd0X1ooS81XqI0SdnTdCaN9NmCrjB7grcr6FJ\n" + 
                    "eSiLlFGIhPpw5LZbnxBJR9JRgRximZ0xaNkhFrWj1sdaIjgS6sf622VHLdSp66QU\n" + 
                    "BqVFsVMCxyxUFCB4plpI+gayMZSPu0A71uncfaQccVRK5uBrhRthPWj0i9LYIo7Z\n" + 
                    "PqaJ3Ic61BdrTu+7JotWkMInkT6AQid2tYXBUv9Chf06ll8nDx2nJjfY+QX+RDjF\n" + 
                    "pLYIJaqGJ19wtxomKrskFHbYAkh1o6oISVZgDe5NfKbTxPup/hX8NHD1SXB2hhgK\n" + 
                    "ba2me7mWNpLfYSZRsdH6i618JlKV1qp+QLr7w80etYjRkPYBHX5g5FJRiR9NQUbf\n" + 
                    "aYMnHZOhxGmeJiwfVUD6ntR0ZrYFyQKiQJCwqLPjEcUc5J/EcoZYVmLj68bTszaG\n" + 
                    "gzWVbx2bWBZ1YybsF26u2+/bs3p2JKDbC0CYoVkFLxxDIZqFBUFbr2q99BcNJnwY\n" + 
                    "UEtih1pooqJQV2EBEwD2YQL1IVu5QfWzqKORDPg4iz9fbpRBdvM36qU1CWHR8W8V\n" + 
                    "NeUCsPHOAwqw+PacVjkVfNPwrWKMINQk2u4AwBh1naEUg/S0TuvrDBoeoeJaBoGg\n" + 
                    "J3ace8RhlJIgcTExl9ZLZr4N80wNz6fMUWX9SY+KCuOYvCiQOeVqBWjPilvSrDLV\n" + 
                    "DPslEvrWshWGb0Jc5y3Ho5P6OjfpB0YpoujoasR0jiIotvheK7lgvhYhAUEoCix1\n" + 
                    "SxBnQJYxgv3Dq10tPbpDDGQKcDqrRSMZbBYrg2VGD0H5/plomY0IkFlzYWUqmUxl\n" + 
                    "MXvIS3FJCEBnZVw2xr+hfAWQtpJ4hhDfxED1parFX0kMEnkHmsPmKkWVITNE1n39\n" + 
                    "KPCfqNWrEOXk7oKHIhnDBk0J/VH2o9qGwXE6sDQhHmyAkk4g5fvDu0BuJUvAq3xH\n" + 
                    "3MqBuafrfIhkFHzUZEqijeRMk3kWTc5U4gNJgTBkm5kK9Q3CwbihkqMEVjBpIAPO\n" + 
                    "gU2nJRcsT1jwPuIplH++KEmp9e8nLZkRisRG5pvusVRYH5lO2mjgiJfThM2scDxN\n" + 
                    "C4nIILlTUVCzVZkIeob6\n" + 
                    "-----END PRIVATE KEY-----\n";

    public static final String PRESIGN_VALIDATION_KEY_DILITHIUM2_PRIV =
            "-----BEGIN PRIVATE KEY-----\n" + 
                    "MIIPRAIBATANBgsrBgEEAQKCCwcEBASCCf8wggn7AgEAAyEA1A9TJqQjA7Xlr1Q4\n" +
                    "w+vvcep+t9fc7fv/njT8DCnraHUDIQCuIBiMpqjhxtrlo+bJ4RpA8RwhDmvDUK6/\n" +
                    "3s96Nx4YAgMhAF7LQuy3SDD49jUQLXWjm6IW8xQJM7DqHJlgaqFkKfihA4IBgQDK\n" +
                    "kmXgOAJKJHAJKSUTJojigCUEBQ4JJSLjNiEkuYiSQkSUyGhhgGhQKEjjBkVZwEAZ\n" +
                    "EC2kGI0DpSCJCEnjGCQBlTFgtk2TKC0CMnLhkIQEJUiYGDIMxQUIhoxZkCiBCJBg\n" +
                    "IoTDRGySxAgLGGVhICVIGEEjlzGQCGbUAkYAQzKUIjIaKE6gsJDaIk3kpCUCOSjD\n" +
                    "AGYSiUCMKGZaFokcBzFhAgIYxVCAFIGItgWgtmnAEmEEhWlMAFIRFjFKRI0EQk6Y\n" +
                    "JirSgjBChizapgQDomUBOTDDIgikFILQlCHAwohiqATBMpEZRWncpEAUNRGgEnIZ\n" +
                    "QIpSpAEgEgwUMkxZxI2MokkTGG6CpGEUMyWchADauC2ctgAahGmcIkQTwSgLlwQJ\n" +
                    "wyEBsyGECIEEtkjkljEZNmiAQk5MoI0hpkXUMAzEMGEBR5BKQm4KskwgkUEiEmZB\n" +
                    "BGEAoyzEhCWJqEwMGGZDEgXKlCGkECXICCzRgmzDCG4EM0EbMxFUJC7iAI5KBIYD\n" +
                    "ggGBABBCbmI4YCLAJFomDmQkkcAAQRs2ReMUaaFIDYRATByEDYw2JlsQLmKQEdEE\n" +
                    "iGK0LRExQNBCUQDCCduUQRzBbVOAYaSGkJuQhOAiRFoISpHIUYgoRsFAgiA4ZJSA\n" +
                    "MKGISJIkUaAEgNpCgcFAUiMGKmGEMdSEARjCQWE2QYJEAJEQgAM5RstAQhgjShMJ\n" +
                    "gRoDKcEQYKIYAkmAEaQwUYoSbRkTKgtCgBsWJAtBUhxJRAJEACEoTpiyDIiGcNyQ\n" +
                    "EZyISWCgDFkUCqAmShglEBKhJWIAThkVIFMYaJjEZBEGkgECRORAZRMiEAszgMCw\n" +
                    "AQqwgQMGKQmwbQEwRtiASYtEbABCJhs0UqAQgZiEaeMmYYCwUcqYaBJCiWEALpQE\n" +
                    "gQK4IWMWJhwnMpoWJkBESgkXhSQJKIOiJZQSLeSySVoocBCwTWSAUQBFbCCBcMnE\n" +
                    "ANCWCOQShhmyjEIUcYAWQgwxJoowbsjCgUQAjZsoRiEZAMkAhkOgMMA4ieKihROC\n" +
                    "gAO5MQOCBoEAqDO6smhey2OoPnAsy47lypAULiDeioe7sC4tb+cLkuKnCoT+ID9X\n" +
                    "pPk02N28DKD9zWk2s9N5NrIcvDB9Q1JH/c9DirC4aIZxdUimnHCwg+wwB6SFQhx6\n" +
                    "0NFOqW+573F7qtHkHRWi+LQ4gGIxwc3Ll5LqPkJI3xbgpOknZlkSuCo8GIvQX66b\n" +
                    "jSXwseaE9cZ0YoBr4qViI7RRMRLQGpAEXuDvl770lypHD4hwlTk8K4NnszQhm20b\n" +
                    "QJhXhJQhWt2OFhOiBkvTxAEXCvcPPNBBZIfKKf5m53faJq3cZGLyu037XQCpFBZP\n" +
                    "5hLFDj08y9pkojnuOMuefbGscSJteWMlNVe4bzcMnNpw43lNXB5ORbxh96kKgaW/\n" +
                    "nC7tyUiriGcFE/bZO39+WkPVQWYzAJUdVIxFvEZUi79bclkAVeFzXrZ6Nr/NU5xO\n" +
                    "udvmftPFaJurEcQfuhhmx6ZS2OfPuLFS5JzTCY/L0rG3HFpRn+USEkwqYRJswlPN\n" +
                    "wB0r58kgeIj6ZiV2Gv7GPc3Tb6RdKFUV0uFpSRlROCMXZjyVUutPDFFACWf3oucI\n" +
                    "SnYxaVlMP2pXxR+ARXfZfAyv336qcyQ0qEiEEMGgNHGarVrVXXcsioDEzdj4IEEY\n" +
                    "jLMyKD3a8lii85ZQceRshmrp+QMrRsiH4y01Tx3qCx2ioiF546m97keUdHV/lwnL\n" +
                    "S/9PSazlKLtQ36KK8SNR1PIvXOYj9c7NaE42jxzxsPwd8WHaIlsfVrSELwunomjC\n" +
                    "3bGdfURtizbN+wTS4HyHwB9IxDxFalWx7BJ0po7gm4clpoue9C3/4Z5J/PbFfsE0\n" +
                    "1C0vu63K7hksG3ZpHM3kPn9rxl/KzjlJP47rLpOs+3zwqDgi9JEN0ImHckku716a\n" +
                    "FmMwmncpfx/GtHByA3lkl8y2nv4svu01H50muI9GOH4S/KKWSP4D+AHR/ec2lYr3\n" +
                    "GrcIirASU+CgNT2/q6ZH155Zkn/Ov90mHLTKp8vWZlxlqO4ZcftpHww703pEtukx\n" +
                    "dZGQ8iqyIl29g9CuaN2UEs7rFsJZAaxIM+kmArihjKqlOJ1FRY2AqcD7/Gczkme1\n" +
                    "/bI07jg/xZA8t79zU0pNyzibmBGUiD25rSAqXUVkXByq/votJqkCulWVFYjNhZ3V\n" +
                    "GT45DbWypm7fi8ROrfdjp4NEKxwL9079XQf7n/+zY7k+nzZ9Z1ZayhyGB0SlHePV\n" +
                    "oVs2YEaWjrCAK9pRCIvl7+LDr/HrB/ciu7xye3OnhCBw+kXDaYUnyH0eQzWTO5zV\n" +
                    "o00VPD8Ddob9x6guig75ZbU1hiCQtG7Ek54pPcgvjzJYQHwGClqIivcbGEl+AtYx\n" +
                    "Le52wLXM/uheZagH9b93vWeWJiApl+2cuSnUCpvghDJTy7faUPTjKw7lpWXzvYpJ\n" +
                    "3gJJ8k3zANb/Pr/2mM8/VH+5D4Kn0TMwZmdmrKGiJ8xLO31zQsoPrBOd5O8wWjks\n" +
                    "h4HQfyFfvrFT1TY73K3GHdYnUphriCXJPfGVvabIuDV46pCc9bRNoy9bgEeP1L0h\n" +
                    "y2i4BPa0CEvQtgPoxb0DyX7lReSinv+R770os/TiL9J5VuPeUSgwvPDFFlNxqHuX\n" +
                    "s3SM80Fu0x8F2BZR6W3pzfMK3YtZ4SYcSBNEDeU0OJAmoNqTwpCLVjqAKBkLE5yF\n" +
                    "PW5V8iIXNK70DTkqEa0URosSpvpEPG3N86C/oKIhTFAUBsBYjudBrvv5Y/D4tB2U\n" +
                    "7HNdx4B9QCpfsvqhqaMkSlGculfrPY2Z7QL6ac1AIzdTD2+ivxRRzx1sCwmLANHG\n" +
                    "IKT7o9B+3lXcPzEDu9tQ//8ZwY77P/LgugpjNzgT5VxtDhbUxBkOuKnDVzjMhyA2\n" +
                    "GROtu3hfcoG0m4JjZOeaJvA162Qm1e7Dtkx77Ut5z/hABqK5+RifeYyDEi8k+2hy\n" +
                    "2dlDd5O6CJSTXH/p+gaGQD8lnAemdPs5uTfZcVkXxREgA3JQP7bbPBMXi2rRZzFu\n" +
                    "6+oU5s0cWv7sG9aNjJJkNiGzfUQsgS44XgEyuq7wNkBnvPu2mckOtzBB8DPYaVPy\n" +
                    "F4RMGyvaKwtEEk1dC74EGrX1EGTREpI49NatNCdzx+UZBLf45abbP1kns30b1UaI\n" +
                    "HHzXQc8HmXZ+C+i9dNpJNzs2Jdd1GRs4cTN7UcVqKOWu6ZyYByMNnDRK71XCt8lw\n" +
                    "e83r55NbSKmUufbP1ve5jcffEgaS9q9Mx2QeUJu4YRlNY2irv87+tGWBggUrADCC\n" +
                    "BSYEINQPUyakIwO15a9UOMPr73HqfrfX3O37/540/Awp62h1BIIFAFpfgzLccwgH\n" +
                    "D98fYQmccqJM/oSCK+KrMduRMsTefcLncBnc+VSmRQsOr3SVpbBIxOkG+1gz2dkV\n" +
                    "etb6JjTz8f1o4y/OU7EnEE6OwitIti/VN6HuQkfb3H8LUXGQUlDiV2oNw4EtfU9u\n" +
                    "KUUYf6mJz97ZEtIjrrP7FUbN3bC4sy6aKxvYf3gpfa9/K8Mx+H9GJ3hWa/DOa/Z4\n" +
                    "hW9+y0MRrDzPecv6EBIY8u8JKcyXzkDs/H7YA5Y2v3jdQ5pwNM1T9qyPtauDq1k5\n" +
                    "G3zQW3xwcUvnKODqLsjNgwBWJF7tnfdartYaugdKkgRaM80JrhLLmM/LYIlxTL06\n" +
                    "IVPcA0kgwFH+vKwrG1ZaC5P9e6ZU2CdlW3yYgH2DzJTKG1sTOAXXapTZ/S/0RvnF\n" +
                    "g3i/Lzz5xIKMHPHeqYiSCOixEwAyofFGvlou63xt6Vs9FwD6UHMSxQW5r0phD/47\n" +
                    "JFkK/d2MmlbdvSv2/4rrNeVdNNVf1SBFcovT38ZgUCxngLej1BTOpVjBthyM3TiM\n" +
                    "PQ/KdJfTne4U6f+fTKr+REzfRxPt7yQKSqpyYko2isAEiYKkgLCe/Usx5hHAHmmJ\n" +
                    "hXv3+vBaaClkVnMlK5mjJV8yT1G4F+pZ639+74jGoiSbOBDsR4RmJnQffMx2FRnP\n" +
                    "GNOyw1e7wlp2pYqZMLZ33aPegsaQz4W2aTQ+xwIp246yP20p531g89X7xT0oC1Lx\n" +
                    "UHoAoGCYPY+zh6CUe219Tkp6o+8lbW9R8ZRnU8D4G8keBvEFnWUC6UtNPsbJJpQC\n" +
                    "vjrdiKiJ0FGqfkt0ojOJwowBfloKkVJAUvVJymoX1dmVPROGy7bo8zggzAiKl5c8\n" +
                    "BSftbEhFgWLedK3mfcyKaO9OY4GKpD8CStOy2tYWl/OmMKH1TEaGZ5THsAZ+OlNT\n" +
                    "FbyzIPSsVbKO9dOos0Ca59HW4mA+HmD38bcmGismeeCz3E1VnyDpdzqKqO6/eZSj\n" +
                    "Zz7uUQUZqm79bWVrclR3BVv4uyNdJ/LyFq7g5pwn3C2QwhpMvEDLg0G6Xgg1v+VU\n" +
                    "+N3Po5dyG6ZG8a2g/XVNaFICamRaES9zBXiVKKcUxaIcyXPeKMyQvMLjh2L6qXRs\n" +
                    "3cw1XYSpAZiQl8NyI9WJt2kg+d666fIZFHvuGshT/D6kl+eMYqB1yuwobMcw2Y50\n" +
                    "d+yAfWnWJToMgmcySoo5h7MXamKk8LBw3C36Viq4Yw3UQ62np0LxvUGeUaN63+Xr\n" +
                    "+xK0B0M2aDTwEjpKDEaaDn16T+bLnKthrDXtei/8ats4W71SOIH8luNVErk1zNmL\n" +
                    "WKK/ArZrRdqR5cCaVTqJXWbCMrbGSsDY1CdMY1ehw0hFMflko5j6UuJu8gbdvRhv\n" +
                    "vcssipVprg68Cf4SKeP6kstxv+srRaAs2zoCy0dJ53ophemcYgnXGEwIumHur86y\n" +
                    "Ho+Kl6ccTWQf7Ap/vknnDMA/B5IVH9mDnSEsxQexYuaShAFu9fKoGwSCz3RVBG5z\n" +
                    "xo7Z1zLdvnsQVfeTSpLWUnmVCpaJgq2AMp/cYHSNq9H/oPqjxRRcVZEwPkP7LqEE\n" +
                    "e54gcvN0LCTV252rucsiPlz8FfN2kpGN/hz/Swcwt0xDLaPv0YxLvbpcHYlPI2Vr\n" +
                    "QTbYR0pTP58hSur3pkyUQZEvp73IEk84e4uvv9ISSuvrWOF4cr0qWe46dgy6Jvr3\n" +
                    "I2YdtGzVcb+DWzBw2MFFdg6WoxclMhte\n" +
                    "-----END PRIVATE KEY-----\n";

    public static final String PRESIGN_VALIDATION_KEY_DILITHIUM3_PRIV =
            "-----BEGIN PRIVATE KEY-----\n" +
                    "MIIXhAIBATANBgsrBgEEAQKCCwcGBQSCD78wgg+7AgEAAyEAkl0llPlRLJVIHCRj\n" + 
                    "w3pmBl4oqIIDmhcUN7NViJXhZLQDIQBhUOwoPs/ruvN2hagUGXqALFGXesO3o7dp\n" + 
                    "Ef4vdB88wQMhABM8IFsW9XpY80WSPjfuiGdlpVFA5Q1FttjaWZdTkMhdA4ICgQAU\n" + 
                    "UiOCRmeFFzR0hTBnZWNiZHhTJGRCQhISc3U3cjeFAigHghgHISBHGBIUdzInR1dY\n" + 
                    "RRAVNWZ4YjdjNzM2g3BYOFiFAlEVZENzg0SBIUBhVFE2MogDdHE4UAgYchOFggIm\n" + 
                    "cRMwF2cCdGNzMocyVxZ3IXg4NogShIJlUXRYMVF0AkFzIEIBAkRkUmEFIDWCN3Vi\n" + 
                    "MSNTY2hiRIZERnRYN4dTZFJxBUckInUUE2eBdUAjdEgXQ2MWEYZIY1ByNYRwMEBA\n" + 
                    "cEAFFkMxQ1h1QWNih0NFZ2MoIUOFWIVzJHEwRyGEQDc4RVI0AWNDMHczcBFEA0F2\n" + 
                    "FCQXZ4N2UHNGZUaEUHZXNxcnQgJoKAVCIXdIRWByCGR3ZGNCYYBQRzUBQ0VYQYhU\n" + 
                    "V0QFU2AmBCExgBdgBINwRDIhVkQhhBMXNlEEMkB2YBJFZkQjcFcVFkeCJFNlUEFF\n" + 
                    "ZkgTBiUUQwdTAlNmeDdWADcDYng4FmhRJCU4ZDNQNUBzRENwYGJod3dDZWFTOEF1\n" + 
                    "h0ImFCBQBjJSIFRShogUVjAIImYDc2UhCFdVIVE0ZmInODNFZCJCU0YYYDFohQaD\n" + 
                    "B1QSh2InR0R3gzQoUxBoInY1EohwRzJmMSVBUFBiFSURIWMzR4M4AjI4NIQydWEo\n" + 
                    "AmEFVRhzFVNzdENWNFZmJARyUxNihSEnEWERFWgiJoEEcFUmBREnE3QTUoFjhIRF\n" + 
                    "cChgInSABzSHN3FRFHEjQ2hIc2dDQGOCVhFYI0WHETd3CBCIiFgiJVZ3glVRQGVh\n" + 
                    "ZxiCdYYYgEBFhUIgEHUABCAkBDVTN3hzJ1SIE1YCRWVIFlghUoZHYYJnJ2UngRhg\n" + 
                    "MjdVgkZwgQWIMnBEETg3A4IDAQBBMYBwRkZgUneFEHYCJ4h2V4EEZFGGAjGCdSIn\n" + 
                    "E3hRVEUhF2QhhngXdmEWgDNEWChgEicHIyVSYmRkJTCFVgJIRoIiJkVSElQ2QAhh\n" + 
                    "IyEyhBgwYFMAAkRGaHVzZzCEWDR3VlFiB2hBJggidVJgNCJAQzR1QVcQhCYTAIcw\n" + 
                    "cFN0IHZAM2FnR0NGZWcDAXczVwMTaEh1QUVzgABxgHFUUoRiVwIkOCcANhMyMzgY\n" + 
                    "UiEQE4YAIoiCgxVTJ1FBZBNChjdyhleICFZYYVA4QWIwckFgMlQUMIVwBEiGFDZo\n" + 
                    "J0ETACYFJlRUY3Vlc1R2ExZXJAM0dYgjU2U2VmVnMgBEBnQWB0SIEzOBR3AkIFU2\n" + 
                    "YCYyF4doIYCBgmA3AUdWUjIjgFWEEXYTCFIHB4FDglRmQYNREjhnETgzFhc1FzVj\n" + 
                    "hSNichR2BjU0ZCIYgoUjYjNoBTE4MYQnSFcACGFoAhcGZoCHhQhSZDE2MEJliEJD\n" + 
                    "V0d2YUMYdmhWYwYgFYQjFzdENIURVgYmgDNSdjdDiIUDIQRXMziHYBGAUyJVOFJm\n" + 
                    "CGZ3AHcVMgYhIgRyESJVFHIFVEZgFWAFUWE4ERSDUGdiODFDNmgAcQOGUQF1ZlAl\n" + 
                    "MwBRciJygTZ4hoMSJ3cHODcwJ0ESiBAYMoIVVVIiODAnc0hFOFVwd2gSASYXSIJy\n" + 
                    "UgYnUnVTADgmAXAWEgVHaIY0BRaGVXSGMQVGFmQleEFwNxFyUTF4hkIghVBwJTNB\n" + 
                    "VVeGMCcVB1dVcCQGFEVFCAJjg1eFQ1Q4OEFDCFEXAYgCY0MRY4Z0SEYzJgJIJ4JU\n" + 
                    "MmhYSCJSZHQQIDEwhRMBYlFIhxIYcAMBMwhjGAQFZRNyaBeAMRFHc2Enc0RRJkMn\n" + 
                    "WGd4BlI2eDNwQzVwBxBzUWNXVig1JYQEd2ZyBwdYEwdUM4hIeDhShIKIFGRFRjNz\n" + 
                    "AnQCI2aGgCJVAWMoRkgDGFZyZ0aFNIhShXNFeAMkBYR2IlRRMRSBN0ZEUzVWhHBD\n" + 
                    "FTJVdzNkd1hzCBhXKGBThUNyWHUDggnBADEUwV4v3Rnlgw6f42DQ+x9ma+X5qRos\n" + 
                    "0EjiFuOlgwxDqYQWy0mdbMrwXc660+PNL93wPTpz2iD7115v/R+FmWSMXZGnOkZj\n" + 
                    "CPiPn5uMeIirLu/Kcf/nte2mh+/pifXnt0IkrNkMm0dymtFpf5pniR9PqmDyalZu\n" + 
                    "gjL3f545oSUcxbURgUb68doeUOTfp5zqonS7Dvure4s/2lgD7J0h1xgf+vmYYjvr\n" + 
                    "HelKFljR+LM84IHyeQOzncRSbWc37xKRk5dgv2FxvMdQjeu2Okdm9+4BG7bxB79H\n" + 
                    "+UcLl02JuyReOoUonK4BW1Rp57HPCNuVsl5TCr33zQ1hRtJcZBho8OnivXltt8pi\n" + 
                    "UA8eJuIeJigIiINJ+SUzohr2fJ6PG7s1Bf+7hiV615tPWwYILVUYCduxayGaXCNe\n" + 
                    "s2Jf9sywhEUUPx0jmyvwAzGDOsooFft7ODTU9uBNcmhVneUbMsBhgB62m693XybT\n" + 
                    "I6yg58nwq1t3BBMAtW2fkeBLIV4IGeOOR8yoMrKmB66Jyx5U6sQSkL0rzuzYYzBS\n" + 
                    "uY2wlEhbP8/VSHs9NjnQl6a+GztRCFOctWAf+ot6ksSEHPQ08ufjkXf0ek8VSMSC\n" + 
                    "I772VZp4tcY3t6DowWAw8pwaI5laakjvY5al53RV0BKYpnw3ngnODHN4SkmGawsr\n" + 
                    "GhcdzI/PUXfZcV2FwS3vX4Tjl6O1gHh3X/aY1ypQm70823UsMR1xNAg+YUsqALjP\n" + 
                    "+ms7UC498j97ren003IJGbHRXsoZDAbRhQhbksMSQaGf1ZbgAPK9xrtktBmhA5SD\n" + 
                    "mwNR3S41N/1rA88CIYq+nJDP/ngVl4ZHc63DOp55iph5HxvoGZOi+Xb7ZKl4gtU8\n" + 
                    "PFKRSv8tXUbDB3rw0mMGC5zuaIObKPjBTMAdZkMAypg4nKrp0gbKeQoHKo7LredZ\n" + 
                    "v8TKaMNeprQk97AWWq00yMcX4noFprKND+9Kf6FpoWP1+576pRmycvffEl8YjES8\n" + 
                    "SAZDGPgPfD5CoUh7zmhJ3SB+bosu2po9kDTXzvSGSB6GStO98T+FUezkS5dPvsZ8\n" + 
                    "WemoelUVKf679WoIwG62HuhBpsVROs0DJ+vjiqVyEmSUb33Uc0J58KgYXckQZ8MQ\n" + 
                    "CWZQtPqwz89WX4iXKMI+wtW1myEBszk/oxCb6eru7sb2jbptocK9BS6aUIHFbcao\n" + 
                    "/oeHU+xzaWNSg3qSlentjuPKZvZvy49mbsi3KK1sG1uvRtE1/4BmH1fnPvpQyPH5\n" + 
                    "+52YCG2p0X1F6sftICDr4X9U+nn9C6Og3Ucy5AMUvIxay5j8RmGZJMzR8CUwlpGH\n" + 
                    "odtxOA+3zjaa9CBvbVPvoBrlGr6VG1rMYnX/iW5GiJi/29vqqfUuAWhsxThr2zDI\n" + 
                    "z4DoliaWEM9wKvDRpeUW6kW9w07NBk5Gl5RaFkht+Fflh0zJvYSAYokodfSKvPCz\n" + 
                    "w8+ZEmlmK2SVXwykWXl05Zg8mNCgzX4FPdrn0yMZFzKLtqloqBskYuaIfcb9Jyni\n" + 
                    "h209EubGKvXbaKBqw1JxGZ4Enj1I7pUW5i9UxxHQOIq0bRtNDNyGgNMO65cIx6F+\n" + 
                    "7Gr3YvAgsyQBAyFtoWPu7xc2IFbhDf8l3F7oC1l9d/cgapJiuOWVEawVJkjCiudu\n" + 
                    "TPHU0PzN5xSK4rG4BFZ7USs8Dx6j4m5MMGUAAgWgmnLYkIobmsAeeomXFbdAd+w5\n" + 
                    "Wt8DAUHySt50YBa6K20i2jmCUd41aXp+c8mg8HzULx1tanLAcFKD95S1OTj8VqSX\n" + 
                    "c/3fWRvY2W3mNhqW9SWiHnuknqX8DFCXbANTkYg54pwy70WX0BZ+71RG/lZe236x\n" + 
                    "QrzVa7GjFjwPkoFElxWBZFWEHj8FT6hTySWVIYHN9t/EC9a2WV80V/C6dxQHPI2N\n" + 
                    "xFiC+Kn15Nf82V244G9S6xFTYBLfGZGZjUcUkF6cTggHdFST8Rn14Dg2phG+Inz6\n" + 
                    "/MHjw4PoGFWFCWAM5OYQYWXLolKhBj2TwwS/7vZ0Z/MKehpyRNRwN6MVZvcm202r\n" + 
                    "8A8hPg7Kt3L+O7l+nJ3NmG0H9znPC3YYkra3QvNNnLllnXqp9WFXGFu1qvVXC/1b\n" + 
                    "PpdPyFZjrxqFaOw5vV1xnqaxSwIgEDUJuftx/LtCoG/vUQdfA053yqnf4C6zdVdR\n" + 
                    "atU4BxsI2HRc3DaueyZVYR566z5SbEOlXcOGu4xQmmxTXQhaJXFtuvBZZUiFSaCI\n" + 
                    "sCCwUhR4+/wbALPCj8lkMxdgat6GH2dg1U2Q+ofg1KSceplNz6j/R76DqhnwgiY0\n" + 
                    "b1h3akH0APrrVX6qXs9GEWdPNh4kPK1OsDa2eNa0JHFQytzzcmtzc5dkD3q39NCE\n" + 
                    "IEAWdzHJuEwn0hMS9kekriofZx5tPXBVhKcW12btToXeACj6NmyZVG6aFr8V6YZ2\n" + 
                    "eL1alngTd0kL7GW57Ro+e6CyIgNw1wwYxeeZdZ7Oc4AaUi+lFc3U4Ur0YRgzyNtm\n" + 
                    "alKB+k3wt43625rJiLfAg1npsZwPaHNgCwOVBec4OyVJD/Y4f+UtnyOo8zVJfknh\n" + 
                    "lzXtWbKuhKU+/PGTtzuxRC4Qrs8hI44OAn/l+KsOzggr8PZ5b/hZg76IjfZkyFIP\n" + 
                    "Tebsey33yYKy/lKenhsg0+/5JrXkXyXkxPZ0CrQMRjnM2b39WXpUukrl+M3oTkeq\n" + 
                    "5mJWCFOGihcFy07jPLiTwtIphFs2RSMkUGbjws9NZM5zOpBP1kmkeo2qU7noFerL\n" + 
                    "0rxXGjQ14r3NbPPT+akEmXmZV654oY4ai8v53xKhpZ2VWH6DdIhlMT/A2upr8x03\n" + 
                    "GWCveTFz/aHLgSdqvtwoQLA4P7E6/OaoKCtArDqcQyeQbOO6M3T0I5XczMm43xmM\n" + 
                    "IEpms1/HBS4QKoohgqRmOyIrXPE8Q1JtQVuGBBYWNDhowTN41dEK0Qqu9+xoxwGN\n" + 
                    "2QmTbh/IAcQ3+9fHttCsWrfdJ9m1VmwxUoRTftic+bB4UsgHE2kXhoa6euEP7yLR\n" + 
                    "OLA28mmCsv5TZ7rphktXi7xAnP2NkHO1uvcbcXLIv1+WCfk+AJcrP0pO2iUw6qOV\n" + 
                    "sdbSpr6WlnvkR06JOXcIyCCKfPC63/fEV80JFG1ZvV9GqdN66h6vI5Q+vhW0NqQD\n" + 
                    "ivFaQtH9sxMyplsJGB4OZScp+3o2nKklfTGujzNBnriGv6NMVpjqDA2iPTWalg0z\n" + 
                    "xlHyWmfBfwVQRmuwvAZfG4lsaiA4bxw5zCvZWExWbnSwR7qFoMxvKnAx2106C0RM\n" + 
                    "nmsuN7yrYYIpoNBK2w2vq+ZMS28Qzeyh6gJp2gzScOnQuFXzgJ9gZZmvhJE+zld7\n" + 
                    "rPYaPE8bZnXaKTR5QSQiVO9+k0godd62rYGCB6sAMIIHpgQgkl0llPlRLJVIHCRj\n" + 
                    "w3pmBl4oqIIDmhcUN7NViJXhZLQEggeAtc5kEMCFWEhKAn8T72W94w9+nbJi5KZv\n" + 
                    "bdpacXMKHCl/QhaqHyUoCsgJf6Zb+Rid/kXHH9QjRUhn33KJfSWec1x+5cnenjjG\n" + 
                    "+EMQBkKgca99kRHD0nOC3TsIdNuhwpp6k2QDT6JhBcJ0Z24CHcAsmWlFnkimjNNv\n" + 
                    "Q+0sr/k2UdyzSgJx53o8HacweapAkm6zXI1SS805w8XtAF191vzRgZO+mVjH5U98\n" + 
                    "okLS9nJrmto9SWc9krWZ2GrP6c7VLZVpHUU2nwTe8nvzrUlOkEOM6Yw028mIQ6Ry\n" + 
                    "xo2c65j24RwamGpVBVpBoiKDLcVeVEWADeHAuv/p3doBudMr8OB0MxFfSOglylO1\n" + 
                    "DOTFL0C3A7qYKoDWVbQvWHfDO4DofVoz3X24Cy7JqSyqofvO8kO2a/YKNCirNvys\n" + 
                    "Jxaj7IZs9Kmc2BiBlXjZN+hFpLrkupwy0RsOnd8mj4Sc0Y7S2FqcbHu6uBcUoaJH\n" + 
                    "bU8fh9ZTn2V4F21r2s3VFV3+WyIP8u0wsO6gP5f/9mTaZsZSD8txQ0mDF6Co5eCH\n" + 
                    "gSHcHUaflbQJbp/vOCtI0/FMmkl10I19hIK2qJQBO2RK8NB7cWnLQu1nPZrbgDu7\n" + 
                    "Ip+RDEpFqCKYWUJ29IoLMnqbCNVam595yXE+qqsZRfuAnNq1fQyzVoTxGAUiWymI\n" + 
                    "/M3oTUQhzvrUGeYg+O9NGWN0vcf3ax5gsM6TRnjEhTH260viY7OhLhHeWmILMA2l\n" + 
                    "HXT3hLsiJswyfQm0/3igWcS8Q3M4t4Phc7YmqmGje/FcIsBxPe1s7jc0thX6QBaD\n" + 
                    "QDIPH4WzExHHyCry0OxHhExgXY6uDOC203yzeNFE1LtgPjtMVYRCsd+8yJIqNlFW\n" + 
                    "HUgAzHUgMqQvlktN1Uc/tbAIHx7SdxQN0/I/Eo0AcSCrBXDL61pUliNcuCUUx18X\n" + 
                    "tPV1+XeBXsqn2+H+HzU2QULCUSVE+MZ2q+8nvU53NAywPol1XH0vmTxEPRDPJy69\n" + 
                    "zszNdhSfVFAIERe8SRP0mM8ISdCteAqRDZ3lpy15FeCPzcPBd9JdSUqowsJpOvv6\n" + 
                    "7NKUqHp4UAw+auUXLrwj+mk/xlLtRRIJ8Uh7Af32pjk/koqHrncb1dHs10weumtE\n" + 
                    "NEnSORKVzY07FNO2rxLR/4LEs/uWYEd6GQmugPJqRSij9MmV2BFHcyy0NO6uVU0B\n" + 
                    "D25NOwrp8fZJosQw3aLHkTCuQf7qSFvg+lbYXUzVTXOOlxx2xlW2RkO3VMS6cYGs\n" + 
                    "Ft0Kr6JKkmejAL7iJevdLVyf3LXGQGh2d+032ob9zmroK96mlsk53FJbk+hU6QRd\n" + 
                    "2BHFtOAzjy2BtsPar31yfVlKuNp/8xSXl2dUeRqRgBL4aky9BpIz6bq8iOVvfAOi\n" + 
                    "RNslVokRd79j55U9QBMPVRUIgxCC5sNNSmXdzLnDqLT4TvpZWfH5Zb/JpVDimVzQ\n" + 
                    "pXYZwE90WFELZhdChaG5fOyXoF/Vsdcrv0ZLkmaXwfp4ZItIYTWJvzI9b3CQ+OB5\n" + 
                    "YA4e1BAh/oXDOHEPekD5eQJtZBa6xbc7nmpnP1ACEPwxqt6X2Eps3YqlqnpK7HDc\n" + 
                    "/Kdhi09iOw0m6A5xkXx/8c8Gpai3omQFZKjMx6QS3PombPAsqI4FzWYTpmkVJnDQ\n" + 
                    "SvTd9Rv+ypzD9FIpTdM0+AApY+GxbvgWpkJUA5GFDjDvXDj6pOc6uCiT0Q4Rqm3I\n" + 
                    "0z3ULiKByZsOdqccPm4VIbjtOPkSO81E14nyw+vOf5Ot2ykTk9HVTZ0UKd4ylwT9\n" + 
                    "ElqBGqVT238G36t/9oWzmYbxYyUhDA4qDQIvx3S+HLU+hkbzwv5edu93G4AdYGmQ\n" + 
                    "uTKcOqFYoZW5uY01uTEh8KipYbfUWMGPmSFVrE3MmUaCd9/oeB3zeGZRaPHlRoZ9\n" + 
                    "O6uP17X35f3zFaHTVJItT+GXQgn/Nhaw3cJN7oPE7kZTpsIgYhuBg3W4XYGtnp1L\n" + 
                    "udsllTzt1XxVBJKOgp5O2hkbt56HV0zadWNJIlsX9IP+oEEJWdOL0dEGkQRlmc4B\n" + 
                    "AyaqAOp3G6UlAgvVwSjNzpFgnQaOoHCtcIxAW1SgCP31lb1oOouaVsHJ5GB77iCh\n" + 
                    "mmFu7AvN9Px+vr8ogPdiHtHi5HAuDYumh+U0EI483XS9C16zM/BFz3JAOMUEavtT\n" + 
                    "fodaw8pIvvoAtBLvfpyedowcmEkwzOO+WFgntfUGgZ6Nyi40S9gI8fdj+fOVQWcp\n" + 
                    "l0AKOZiGGu5tHv7uUuDPNEoxm8lxmYERbeWS5iyuC4p6jBdKInMknq1iiT2IabsF\n" + 
                    "sIXSDklfXrjMXcLvq5PviC4l15cHtL4CjQHhmvgeb9/SL6rS3di/dULhLTQRmJN/\n" + 
                    "2lC5EOZPbZHnjh1wKxKlGDOc/K45fsTu/EM3VtjvyF0qBZajdr2LHOvRoLcbAsNg\n" + 
                    "xUOppa76slz2Y/8N1rkMTSuyu27H3l7rqpXvfpOix9srsFfZUQERI85Ra5mIticI\n" + 
                    "SASeS/bI8XSt2YgbbQkWD+aVTodHDd0Yoh3OhG+0C/sGy5zLI1WgB43BEUlaLFF5\n" + 
                    "BNlqKphjjx9wQTqpKF3v7e9bszIczqb7\n" + 
                    "-----END PRIVATE KEY-----\n";

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void testGetKeyAlgorithm() {
        assertNull("null if no match", AlgorithmTools.getKeyAlgorithm(new MockNotSupportedPublicKey()));
        assertEquals("Should find DSA key",
                AlgorithmConstants.KEYALGORITHM_DSA,
                KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_DSA_PRIV).getPublic().getAlgorithm());
        assertEquals("Should find RSA key",
                AlgorithmConstants.KEYALGORITHM_RSA,
                KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_RSA_PRIV).getPublic().getAlgorithm());
        assertEquals("Should find secp256r1 key",
                AlgorithmConstants.KEYALGORITHM_ECDSA,
                KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_EC_SECP256R1_PRIV).getPublic().getAlgorithm());
        assertEquals("Should find secp384r1 key",
                AlgorithmConstants.KEYALGORITHM_ECDSA,
                KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_EC_SECP384R1_PRIV).getPublic().getAlgorithm());
        assertEquals("Should find Ed25519 key",
                AlgorithmConstants.KEYALGORITHM_ED25519,
                KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_ED25519_PRIV).getPublic().getAlgorithm());
        assertEquals("Should find Ed448 key",
                AlgorithmConstants.KEYALGORITHM_ED448,
                KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_ED448_PRIV).getPublic().getAlgorithm());
        assertEquals("Should find Falcon-512 key",
                "FALCON-512",
                KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_FALCON512_PRIV).getPublic().getAlgorithm());
        assertEquals("Should find Dilithium-2 key",
                "DILITHIUM2",
                KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_DILITHIUM2_PRIV).getPublic().getAlgorithm());
    }

    @Test
    public void testGetSignatureAlgorithmsNotSupportedKey() {
        final List<String> algs = AlgorithmTools.getSignatureAlgorithms(new MockNotSupportedPublicKey());
        assertNotNull("should not return null", algs);
        assertEquals("no supported algs", 0, algs.size());
    }

    @Test
    public void testDigestFromAlgoName() throws Exception {
        final byte[] someBytes = new byte[] {};
        // SHA2-{256,384,512}
        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA).digest(someBytes);
        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA256_WITH_RSA).digest(someBytes);
        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1).digest(someBytes);

        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA).digest(someBytes);
        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA384_WITH_RSA).digest(someBytes);
        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA384_WITH_RSA_AND_MGF1).digest(someBytes);

        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA).digest(someBytes);
        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA512_WITH_RSA).digest(someBytes);
        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1).digest(someBytes);
        // SHA3-{256,384,512}
        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA).digest(someBytes);
        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA).digest(someBytes);

        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA).digest(someBytes);
        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA).digest(someBytes);

        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA).digest(someBytes);
        AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA).digest(someBytes);

        // There is no digest defined for Ed25519, Ed448, Falcon, Dilithium
        try {
            AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_ED25519).digest(someBytes);
            fail("should have thrown for Ed25519");
        } catch (NoSuchAlgorithmException e) {} // NOPMD
        try {
            AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_ED448).digest(someBytes);
            fail("should have thrown for Ed448");
        } catch (NoSuchAlgorithmException e) {} // NOPMD
        try {
            AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_FALCON512).digest(someBytes);
            fail("should have thrown for Falcon");
        } catch (NoSuchAlgorithmException e) {} // NOPMD
        try {
            AlgorithmTools.getDigestFromAlgoName(AlgorithmConstants.SIGALG_DILITHIUM2).digest(someBytes);
            fail("should have thrown for Dilithium");
        } catch (NoSuchAlgorithmException e) {} // NOPMD

    }

    @Test
    public void testGetKeyAlgorithmFromSigAlg() {

        // Test that key algorithm is RSA for all of its signature algorithms
        for (final String s : AlgorithmTools.getSignatureAlgorithms(new MockRSAPublicKey()) ) {
            assertEquals(AlgorithmTools.getKeyAlgorithm(new MockRSAPublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg(s));
        }

        // Test that key algorithm is DSA for all of its signature algorithms
        for (final String s : AlgorithmTools.getSignatureAlgorithms(new MockDSAPublicKey())) {
            assertEquals(AlgorithmTools.getKeyAlgorithm(new MockDSAPublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg(s));
        }

        // Test that key algorithm is ECDSA for all of its signature algorithms
        for (final String s : AlgorithmTools.getSignatureAlgorithms(new MockECDSAPublicKey())) {
            assertEquals(AlgorithmTools.getKeyAlgorithm(new MockECDSAPublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg(s));
        }
        // Test that key algorithm is Falcon for all of its signature algorithms
        for (final String s : AlgorithmTools.getSignatureAlgorithms(new MockFalcon512PublicKey())) {
            assertEquals(AlgorithmTools.getKeyAlgorithm(new MockFalcon512PublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg(s));
        }
        // Test that key algorithm is Falcon for all of its signature algorithms
        for (final String s : AlgorithmTools.getSignatureAlgorithms(new MockFalcon1024PublicKey())) {
            assertEquals(AlgorithmTools.getKeyAlgorithm(new MockFalcon1024PublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg(s));
        }
        // Test that key algorithm is Dilithium for all of its signature algorithms
        for (final String s : AlgorithmTools.getSignatureAlgorithms(new MockDilithium2PublicKey())) {
            assertEquals(AlgorithmTools.getKeyAlgorithm(new MockDilithium2PublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg(s));
        }
        for (final String s : AlgorithmTools.getSignatureAlgorithms(new MockDilithium3PublicKey())) {
            assertEquals(AlgorithmTools.getKeyAlgorithm(new MockDilithium3PublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg(s));
        }
        for (final String s : AlgorithmTools.getSignatureAlgorithms(new MockDilithium5PublicKey())) {
            assertEquals(AlgorithmTools.getKeyAlgorithm(new MockDilithium5PublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg(s));
        }

        // EdDSA have specific signature algorithms per key
        PublicKey pk = KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_ED25519_PRIV).getPublic();
        List<String> algos = AlgorithmTools.getSignatureAlgorithms(pk);
        assertEquals("There should be exactly one signature algo for Ed25519", 1, algos.size());
        assertEquals("Not Ed25519 algo returned", AlgorithmConstants.SIGALG_ED25519, algos.get(0));
        assertEquals("Should be Ed25519", AlgorithmConstants.KEYALGORITHM_ED25519, AlgorithmTools.getKeyAlgorithmFromSigAlg(algos.get(0)));
        assertEquals("Should be Ed25519", AlgorithmConstants.KEYALGORITHM_ED25519, AlgorithmTools.getKeyAlgorithm(pk));
        pk = KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_ED448_PRIV).getPublic();
        algos = AlgorithmTools.getSignatureAlgorithms(pk);
        assertEquals("There should be exactly one signatur ealgo for Ed448", 1, algos.size());
        assertEquals("Not Ed448 algo returned", AlgorithmConstants.SIGALG_ED448, algos.get(0));
        assertEquals("Should be Ed448", AlgorithmConstants.KEYALGORITHM_ED448, AlgorithmTools.getKeyAlgorithmFromSigAlg(algos.get(0)));
        assertEquals("Should be Ed448", AlgorithmConstants.KEYALGORITHM_ED448, AlgorithmTools.getKeyAlgorithm(pk));

        // should return a default value
        assertNotNull("should return a default value", AlgorithmTools.getKeyAlgorithmFromSigAlg("_NonExistingAlg"));

    }

    @Test
    public void testGetKeySpecification() throws Exception {
        assertNull("null if the key algorithm is not supported", AlgorithmTools.getKeySpecification(new MockNotSupportedPublicKey()));
        assertEquals("unknown", AlgorithmTools.getKeySpecification(new MockECDSAPublicKey()));
        assertEquals("10", AlgorithmTools.getKeySpecification(new MockRSAPublicKey()));
        KeyPair pair = KeyTools.genKeys("prime192v1", "ECDSA");
        final String ecNamedCurve = AlgorithmTools.getKeySpecification(pair.getPublic());
        assertTrue("Key was generated with the right curve.", AlgorithmTools.getEcKeySpecAliases(ecNamedCurve).contains("prime192v1"));
        assertTrue("Key was generated with the right curve.", AlgorithmTools.getEcKeySpecAliases(ecNamedCurve).contains("secp192r1"));
        // We can't really say if "secp192r1" or "prime192v1" should be the preferred name on this system, since it depends on available providers.
        //assertEquals("Unexpected preferred named curve alias.", "secp192r1", ecNamedCurve);
        pair = KeyTools.genKeys("1024", "DSA");
        assertEquals("1024", AlgorithmTools.getKeySpecification(pair.getPublic()));
        PublicKey pk = KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_ED25519_PRIV).getPublic();
        assertEquals("Ed25519", AlgorithmTools.getKeySpecification(pk));
        pk = KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_ED448_PRIV).getPublic();
        assertEquals("Ed448", AlgorithmTools.getKeySpecification(pk));
        pk = KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_FALCON512_PRIV).getPublic();
        assertEquals("FALCON-512", AlgorithmTools.getKeySpecification(pk));
        pk = KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_DILITHIUM2_PRIV).getPublic();
        assertEquals("DILITHIUM2", AlgorithmTools.getKeySpecification(pk));
    }

    @Test
    public void testGetKeySpecificationGOST3410() throws Exception {
        assumeTrue(AlgorithmConfigurationCache.INSTANCE.isGost3410Enabled());
        final String keyspec = "GostR3410-2001-CryptoPro-B";
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("ECGOST3410", "BC");
        AlgorithmParameterSpec ecSpec = ECGOST3410NamedCurveTable.getParameterSpec(keyspec);
        keygen.initialize(ecSpec);
        KeyPair keys = keygen.generateKeyPair();
        assertEquals(keyspec, AlgorithmTools.getKeySpecification(keys.getPublic()));
    }

    @Test
    public void testGetKeySpecificationDSTU4145() throws Exception {
        assumeTrue(AlgorithmConfigurationCache.INSTANCE.isDstu4145Enabled());
        final String keyspec = "2.5";
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSTU4145", "BC");
        AlgorithmParameterSpec ecSpec = KeyTools.dstuOidToAlgoParams(keyspec);
        keygen.initialize(ecSpec);
        KeyPair keys = keygen.generateKeyPair();
        assertEquals(keyspec, AlgorithmTools.getKeySpecification(keys.getPublic()));
    }
   

    @Test
    public void testGetEncSigAlgFromSigAlgRSA() throws InvalidAlgorithmParameterException {
        PublicKey publicKey = KeyTools.genKeys("1024", "RSA").getPublic();
        assertEquals(AlgorithmConstants.SIGALG_SHA512_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA384_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA1_WITH_DSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA256_WITH_DSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA384_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA384_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA512_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA512_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA384_WITH_RSA_AND_MGF1, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA384_WITH_RSA_AND_MGF1, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_ED25519, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_ED448, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_FALCON512, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_FALCON1024, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_DILITHIUM2, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_DILITHIUM3, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_DILITHIUM5, publicKey));
        assertEquals("Foobar", AlgorithmTools.getEncSigAlgFromSigAlg("Foobar", publicKey));
    }
    
    @Test
    public void testGetEncSigAlgFromSigAlgECDSA() throws InvalidAlgorithmParameterException {
        PublicKey publicKey = KeyTools.genKeys("secp256k1", "ECDSA").getPublic();
        assertEquals(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA1_WITH_DSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA256_WITH_DSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA384_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA512_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA384_WITH_RSA_AND_MGF1, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_ED25519, publicKey));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_ED448, publicKey));
        assertEquals("Foobar", AlgorithmTools.getEncSigAlgFromSigAlg("Foobar", publicKey));
    }
    
    @Test
    public void testGetEncSigAlgFromSigAlgFalcon() throws InvalidAlgorithmParameterException {
        PublicKey publicKey = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_FALCON512).getPublic();
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_FALCON512, publicKey));
        publicKey = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_FALCON1024).getPublic();
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_FALCON1024, publicKey));
    }  

    @Test
    public void testGetEncSigAlgFromSigAlgDilithium() throws InvalidAlgorithmParameterException {
        PublicKey publicKey = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_DILITHIUM2).getPublic();
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_DILITHIUM2, publicKey));
        publicKey = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_DILITHIUM3).getPublic();
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_DILITHIUM3, publicKey));
        publicKey = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_DILITHIUM5).getPublic();
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_DILITHIUM5, publicKey));
    }  

    @Test
    public void testGetAlgorithmNameFromDigestAndKey() {
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA1, AlgorithmConstants.KEYALGORITHM_RSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_DSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA1, AlgorithmConstants.KEYALGORITHM_DSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA256, AlgorithmConstants.KEYALGORITHM_RSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_DSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA256, AlgorithmConstants.KEYALGORITHM_DSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA384_WITH_RSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA384, AlgorithmConstants.KEYALGORITHM_RSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA512_WITH_RSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA512, AlgorithmConstants.KEYALGORITHM_RSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA1, AlgorithmConstants.KEYALGORITHM_EC));
        assertEquals(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA224, AlgorithmConstants.KEYALGORITHM_EC));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA256, AlgorithmConstants.KEYALGORITHM_EC));
        assertEquals(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA384, AlgorithmConstants.KEYALGORITHM_EC));
        assertEquals(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA512, AlgorithmConstants.KEYALGORITHM_EC));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(NISTObjectIdentifiers.id_sha3_256.getId(), AlgorithmConstants.KEYALGORITHM_RSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(NISTObjectIdentifiers.id_sha3_384.getId(), AlgorithmConstants.KEYALGORITHM_RSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(NISTObjectIdentifiers.id_sha3_512.getId(), AlgorithmConstants.KEYALGORITHM_RSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(NISTObjectIdentifiers.id_sha3_256.getId(), AlgorithmConstants.KEYALGORITHM_EC));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(NISTObjectIdentifiers.id_sha3_384.getId(), AlgorithmConstants.KEYALGORITHM_EC));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey(NISTObjectIdentifiers.id_sha3_512.getId(), AlgorithmConstants.KEYALGORITHM_EC));
        // Default is SHA1 with RSA
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getAlgorithmNameFromDigestAndKey("Foobar", "Foo"));
    }

    @Test
    public void testIsCompatibleSigAlg() {
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1));
        assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA_AND_MGF1));
        assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1));
        assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA));
        assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA));
        assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_DSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_DSA));

    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
        assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
        assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA));
        assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA));
        assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_DSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_DSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA));

    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_DSA));
        assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_DSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA));

        PublicKey pk = KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_ED25519_PRIV).getPublic();
        assertTrue(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_ED25519));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA));

        pk = KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_ED448_PRIV).getPublic();
        assertTrue(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_ED448));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA));

        pk = KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_FALCON512_PRIV).getPublic();
        assertTrue(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_FALCON512));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_DILITHIUM2));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_DILITHIUM3));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_DILITHIUM5));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA));

        pk = KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_DILITHIUM2_PRIV).getPublic();
        assertTrue(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_DILITHIUM2));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_FALCON512));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_FALCON1024));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA));
        
        pk = KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_DILITHIUM3_PRIV).getPublic();
        assertTrue(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_DILITHIUM3));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_FALCON1024));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(pk, AlgorithmConstants.SIGALG_SHA256_WITH_RSA));

    }

    @Test
    public void testIsCompatibleSigAlgGOST3410() {
        assumeTrue(AlgorithmConfigurationCache.INSTANCE.isGost3410Enabled());
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_DSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_DSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145));
    }

    @Test
    public void testIsCompatibleSigAlgDSTU4145() {
        assumeTrue(AlgorithmConfigurationCache.INSTANCE.isDstu4145Enabled());
        assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_DSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_DSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA));
    }

    @Test
    public void testCertSignatureAlgorithmAsString() throws Exception {
        // X.509
    	KeyPair keyPair = KeyTools.genKeys("2048", "RSA"); // 2048 needed for MGF1 with SHA512
    	Certificate sha1rsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA1WithRSA", true);
    	Certificate md5rsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "MD5WithRSA", true);
    	Certificate sha256rsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA256WithRSA", true);
    	Certificate sha384rsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA384WithRSA", true);
    	Certificate sha512rsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA512WithRSA", true);
    	Certificate sha1rsamgf = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA1WithRSAAndMGF1", true);
    	Certificate sha256rsamgf = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA256WithRSAAndMGF1", true);
        Certificate sha384rsamgf = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA384WithRSAAndMGF1", true);
        Certificate sha512rsamgf = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA512WithRSAAndMGF1", true);
        Certificate sha3_256_rsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA, true);
        Certificate sha3_384_rsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA, true);
        Certificate sha3_512_rsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA, true);
    	assertEquals("SHA1WITHRSA", CertTools.getCertSignatureAlgorithmNameAsString(sha1rsa));
    	assertEquals("MD5WITHRSA", CertTools.getCertSignatureAlgorithmNameAsString(md5rsa));
    	assertEquals("SHA256WITHRSA", CertTools.getCertSignatureAlgorithmNameAsString(sha256rsa));
    	assertEquals("SHA384WITHRSA", CertTools.getCertSignatureAlgorithmNameAsString(sha384rsa));
    	assertEquals("SHA512WITHRSA", CertTools.getCertSignatureAlgorithmNameAsString(sha512rsa));
    	assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1, CertTools.getCertSignatureAlgorithmNameAsString(sha1rsamgf));
    	assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, CertTools.getCertSignatureAlgorithmNameAsString(sha256rsamgf));
        assertEquals(AlgorithmConstants.SIGALG_SHA384_WITH_RSA_AND_MGF1, CertTools.getCertSignatureAlgorithmNameAsString(sha384rsamgf));
        assertEquals(AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1, CertTools.getCertSignatureAlgorithmNameAsString(sha512rsamgf));
        assertEquals("SHA3-256WITHRSA", CertTools.getCertSignatureAlgorithmNameAsString(sha3_256_rsa));
        assertEquals("SHA3-384WITHRSA", CertTools.getCertSignatureAlgorithmNameAsString(sha3_384_rsa));
        assertEquals("SHA3-512WITHRSA", CertTools.getCertSignatureAlgorithmNameAsString(sha3_512_rsa));

    	assertEquals("SHA1WithRSA", AlgorithmTools.getSignatureAlgorithm(sha1rsa));
    	assertEquals("MD5WithRSA", AlgorithmTools.getSignatureAlgorithm(md5rsa));
    	assertEquals("SHA256WithRSA", AlgorithmTools.getSignatureAlgorithm(sha256rsa));
    	assertEquals("SHA384WithRSA", AlgorithmTools.getSignatureAlgorithm(sha384rsa));
    	assertEquals("SHA512WithRSA", AlgorithmTools.getSignatureAlgorithm(sha512rsa));
    	assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1, AlgorithmTools.getSignatureAlgorithm(sha1rsamgf));
    	assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, AlgorithmTools.getSignatureAlgorithm(sha256rsamgf));
        assertEquals(AlgorithmConstants.SIGALG_SHA384_WITH_RSA_AND_MGF1, AlgorithmTools.getSignatureAlgorithm(sha384rsamgf));
        assertEquals(AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1, AlgorithmTools.getSignatureAlgorithm(sha512rsamgf));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA, AlgorithmTools.getSignatureAlgorithm(sha3_256_rsa));
        assertEquals(AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA, AlgorithmTools.getSignatureAlgorithm(sha3_512_rsa));

    	// DSA
    	keyPair = KeyTools.genKeys("1024", "DSA");
    	Certificate sha1rsadsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA1WithDSA", true);
    	assertEquals("SHA1withDSA", CertTools.getCertSignatureAlgorithmNameAsString(sha1rsadsa));
    	assertEquals("SHA1WithDSA", AlgorithmTools.getSignatureAlgorithm(sha1rsadsa));
        Certificate sha256rsadsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA256WithDSA", true);
        assertEquals("SHA256WITHDSA", CertTools.getCertSignatureAlgorithmNameAsString(sha256rsadsa));
        assertEquals("SHA256WithDSA", AlgorithmTools.getSignatureAlgorithm(sha256rsadsa));

        // ECC
    	keyPair = KeyTools.genKeys("prime192v1", "ECDSA");
    	Certificate sha1ecc = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA1WithECDSA", true);
    	Certificate sha224ecc = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA224WithECDSA", true);
    	Certificate sha256ecc = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA256WithECDSA", true);
    	Certificate sha384ecc = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA384WithECDSA", true);
        Certificate sha512ecc = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA512WithECDSA", true);
        Certificate sha3_256_ecc = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA, true);
        Certificate sha3_384_ecc = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA, true);
        Certificate sha3_512_ecc = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA, true);
    	assertEquals("ECDSA", CertTools.getCertSignatureAlgorithmNameAsString(sha1ecc));
    	assertEquals("SHA224WITHECDSA", CertTools.getCertSignatureAlgorithmNameAsString(sha224ecc));
    	assertEquals("SHA256WITHECDSA", CertTools.getCertSignatureAlgorithmNameAsString(sha256ecc));
    	assertEquals("SHA384WITHECDSA", CertTools.getCertSignatureAlgorithmNameAsString(sha384ecc));
        assertEquals("SHA512WITHECDSA", CertTools.getCertSignatureAlgorithmNameAsString(sha512ecc));
        assertEquals("SHA3-256WITHECDSA", CertTools.getCertSignatureAlgorithmNameAsString(sha3_256_ecc));
        assertEquals("SHA3-384WITHECDSA", CertTools.getCertSignatureAlgorithmNameAsString(sha3_384_ecc));
        assertEquals("SHA3-512WITHECDSA", CertTools.getCertSignatureAlgorithmNameAsString(sha3_512_ecc));

    	assertEquals("SHA1withECDSA", AlgorithmTools.getSignatureAlgorithm(sha1ecc));
    	assertEquals("SHA224withECDSA", AlgorithmTools.getSignatureAlgorithm(sha224ecc));
    	assertEquals("SHA256withECDSA", AlgorithmTools.getSignatureAlgorithm(sha256ecc));
    	assertEquals("SHA384withECDSA", AlgorithmTools.getSignatureAlgorithm(sha384ecc));
        assertEquals("SHA512withECDSA", AlgorithmTools.getSignatureAlgorithm(sha512ecc));
        assertEquals("SHA3-256withECDSA", AlgorithmTools.getSignatureAlgorithm(sha3_256_ecc));
        assertEquals("SHA3-384withECDSA", AlgorithmTools.getSignatureAlgorithm(sha3_384_ecc));
        assertEquals("SHA3-512withECDSA", AlgorithmTools.getSignatureAlgorithm(sha3_512_ecc));

        // EdDSA
        keyPair = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_ED25519);
        Certificate ed25519 = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_ED25519, true);
        assertEquals("Ed25519", CertTools.getCertSignatureAlgorithmNameAsString(ed25519));
        keyPair = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_ED448);
        Certificate ed448 = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_ED448, true);
        assertEquals("Ed448", CertTools.getCertSignatureAlgorithmNameAsString(ed448));

        // Falcon
        keyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_FALCON512);
        Certificate falcon = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_FALCON512, true);
        assertEquals("FALCON-512", CertTools.getCertSignatureAlgorithmNameAsString(falcon));
        keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_FALCON1024);
        falcon = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_FALCON1024, true);
        assertEquals("FALCON-1024", CertTools.getCertSignatureAlgorithmNameAsString(falcon));
        
        // Dilithium
        keyPair = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_DILITHIUM2);
        Certificate dilithium = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_DILITHIUM2, true);
        assertEquals("DILITHIUM2", CertTools.getCertSignatureAlgorithmNameAsString(dilithium));
        keyPair = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_DILITHIUM3);
        dilithium = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_DILITHIUM3, true);
        assertEquals("DILITHIUM3", CertTools.getCertSignatureAlgorithmNameAsString(dilithium));
        keyPair = KeyTools.genKeys(null, AlgorithmConstants.KEYALGORITHM_DILITHIUM5);
        dilithium = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_DILITHIUM5, true);
        assertEquals("DILITHIUM5", CertTools.getCertSignatureAlgorithmNameAsString(dilithium));
    }

    @Test
    public void testCertSignatureAlgorithmAsStringGOST3410() throws Exception {
        assumeTrue(AlgorithmConfigurationCache.INSTANCE.isGost3410Enabled());
        KeyPair keyPair = KeyTools.genKeys("GostR3410-2001-CryptoPro-B", AlgorithmConstants.KEYALGORITHM_ECGOST3410);
        Certificate gost3411withgost3410 = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410, true);
        assertEquals("GOST3411WITHECGOST3410", CertTools.getCertSignatureAlgorithmNameAsString(gost3411withgost3410));
        assertEquals("GOST3411withECGOST3410", AlgorithmTools.getSignatureAlgorithm(gost3411withgost3410));
    }

    @Test
    public void testCertSignatureAlgorithmAsStringDSTU4145() throws Exception {
        assumeTrue(AlgorithmConfigurationCache.INSTANCE.isDstu4145Enabled());
        KeyPair keyPair = KeyTools.genKeys("2.5", AlgorithmConstants.KEYALGORITHM_DSTU4145);
        Certificate gost3411withgost3410 = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145, true);
        assertEquals("GOST3411WITHDSTU4145", CertTools.getCertSignatureAlgorithmNameAsString(gost3411withgost3410));
        assertEquals("GOST3411withDSTU4145", AlgorithmTools.getSignatureAlgorithm(gost3411withgost3410));
    }

    @Test
    public void testGetWellKnownCurveOids() {
        // Extracted from debugger
        final String[] wellKnownCurveNames = new String[] { "secp224r1", "brainpoolp224t1", "c2pnb368w1", "sect409k1", "brainpoolp224r1",
                "c2tnb359v1", "sect233r1", "sect571k1", "c2pnb304w1", "brainpoolp512r1", "brainpoolp320r1", "brainpoolp512t1", "brainpoolp320t1",
                "secp256k1", "c2tnb239v3", "c2tnb239v2", "c2tnb239v1", "prime239v3", "prime239v2", "sect283k1", "sect409r1", "prime239v1",
                "prime256v1", "brainpoolp256t1", "sect283r1", "FRP256v1", "brainpoolp256r1", "secp384r1", "secp521r1", "brainpoolp384t1", "secp224k1",
                "c2tnb431r1", "brainpoolp384r1", "sect239k1", "c2pnb272w1", "sm2p256v1", "sect233k1", "sect571r1"
        };
        for (final String wellKnownCurveName : wellKnownCurveNames) {
            assertNotEquals("Could not retrieve OID for curve " + wellKnownCurveName, AlgorithmTools.getEcKeySpecOidFromBcName(wellKnownCurveName),
                    wellKnownCurveName);
            log.info("Successfully retrieved EC curve OID: " + AlgorithmTools.getEcKeySpecOidFromBcName(wellKnownCurveName));
        }
    }

    /** A simple test that just checks that we have items in EcCurvesMap, and can be used to 
     * (debug) print out for manual inspection.
     */
    @Test
    public void testGetNamedEcCurves() {
        final Map<String,List<String>> list = AlgorithmTools.getNamedEcCurvesMap(false);
        assertNotNull("getNamedEcCurvesMap can not be null", list);
        assertFalse("getNamedEcCurvesMap can not be empty", list.isEmpty());
        final Set<String> keySet = list.keySet();
        assertNotNull("getNamedEcCurvesMap keySet can not be null", keySet);
        assertFalse("getNamedEcCurvesMap keySet can not be empty", keySet.isEmpty());
        for (String name : keySet) {
            log.debug("testGetNamedEcCurves: " + name);
        }
    }
    
    private static class MockPublicKey implements PublicKey {
        private static final long serialVersionUID = 1L;
        @Override
        public String getAlgorithm() { return null; }
        @Override
        public byte[] getEncoded() { return null; }
        @Override
        public String getFormat() { return null; }
    }

    private static class MockNotSupportedPublicKey extends MockPublicKey {
        private static final long serialVersionUID = 1L;
    }

    private static class MockRSAPublicKey extends MockPublicKey implements RSAPublicKey {
        private static final long serialVersionUID = 1L;
        @Override
        public BigInteger getPublicExponent() { return BigInteger.valueOf(1); }
        @Override
        public BigInteger getModulus() { return BigInteger.valueOf(1000); }
    }

    private static class MockDSAPublicKey extends MockPublicKey implements DSAPublicKey {
        private static final long serialVersionUID = 1L;
        @Override
        public BigInteger getY() { return BigInteger.valueOf(1); }
        @Override
        public DSAParams getParams() { return null; }
    }

    private static class MockECDSAPublicKey extends MockPublicKey implements ECPublicKey {
        private static final long serialVersionUID = 1L;
        @Override
        public ECPoint getW() { return null; }
        @Override
        public ECParameterSpec getParams() { return null; }
        @Override
        public String getAlgorithm() {
            return "ECDSA mock";
        }
    }

    private static class MockGOST3410PublicKey extends MockPublicKey implements ECPublicKey {
        private static final long serialVersionUID = 1L;
        @Override
        public ECPoint getW() { return null; }
        @Override
        public ECParameterSpec getParams() { return null; }
        @Override
        public String getAlgorithm() {
            return "GOST mock";
        }
    }

    private static class MockDSTU4145PublicKey extends MockPublicKey implements ECPublicKey {
        private static final long serialVersionUID = 1L;
        @Override
        public ECPoint getW() { return null; }
        @Override
        public ECParameterSpec getParams() { return null; }
        @Override
        public String getAlgorithm() {
            return "DSTU mock";
        }
    }

    private static class MockFalcon512PublicKey extends MockPublicKey implements FalconKey {
        private static final long serialVersionUID = 1L;
        @Override
        public FalconParameterSpec getParameterSpec() {return FalconParameterSpec.falcon_512; }
        @Override
        public String getAlgorithm() {
            return "FALCON-512";
        }
    }

    private static class MockFalcon1024PublicKey extends MockPublicKey implements FalconKey {
        private static final long serialVersionUID = 1L;
        @Override
        public FalconParameterSpec getParameterSpec() {return FalconParameterSpec.falcon_1024; }
        @Override
        public String getAlgorithm() {
            return "FALCON-1024";
        }
    }

    private static class MockDilithium2PublicKey extends MockPublicKey implements DilithiumKey {
        private static final long serialVersionUID = 1L;
        @Override
        public DilithiumParameterSpec getParameterSpec() {return DilithiumParameterSpec.dilithium2; }
        @Override
        public String getAlgorithm() {
            return "DILITHIUM2";
        }
    }

    private static class MockDilithium3PublicKey extends MockPublicKey implements DilithiumKey {
        private static final long serialVersionUID = 1L;
        @Override
        public DilithiumParameterSpec getParameterSpec() {return DilithiumParameterSpec.dilithium3; }
        @Override
        public String getAlgorithm() {
            return "DILITHIUM3";
        }
    }

    private static class MockDilithium5PublicKey extends MockPublicKey implements DilithiumKey {
        private static final long serialVersionUID = 1L;
        @Override
        public DilithiumParameterSpec getParameterSpec() {return DilithiumParameterSpec.dilithium5; }
        @Override
        public String getAlgorithm() {
            return "DILITHIUM5";
        }
    }

}
