/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Locale;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.util.KeyTools;

/**
 * Constants for CAs.
 */
public final class CAConstants {
    public static final Logger log = Logger.getLogger(CAConstants.class);

    /**
     * The state of a node-local CA with a keypair which is neither expired nor revoked.
     * An active CA should be able to create signatures unless the crypto token associated
     * with the CA is offline, in which case healthcheck will fail. A CA stays in this
     * state until the certificate expires or is revoked.
     */
    public static final int CA_ACTIVE = 1;
    /**
     * The state of an external CA where a CSR has been created but the signed
     * certificate has not yet been imported into EJBCA.
     */
    public static final int CA_WAITING_CERTIFICATE_RESPONSE = 2;
    /**
     * The state of a node-local or external CA whose certificate has expired. Once
     * a CA's certificate has expired, it will stay in this state indefinitely.
     */
    public static final int CA_EXPIRED = 3;
    /**
     * The state of a node-local CA with a certificate which has been revoked.
     */
    public static final int CA_REVOKED = 4;
    /**
     * The state of a node-local CA which has been purposely put offline by the user, i.e
     * a CA whose "CA Service State" is "Offline". Healthcheck will be disabled for CAs
     * in this state.
     */
    public static final int CA_OFFLINE = 5;
    /**
     * An external CA without a private key. A CA stays in this state until
     * the certificate expires.
     */
    public static final int CA_EXTERNAL = 6;
    /**
     * The initial state of a CA imported using Statedump. In this state, the CA does not have a keypair. The CA can advance to the
     * CA_WAITING_CERTIFICATE_RESPONSE state if a CSR is created for the CA, or it can advance to the CA_ACTIVE state directly, if
     * a keypair is associated with it.
     */
    public static final int CA_UNINITIALIZED = 7;

    private static final String[] statustexts = {"", "ACTIVE", "WAITINGFORCERTRESPONSE", "EXPIRED", "REVOKED", "OFFLINE","EXTERNALCA", "UNINITIALIZED"};

    /**
     * Prevents creation of new CAConstants
     */
    private CAConstants() {
    }

    /**
     * Constants used in the SignSessionBean indicating the userdata defined CA should be used.
     */
    public static final int CAID_USEUSERDEFINED = 0;

    /** Used in profiles and service workers to make the catch all every CA instead of listing individual CAs when operating on them
     * This is duplicated in SecConst */
    public static final int ALLCAS = 1;

    public static String getStatusText(int status) {
        return statustexts[status];
    }

    /** Returns the integer constant for a given status string (case insensitive), or -1 if the string is incorrect. */
    public static int getStatusFromText(final String statusText) {
        if (StringUtils.isEmpty(statusText)) {
            return -1;
        }
        return ArrayUtils.indexOf(statustexts, StringUtils.upperCase(statusText, Locale.ROOT));
    }

    // A hard coded key to sign certificate for presign validation.
    // presign validation is signing a certificate with dummy keys, not the CAs real keys, so that the certificate contents can be verified
    // before the actual certificate is issued with the CAs real signing key
    // get the public key by 'openssl rsa -in privkey.pem -out pubkey.pem -pubout'
    public static final String PRESIGN_VALIDATION_KEY_RSA_PRIV =
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

    public static final String PRESIGN_VALIDATION_KEY_EC_SECP256R1_PRIV =
            "-----BEGIN EC PRIVATE KEY-----\n" +
                    "MHcCAQEEIEGrpEiJQlvnnPWqPVOT7LVD+h2RNw1orVXdu/HumkWqoAoGCCqGSM49\n" +
                    "AwEHoUQDQgAEjFHZzIXCz4W+BGV3V3lAoXMqISc4I39tgH5ErOWKMdU6pzpKWlXi\n" +
                    "gx9+SNtdz0OucKFLuGs9J0xHLJhTcLkuyQ==\n" +
                    "-----END EC PRIVATE KEY-----\n";

    public static final String PRESIGN_VALIDATION_KEY_EC_SECP384R1_PRIV =
            "-----BEGIN EC PRIVATE KEY-----\n" +
                    "MIGkAgEBBDCoT+vJRt9bVUD2zk5r2s6MAfoQOZW1mPAGazJIyTxjF+QpFJuSsTt9\n" +
                    "MHK5e3JKswOgBwYFK4EEACKhZANiAASXpPMP3vBs9isr8ssU91Ex93XIiwyMQ77l\n" +
                    "r5FLJamnT5+eL7RwEPiK/rfFrJJS7glgbBAmzDlkxlw67EAd2gz3tyW9UoxF8jpe\n" +
                    "ojP8Ay3AJ3Ms1cAT+uYp+ySa1LPNsOk=\n" +
                    "-----END EC PRIVATE KEY-----";

    public static final String PRESIGN_VALIDATION_KEY_DSA_PRIV =
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

    public static final String PRESIGN_VALIDATION_KEY_ED25519_PRIV =
            "-----BEGIN PRIVATE KEY-----\n" +
                    "MC4CAQAwBQYDK2VwBCIEIErU1sdUkfufFIiIjeyB6XCqEKR4dFtTYejBjH/jeM4O\n" +
                    "-----END PRIVATE KEY-----\n";

    public static final String PRESIGN_VALIDATION_KEY_ED448_PRIV =
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

    public static final String PRESIGN_VALIDATION_KEY_FALCON1024_PRIV =
            "-----BEGIN PRIVATE KEY-----\n" + 
                    "MIIQKwIBADAHBgUrzg8DBASCEBswghAXAgEABIICgP+GLoPDAMPfi4DRO+4MH++G\n" + 
                    "DwO8+DmwcD/gw8CDfABF0vQ8H8YPi+P+wACQfei/4OhCCQXwcGT4iD94PzA2H5g+\n" + 
                    "N//xj+AowcB0AAeCAHv6AEJB+CEXvgCMZhjOMHhIEMgQCAIIf7ALPubF7/vbFsYe\n" + 
                    "/J3YvjEIIA8ELwwBCD4iDCMA8d78Qhd+TnR8IIH/FEIPiAAAHQhHzvSBL8HSAB0H\n" + 
                    "AjEUgQe58IRA+AANZ8QXO/AEQN9ALgQgEEAwC+EAfELwnuf94YA6AEguC8AAi+B4\n" + 
                    "X8h73/A+8LXgjIH5Na57Ze//zwOcB3vwkyT3/jEHoR55/oDeOIQggF/oih0AYvdC\n" + 
                    "AAvm6Hv+oHn/ff30P+gLvwgA53vxC4IIBfB4gQ+EMYOcJ7vOg9znCe/8IPi9z/AA\n" + 
                    "D0hQY/v3wC/3nSB784P/8EQBEIX3uD9z/vlD/xBYB0Qv8D8oiBIEwf/HwPx+EEQg\n" + 
                    "gCD5PgJ8ovh4IBA/CLxPeGQHdjKboB82DoelHvnv7GIABB0AIQ9/8I+96L4S+AAA\n" + 
                    "vh+P4RZ533w9D7ew+IAP/gCTnwB78YQAAHg+dHwG97AMPBD/8QvCF8W/cKIH/ADk\n" + 
                    "YjbD7xAgV8YehH0QwhCYgh88HvBgAEQw9QMXQ9AbxAB38Q+AKMABCCHnDg57oACJ\n" + 
                    "4PRCITYAfAEPPByUgNFCEHffGAPPD90IRfJsASBH7/QdBroOE6AZQkCEIACCEIef\n" + 
                    "7/QBd70Q/D+AgRb6EAf56Dw/hD7vghEMhABHwPy9D34ODB7whAL7/Q/74g+eAIPA\n" + 
                    "iGEIyi+QX9BFzovC/v4x/H7vxC+DngA+AXxD/wgh/EL5AlF4n+gH8vvD+TXQ/PwE\n" + 
                    "ggKA8D5ag/8Hej6HnwhB8Iji8DXAb9kvggD73f9EQYOAFweweB4JfdF8oSEHr4Ag\n" + 
                    "6Hxv/EARQeLwItf6MIRD/8Ivc7nvii/r4AgCToQj8MQtB8Lohd4IIPEBzvgC8D3h\n" + 
                    "kCEfCfAAIyf97wgh9/XwfEQP/cF4gxe6Xw/iEEXwBH8X/rB/oAbD8v+EFwGTfFoH\n" + 
                    "hBF34Qh8An/jD7wCkCIAO/H3/R8D34vAF8nOC3//Rg2MPgB+AZvi8LvedH8Ag//3\n" + 
                    "ffB7kQReAIRgC+X4Ni6PQgk+MvA99z4fgH3wPAAQIBdJ4IAEAH5Bc+H/O7AMOwA+\n" + 
                    "Afgh/0Q+d1wQdl3oXe+D7IgAB4Ag/FsH+/KT4OY94IP6ETojl6QQdA+YAP/2Efel\n" + 
                    "F0fhh+MBehMEZP9//Qe/CIXOh+IIBdEAWwi4D/fe/wJviAD4teFzfSiBvvwBFvhA\n" + 
                    "gAMXg8J8wQg6UAfjCEZO9AT39j4IH//8EAQ6F8HgA+H/hcEMYfB4D3hA4Powg4Eo\n" + 
                    "f+78QdhCLoxh53QO498YRgEMvvfAH4B9/0gv7//whDH3vSB94ABdCb/gE78XyACH\n" + 
                    "g+AFvxjBEEoP+AIHffF/YfgCPwBh+HXhA+H/Ng8D/hFr8PfhJ86A+8EnBAKDmwZF\n" + 
                    "34/B0Leh8H0RBC6AP/gCLvQ+B8Qvg+EAAc9oB//F4HteD3PxfBsQgDCQAgDAMXuh\n" + 
                    "DoHQfCX4/bIX/x+/0ZBDH4PefB0gRA+cP/CAH/xA+DgPjGQXvAIH3ycD/4OdETnO\n" + 
                    "A2P3xd6EX+gADgP/AEYOlCLwNCGT3fiF0PgBIMYQhID4xfGIHQf/4IxZ4TpQ+AAQ\n" + 
                    "gg/8Zf+CAX/+/8QfeMLoBDEAYwSCBAAqJvMhH+sKOxoPGejf9ib0Fu8M9xL2F/Ho\n" + 
                    "GtT1IQn85ift2su9AvrduiH6D/0AC+DoLtkk/evgHfoL9/zuKfYVHvnmLAgT+SwM\n" + 
                    "GkPbDtjd7Rj4GwQFCRQfGPQOHQ8S3gbnFiUSBxQeCwf+IiVI3+YM8uYdHBAE+w0d\n" + 
                    "5xL4/wcE6OgCIPQICPsZ7PkSHP38zfwZJOExF/QM3efxEuUPKAvjH1kVJhn/Ke37\n" + 
                    "8hf2KtDv6trgCOfgCfLdF9sSPhQC5vQT+eUXCfjMI/nhFv4nK/rUxjP9QN3i/yfH\n" + 
                    "9Q4m7fgU8QDL5PD78yf30QAT7xAG6PvvBOIM7ugezvzj9+s37PvG4jQ77x7wFwn9\n" + 
                    "+hP0B/7zMvj7BfIWwSPY8TDsNezo7A4SyvsECqvo9wb36/QP/eXyL9zuAd/oCM7w\n" + 
                    "HQfc+xkGzvAAC+7Q2hAW8fkkAvju8tAC8iDp+DLe5PAEF8zp++v5LQIeHvD1Hgvy\n" + 
                    "5Aze+Rn46wkuKhb99+n4FgDwAC0N6xbn2SAT4C3z998LFf369fYZRiAKKS8Q22Mh\n" + 
                    "FyUtMBc34PYNFy4O+xL5HxfkC/UJ6hj+CRck3bwXEPQOLAfa6NIEGe0+TjboHw4N\n" + 
                    "FQEd+ygD/B8rISQgAxPv2P8E1xEKD6//FAsD9f/09Ob98wz0Dd8N9QPXMt33wOYP\n" + 
                    "KOLuMBD4yg0K6Bz9BtcAHQT5BvcJ/g7i+g4X7A0K+93oCAPIEe4vEsDzOQv+BP75\n" + 
                    "Qf4R+Q0I6+TlGdr9QfH1PegV9e8S4xLm/jkPEN/YFOP7+sIBFt8ZGRXzLxLpKxLy\n" + 
                    "MiL2ABwVGQXlEtYOAhoQAv8H0AHl/t4Mxifr/tgM6fru2Kgg+Pj+IhIi+APV9NTr\n" + 
                    "5fP68QUazwgM+gvk9OQkFxDlAf7PFQsN/vQf4MQTIAYCA9UqBwDJ+8X4+gbdFfMM\n" + 
                    "+hYG3AvnJM/pGecN5xAH+wnBFwIO1PwUFN4KHkAVKSNCB/cXFjH4H/YQFfX78wD/\n" + 
                    "A+bz6f3iMhAF4h7v3wr9AwTcF/AU6hT/AggKEvAYDuj85B/V3zTv5On7B+y/FDkJ\n" + 
                    "Dyzy+irp5xAB2MHyydnzDuzx+hclHefyJRcc4RcM9DMr8dj79d0d3e4UJu/o9iTn\n" + 
                    "zuL9APrI9wMX3vL//PQPHQz+2v8CGfEi6gnrBhccFgvz7BQZ7QHsIRAO2/fM5Abu\n" + 
                    "FPInBAbm5gcQ+PEHCNwC8RwJ3+42HSAPEQ0LFCEWHf0PLx3u/RHhCBLpAsDbCcP5\n" + 
                    "7fHQ8Ars7M35OevfD8/t7RYkAwHQ8+n0Jx8VJyn12ekG7gru6xMiFPn+BQMR9Av5\n" + 
                    "Ag/0//8fD+je0yja4/TUBB02Fdnz9h8rOhgXEisX+hLySQMq7voDMIIHBASCBwBy\n" + 
                    "3mJK6SndGyIFqpgO4kv9OVf8rft/CaIW8JWZQEAtwA7GJIg8AjOhU+MF/cfWcOrx\n" + 
                    "VEBDxJSDpBRd/fBiXGNxHitn75nYFvXMEf7oDmHNspohlutOOftn94NjI8aFgaJk\n" + 
                    "B4xKmwORU+tWLVDF/U1NSR17E2iidzKSfQUhr5OfLB753Ve0hvnflRWam0QtFfM4\n" + 
                    "53WREJtDWhpSB4KWVoZs85CakALtL3anteaFHi9QX40TNahWilZkBZn5HHZM9Vla\n" + 
                    "xoGsNmZIMM+tMDvYnBDlose/7UM3TUOSNAXSpabcFhBuAxR24BQvwFAUfSW9T8bW\n" + 
                    "WgTdjm+S4TlUC0tgZU+DvCizIGz+VRuMXYjyyIJJ3wiDaqDYbN1Dig43VlYsNw9e\n" + 
                    "KTSNLKZ9hTFpBgexlhYT9UBQMZScHADjIdJ/hpuoP0MEhgCbtEDBJYHxy/m/7p8T\n" + 
                    "SgeGQ45vFs3/OrUJth6tU7h+Wmc0aix7rCj7HAiqVONAlEDKWxj6Y88khpFhztp8\n" + 
                    "qaKgRpSEua8oviUpy1+6grk7L9RmJ/ALyIdnQTwV8Of5LLwNuS3jNciDZILB4TqQ\n" + 
                    "6m0mpSj+C/wx9Spi5dnCfy7ZkF6g/x+6QABVhM20GBWYAd7Vcx35VTCN7YhwaIqT\n" + 
                    "yEWRoB9KoUpUWUHzKYxZqVLCATIvjL9PYLFHalIhOK23wF3SaQbS+7RRBNkOXaT6\n" + 
                    "fOeMWxLH+PohF1dqw2htFuZeAdxx5yN8IPIR0dtWmoVUODF07lcJxNwofUH2fchN\n" + 
                    "GqGE5ImkNET9ZOeAPTJ2pGNMIzALyazo6g6VUOafjLAgXjmgSC8IZSaP0ZZhO5Se\n" + 
                    "IuH6lMpAhnlkC6Y1LY2WeKNJ0b2mftCVCWGNVuBhgFIKmMxQ2cBKRhYhMMgNx7ak\n" + 
                    "/h9CJpHzjPiqZJCEHa0obkHtzgBAcqe6jJelpXqjS+Joi7zNKZfnKImdnRZRLoZt\n" + 
                    "g0j8KzJEvhjFaaiZ0qWkwZ+KLgMBg2rwWGos0WnQgJqkYZRPBQhlj4vhVc6j0oUp\n" + 
                    "tB8RSFW1SqI7VUQx5yrjT7Aml8nXJwWCSAV5bEG8GshimCrMacj4AJ3TiA+xv5XD\n" + 
                    "xlJLHsmmR5oRGu7uhD9L6zkgpOKWDuCBEslaxEhjivnc6o1ROmwKmQvOowgKDAa3\n" + 
                    "kVhVWRpicxELUGvYgXK55JwnFQD3GR/AnCFROg2qYWXJiWJoBVaZpH3haa9vYLKw\n" + 
                    "ulnGGIExmSDzL88+KIkyWpZmHowlRMim45K8zXEUj0FgxMcyhxM1E0qN2shqNh0A\n" + 
                    "Wabl2/qMSF2CMNlpY3TRuM5t3ppVyzObl7FvCH8YzI+5RBW7ysaeBbJk2xh2HGAs\n" + 
                    "Rcsp4qqlO4KlNUfUfLJuXxQpppa5pb5oNiTISoAJ1AeijEpJbWTCVCdFokyLp+oR\n" + 
                    "K+EQeLsRt5EuiqTUxxK0Hqu6NqDtBt4blmKvAoMmBVJBKWACIfXFlcgEdfmPFkek\n" + 
                    "B6FccpnqXKaHEFPmB9l3PsRE6YtNSHFJotel4hKEsH1iKGyaviam1gfpWktKmBJw\n" + 
                    "zdk6hsqSMBP1NjLoM0FYMhL92cYjm/UB3s5kFwbwa7gAgzcCZF+MuRNMBdtX3jtF\n" + 
                    "HymtEzad5gth2G00weeLJ6SJ5kgB+R0KtUHLMQnlvIflKdHkYE5YsjrqzAHMhF0Y\n" + 
                    "oRSmyxT26In9L+8V2Sl5q6Fbt5wHMzHUs4bqr4r66qAU0VOy2ooTNHlWpsdFci8M\n" + 
                    "6+I6puuGst/1UNLuYh20hFlQZQ4kfkBBjT9szVQJzla6IFyEW3dje4KemSdQ5veY\n" + 
                    "wvwoWp6tDMoAU+6SzUve8rh1zaBMFh7adVuKYbYqOXXmUWVlEKV4ii+k7bRUcYt/\n" + 
                    "pQQK0UEEvZPgFeo5Zny3lX/HcitLKyYF4HYuvph1iJBrWHKAGpg1P04vH1nYOn9C\n" + 
                    "Y1/ASShdWK6mXgE1XCJosMgj4b2V0j70ZdgZoYk7xLJKp1MnToSgJtLKxUu8WvDn\n" + 
                    "XeYrJr5bpoIHjdUceIVUyUfVA6ETx6ENtpGKcm1hARLR0iMX8ocYNrBn3euBue3g\n" + 
                    "i+3xh/mE12YUcIxmrbbqZMeemQM2+kMDapn9IoLrTnH+4ORA3GSl4rbBEZWrMcjg\n" + 
                    "2JYbnkXMD8efibem7dclOuFxSjjp94Jjfp/Zq+h2D620PSwZhIEEJwb7+j4jlY6G\n" + 
                    "AFrSxCEbwSFE2arHa/IPU5sqBYOlYKq80bRMNiimf1ngcvB2Co1M65S8LCqKg/Ip\n" + 
                    "HqyYaJF5MRbaRzQG9rd019iqHbs+GT+EfY7TDhwJFiUDHwHBsCaDww9BvM6wEZID\n" + 
                    "Ulj0AtKLk1XVhkF2o4y1DJtXxdwLquoiVJdSJhzmuwMxgKcXmbrXRYzEeYrn8yko\n" + 
                    "k4lte4UGSj8/KayHtE9S\n" + 
                    "-----END PRIVATE KEY-----\n";

    public static final String PRESIGN_VALIDATION_KEY_DILITHIUM2_PRIV =
            "-----BEGIN PRIVATE KEY-----\n" + 
                    "MIIPRAIBATANBgsrBgEEAQKCCwcEBASCCf8wggn7AgEAAyEAKO4qMC2wscUBwicR\n" + 
                    "UYh3Ij3nj5w17jRNcW0u3w9XOigDIQAChd/q3PVj/BKZEd34rHRUYUrVU6aCmMvB\n" + 
                    "/ZlmohP5vAMhAAKl1IlrjcKNKvSdlP15bSa4wG9vL1ThBshYD+fIpz4+A4IBgQDR\n" + 
                    "BojKQAnTBCoJMY4YM2rkKCxjuC2hNkEgRmLBoFAARmoMyAEABi1BAhEgR2wjyChJ\n" + 
                    "NEjIyFAQRASKMICZNkYIBkaRSAbCIIwKICEBxAQKpmGcgoVaQm1KyEnLBgyJBHIi\n" + 
                    "hDAbxSnIRkoYyS0BOGASiAUACU0MIGlTMgnUBmWKIiDbKCZAyJGggkRRFAIIB2Ig\n" + 
                    "hUBhNCwUxTDLFGWaxkgLBXBDpIgZAlEgCQREsE3htkjABACKCIWAIoUSAIkJJ00B\n" + 
                    "mEkgFEKIMmacGEBMklHEODBEQi4LpQUhJQQZCW1UIG0IFChLxJFJklGbQEAUGUVZ\n" + 
                    "oG0RyICYtiiTIIUksTGhhCkSEXLTBCEhCSCZggCZJjEKQgiQuHCZQiwcsIkRJyhB\n" + 
                    "OIyTJBBEtG0hiA2DQiYjRmbjiIwKpEEBA0DMpG0KuElYQoFJNirUAgKTCIrBpDBg\n" + 
                    "iHAkOCFRMBCSRmwkGGUKB0TgFkXBQG4kJiaRKI0QJ2lJpIkUwoFJgkgjNwIiOY4D\n" + 
                    "ggGBAJQ2ZGCiRQuxAUu4aGQ4LUEkgZxGZOGiKKBEBBqwCQISakimgdqkEaSkcEqG\n" + 
                    "JIOYjSNJChyAZCITaQO1LOKSLBsJSJokYGQYjcsgRAyFjYISACGxcYE2jGEIAAMX\n" + 
                    "KQqgABKkTQwjUowYJIQmgYQQKgCDZZlGEeJEUEDEcZw2DcQCAlu2IUG0TSQDjQHB\n" + 
                    "DeQ2gBOpRcooJtlIjFwCDZG2JIoSjCIRYUPIYEy4kcNESgkhjRFGgYIiCiERiAlJ\n" + 
                    "EhSZkVPAIeK2TNA2REuwjVPIKJqUCAk5jVOAYVNGiRwTYdwGKMQSYgElTUA4EuCY\n" + 
                    "jCADESMSaIjADIA0RAi0CQCUgJoYUAwzAQrCYQAXBhgRMOQyKVugYAQWaWSSUJAY\n" + 
                    "AuEGcFIgikRAcOCkQCM3hsPEjdOSZQmCYRMXCVHASQiFEdmokMHASEsmhptCQZlA\n" + 
                    "LkE0CaCoIds0Tgu4DcBGDRoJYRTGiAE4CRwihAAQKgykgYo4CNLCbBSjMVQmMRij\n" + 
                    "YEEyCAOCBoEABEn1ngXo4b4q/fpxjknO0V8A1FUSguIGj1TDk8Zzx9B+c1DgJUF0\n" + 
                    "U7NVjUa4ZayWXNsV43azoDBLEQKYqXQm4r2Ib97ZHCuvM3Btr1O24RJz6bs3wgwH\n" + 
                    "OskKTjACPeLf+IBNAcBZgVKSYwIwFjPbtYfagJRft+5GUVV9go3J8Xvs0o4IOJXQ\n" + 
                    "V8QIqhcQN2x0OcofEyxWM++duZay2M0e4Fp8+mSgpX/Bw/dP0nBWx3L+ibgrEUNB\n" + 
                    "Jld/X2bHjdULw4LkskKdTE4i4ZvdWDYBRY5YF0NoQKrjps9OHnVyjPtQ71Jn+DJD\n" + 
                    "aNNBcLfH5ijQGL3jNHq5AOyY2F8HBg8Dl+3id2wjRbBRM/A+f1QVXSjVGTunSL/b\n" + 
                    "q1cn8AYLYvUWEFCg5Ksg2oqcn7Cbkx+VX5+XdL+AaoiYLsW9yzwJn1C4bOALem60\n" + 
                    "4AGjWASwAtbq/ZTfxpnceTWSHuPK8s3nh62Lra8VcRoPjCkvND2xs3PShuN97THf\n" + 
                    "3mLn+c9a5MIglgABPGAI+pNoiuaNmzJfQX2/7mq958msep1zkKKuoI1TOaWmYysf\n" + 
                    "LvVqLjNjYGnzvYe6aTJePXPbc59dhyqht2VW8B5JFLOuvpZTh4V6L5M2ilxxt34T\n" + 
                    "LBhPHxbCJ8W5k5ZkJtDEeTQk5KoN6pXt4hYKq3KeSKR5yVCq81Ke2VJCikzbuy+b\n" + 
                    "xoN+alh+egVqbaLOjj48cuM3Cc8UhMH4piJfekQDVgfm8CBL/MlQMZP7cyVqSmf9\n" + 
                    "hcIB/NoAHehH+eyi5IB2mNU+El+792j2z0AjwbbLedOCqgsifJGiw7riQVD6PMO7\n" + 
                    "Oeg99J/O3AeLKUFpypna/RV7ycQf/61gQ1bhEE+epQbGlZwfMAC9oyZ0zPqrs3ep\n" + 
                    "rCBxS/FZFc2h1SduyuW9c+WWKORVCFFayXTPt24obS/SBvOD0O1k1u4jwYZUnLsE\n" + 
                    "eAWxWcicseaZqHe28ZHRJeDjgYkB5B013wSSrhVW9zSkCSTgjxSwmIIzY2P/f5KY\n" + 
                    "7DBUb73KHO5jKBVTiBodrAe8KGVugFKWNPCwb+p4CZN74Jj3Rl2u++XWZjWkCAT4\n" + 
                    "eISqYUKhZGWS8BCcRhDrzQ87bSI0CLZJEKW7WoXkMCeqSmC8ObGH/YuHAakYtiCV\n" + 
                    "AxzIL5gqZypUjQbTZ7dEcTcu41WWJBm91I+nru0FRd2/UopWn41YleC51T6D39+E\n" + 
                    "jI1yIgEs8ATxaUYK7sbnskgL3D47mOmpHGb8TOIeuo15OWpRLHJDVqdILYJWFJ6t\n" + 
                    "jMo+5RR6PCBXeviewNtq01ci5+JzvJhhbtnZXyGT/nDbPMktGqjkBIzOsZ5wl8Gi\n" + 
                    "haAWb3zn11ej72EWOrqvzX0hACQzUJLAVlHHQnipwkKET4WzoZODv8Y+5CZCkzuP\n" + 
                    "WuMnxOpJFZOXDmpQhU3CpX2LyzeP9uXMV+2NRitTM9mr0+hh7ptewAtfsIYn7Zx3\n" + 
                    "XNDKG+cZGIWrY8iTGK3XqlA0G9Tf2X8BD30nL+PQX223+vG7WsL67q/YVg/wc3zq\n" + 
                    "235bo5YiQqLVYWpdV2w93Q2oA8UsoqHIwiFgLzhDAaXI++ZPQH6m5J478to/C8fb\n" + 
                    "1zt/Uvqyg9iHJP5P1AAGmxqhb5b//f+h2rbGrgGiwv9NhubxgWaYqNAiOWcZoH/e\n" + 
                    "TD2djrrN2gjnXA5IaIR5E+EQT+9qpt993Gx8SF6++DQb9uNMcNeDR498O51iwOPN\n" + 
                    "WZoWXqomuRpLOQfRThXyYEAL3EnpvDy66z5jsRPo8sFPPByWEumMvGOWhT6InD8w\n" + 
                    "RXhkJMJ4lyGowjJdlNEVp2oGqscJAc1xY9aZTvzyGlHYaLdit86jYsaLU2P2r0oR\n" + 
                    "7xu0RNXNnhH3wObyp7DTTp9dIAbPmNhAK2hG8LwjFNiwixUgIN0yN9wyh5hZw8xu\n" + 
                    "prIu392slM7hKmZePBWmpemDdNoksm20HJxcWlb/9w+QxuibJmXePcnmV/RfVR6k\n" + 
                    "mz2iw/G2QvBtVx580Z+CxxI1x22zsicfje2aLuin5y22qMCubZZ1nQrrkgR5K4E5\n" + 
                    "6/LKCsWVJC2uWH1lYCbXlHx0qlBCVpzIXKYtj/LYDv8080VHOV3AFVsyF7JFGUYS\n" + 
                    "MJhp5NRnwKK0Nwo+/I6f/KdeUPrlSNQJ/UzK2lKVtNifiMwEtZmCJVY60Lb6bvkL\n" + 
                    "1jl9yxXOxiAs/uv8pv6cWsurUtraCfUsflGjUPmt45X1c4GmXr9JSd6BggUrADCC\n" + 
                    "BSYEICjuKjAtsLHFAcInEVGIdyI954+cNe40TXFtLt8PVzooBIIFAF/SP78INcJd\n" + 
                    "zTgCeQtvrW1S6a4/yn5Ht2CDynSd7qhcRdnh5Xqk2RnYnoFzc/Y+xSuAosoMdMbx\n" + 
                    "b3OtzsdKhvCL0glAO4r4JZ7kniLsHUmUVsGHETP8q0ryU2eTSufIsWikukIFzPpy\n" + 
                    "POyJ3oqZ0ZAJX1TktVZ1Dw4A9ChAMAZvQeCIVsfMHXG7n/GgUrIcezZQKF4RraXE\n" + 
                    "ZeM9Zv6QjTprBvMWYoygYmMdbp2JsCWf/PFEMDW50zKgKlMNbfZDnqZ5zjpuooKS\n" + 
                    "gv4HF3R6T2c1hB7wNKMLEolad65J9qwS6eq0eCjC/OdO96FQ+xK/t8l0dWwAHi0d\n" + 
                    "FxuxGBjXzvO6Pkt231osGFQPFLooho4fcJd0HuwmUvA2CZZFEcUc+vZN0ggADFJ6\n" + 
                    "sbBmY2qkUAujt0CQtGGdlXcVNNNLS4b0KeB2W/TaxqGCZHIIDaipZTWzz+w+jKlT\n" + 
                    "L/xKIicgFZLW31h57dmgLDKS+gEfNTjntQaW15RW8C1pPz3QGUabsmdCoLvlckTc\n" + 
                    "ENTZ5Cn/1JSTRuWn5dNoV+zBZzSxtfseXoPF/JLfsobndR/Lg5D6Uwoz77GgNzXp\n" + 
                    "I9ciHxtGJCT6QS1AoEcvNQ4tCfM0pbhwypjJ559xOv79yf6pFd8xbvCiYgWFsSyv\n" + 
                    "xPVi/hOZLTn+nJbhDCPiB1TQVegXb9FMT/msvS4QhdJax6Js08jqrvRIoVr9M5eF\n" + 
                    "AYQmcRfdWL7RZPgIZSGam9VS/Lv7JIoIiXUEoVlITBYIKma3BXMnmmOsdrRtpxfr\n" + 
                    "oGchEU1GIQCReh4J+PNupC41MnvbJx9s8ssUv6vtSnWzJuFEGt8WEU2JjeqM0SoG\n" + 
                    "iT9dE5Y0UiFqN9yjeV55ZElwBPL2Oz/k0T74HkuZahF980Q08jTDTwFsue+KoZi5\n" + 
                    "T9qzf245jVQ6bUK4qmTb6qiXvMQZ0AVUK33GLzNs2xyUU9g4U21B6y9qJrGYuWnc\n" + 
                    "un832uOaz2JCJUxUB11SE/l1Lgz2CS/ZrSH7VOWxuPZYhQJpZsyVg9LyrEnXlN5H\n" + 
                    "vAtxzeMOAxprTaGPoF7Tr8t43XF81wt002nQGOatp1T9Mt6wrOYfFyXEYxX1vSvH\n" + 
                    "DtuX9mEKcrqGEofJ5EujP70TvLBIMI1cvQfMqoGDPQOnB/L07scsKl0N4a/mergU\n" + 
                    "p120P7zak0b5UyO2VJj4tKdn4SeTlH07LxoBKnPsUL3DRaA3ZDERjX4SPEmkM7tp\n" + 
                    "NxPDy79fwyyOlEm3DP3F36dkpgW90GrbggrDQgbNUcPvWq+fDc3RuXQorLt5Pyen\n" + 
                    "/HoC9JZpCvybfe+cGH0oYc2kgP0xoURi/CzgpMqcelhYC199n7Y8SPeSrRLc/6+j\n" + 
                    "+s8ZVah+OT+UoyHuFOS7SF+Mjy3IrsT5UMHD0NenLQM0dC/SakQSGhLCCOs8gzaf\n" + 
                    "BXILTHmFknUdxFI2GH7RtUPnAMV1hGfTvjQkxlUsydJnXizV5xzaTonJ5I6Nl06q\n" + 
                    "l+FlX439Sxb5O6lP1XM9HlyML7qS0iV9vxdXWcyUFrLsoNh+rvA0pu4cwRlv5e4R\n" + 
                    "DScDZyhOA+ya4pod5NVHaQUC+z+qOWn7CCzVFIO27PerZOLGB5sogwtJGcEKXjil\n" + 
                    "+mG4kCB+aYlkZW0WB/w35+dIupUf+cSQQhba4XiW6EQU0Lfu8yvqYrVIimybSunA\n" + 
                    "TC0CBcLiD3p1JRpncwd1Zb5JYJTaISb2\n" + 
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

    public static final String PRESIGN_VALIDATION_KEY_DILITHIUM5_PRIV =
            "-----BEGIN PRIVATE KEY-----\n" + 
                    "MIIdZAIBATANBgsrBgEEAQKCCwcIBwSCEx8wghMbAgEAAyEA1Lm7xURt5KtRGrm5\n" + 
                    "GcWJ6tG+rL83LMcyYx2m/V/QuMwDIQANaRhxcpSpYAM7KQnVACrkOCpDJt+PFHdS\n" + 
                    "36y7GD0fcwMhAJiFDTezGWiaQzh0n37RvJvMtdTBmJl4989R38VwSupiA4ICoQCI\n" + 
                    "lmQEgBFjpGTjSIhgiAAQEFICMIRBAGQhgnBiNFCBGE7aRBBRQigUI0ITAiASRwAT\n" + 
                    "SS2IFgEaAQ1UKBITxQkACYBaCGASw03RxoEBIEkDthHCMkkalSFZJkzUBg5JRoZJ\n" + 
                    "JAUkwAwClAwitGAAqGghIEYSgQ0ZEFFaQoYgwCwcMgzbMg0QuXBARoALtwhCOG4M\n" + 
                    "BSnklkFBNEhERkibAHAKloEEOWHjAFBaBkSZJBIbKFHJII7TRIqcqAiJEHLEyAik\n" + 
                    "poRUSCwDIEIYtgyhxkUiKQ1TIIUjIQlBJE4cpi1ZIkgCRggKh2mbNikJBWyCMnJL\n" + 
                    "SAqSJG0AlU2gIILDOGERuGEcOAzDhIgaJ2xKAGJZxoUBhGRikJEENSxLAApMQogj\n" + 
                    "GQbSMCRZAkghCFJCFiIZsCgQoVEYuY2DJoVZEA3YNEDJNmrkECCDRonalGTCSIjU\n" + 
                    "AHJUiGGMBACiMAUQGCKCRAHQgjAYQ0GbACwSB06SKImEKI1ahmCaFCjalG1UFEoA\n" + 
                    "iEEcGSlgAAoBCVADGDEiuCxLNGyJlpETM0CCOAlCNGoSxymUkgUjkUGkBobYAm6B\n" + 
                    "xGwjAwRKQgzUxGQcCISKIkTAJGwQRQWiCAKgRmZbyGiTCAwbwkwJBSYQMIWUyCyh\n" + 
                    "KAxDIIlBMDBZkoRJAgJDMi0DQkXIMg0iIyZcFAzbRA0UokzYsgXAKCKEEA4UiHBg\n" + 
                    "uGwUIALAkIzTIk0jMHJhCICKgkkJgighwEwglzGCRGQASYUYMk1UEhAZEoygAGWR\n" + 
                    "QEiBAAUjgYmgAI6ZxEnJtAHUlGngEJAgIG0SlADUAnBKmAgCyUgcSI4Ilm0khIEE\n" + 
                    "GEaAlG2apI0SF2oDEU3RAFCZIhIMJHJLpGmKIm5DhjDERIQCNpFDwg1LEnLDyCUD\n" + 
                    "ggMBAAgXBZCmUAFHRMsSZmQEaYEmMtIyicDCcRkYCQsiAoBIkmMGTBADYCACRAgm\n" + 
                    "RpOULZEkZBGIEMLIZSNGitQCEhQZDSJBcVEWCtOiASMlJZgIQhQoaRoxctMmjBwA\n" + 
                    "SosgTWSwYFCijEOIcZgSUdswhVuoBFmQYCTGcQM1SROUIRxFcdM0aUSEAGIUEBsF\n" + 
                    "AcFASISmjOG0EEyoDWBGQYSihQq3gIAYQUwYCJI2UBgWCRBEKJKYEeKSKeMwCpyo\n" + 
                    "MRCnkCQ1UkAwRNA4jASWjQPIEAIBEhITIUC2LImEbRCXjUuShQOkSZuEJdqmAAER\n" + 
                    "ZGAEEogoIFQSkFQAKBRICNG2EYSQbaNGQBQgCSBDaQwXIBmDgUCWQGKgYQKRcMSI\n" + 
                    "RMrIBBgjCgqABaIyZQIpUgO0CACxEJQERNEgChNIihRJEAQHImSGjMOYhFM0CeEw\n" + 
                    "jJKkAYxGMkEkgAgjDgMZECCEDVMWBsk4ScNITtAUAdg0EAqhBBkWBookJlgGEECm\n" + 
                    "bSREcCESRKNGUQQZRhMRioIiYFOSEQSWhdiiSRkmTINEicwgSGS2UdoIJBm1YGIg\n" + 
                    "aRNAiQImCcEGQlwkhhAnhAmHBYQYKRAjcUAEiARDigsGguMWaQkkMBqUkVk4KuFA\n" + 
                    "ZYgQJgAZAFxAEAJIZeA0idCIkJMoCQswCdlGQiKwKZtIYSHJKBiXBUiyZAGkjQKi\n" + 
                    "YZEACgw2EOQ0UcsIjBE4IpE0IZoUEUtEYIkyMAGABEqYLQyYcRtAJsMYTCAWkVy2\n" + 
                    "hQqngRqQTJBGbAGjhQynRJMoDFmESCAwIVjAZJCobMPEAdFGUlMySRwVSFg0jBxE\n" + 
                    "IdiWcBK3AIoybGMkICGgIZkYipMEbOKUCCGlacFGMFQ4gBy0jaMoICPBjEQGBUQk\n" + 
                    "KaM0AdgmAIywBRwmDeKkgaOygUCmCCQWQiGEKQEUiSQGCiSpSJOwcEI0KRggRWGE\n" + 
                    "hAClDYQoMgwlTOPELBKIBISyLFTAJMkGcdNGCCQDaQKEZWAWYoyCjKFIQJGYCAAR\n" + 
                    "SkGmCAOCDQEAaS8LU7HCb96vrqjxue84yU4Z+PPJhxeukmGOPSpTlgQhrThsTd2f\n" + 
                    "JODF5MFeoOzHD3bixtOKPsrgp1JjHRttolD/WCXLSW8lGNMnc5fdI8CCjvCyDTwp\n" + 
                    "vixxZPh7A2FgX0nIWVv5tHvtAji1tNyXwD9bMFDE9YYw8jurXl+AWyR1FD4WO/az\n" + 
                    "pXwgB+u4GkaT8B8QJwA1cskMa564FeG4dwt2Dlj5JFSaOrKSFghGtjGBila9sk5V\n" + 
                    "nXyznpplh13bOw5TKNlNIgmzlY1bWCQAdgwHT1aQ6tPlYtit/VerH71ILVQ7tAkW\n" + 
                    "El095NoiqGfA38Q1sy+P0DZelWyDO4f8xOCuA/mIudiJk6OJ6zDlTuMeTG0+MKsx\n" + 
                    "U1gQ9Gyz4wM2RsdUIWM+KEXi4lWGMV3QSGmYwvxukui0CmAqsQG6lga8x1MBVNKU\n" + 
                    "aVRZSFhxBpp0r1R4thzoAWKGUQTeh+f23KfD3y6ehWQyFJH1lEhk+DbzDmsRiiNn\n" + 
                    "o0I09oP7A1vtZ0EZwenCkd8OYmy7PYf/OWHOtgyXTS9JKumjlCNJI4N9JmIt4sJp\n" + 
                    "P9ZfGfCEuIZhOt5GHuKQsKBERqUBGC9jA8CAPPLckSqYSW25i1CO6RZeGP4zQVbE\n" + 
                    "fzwx3BXpHv3Z5GHiMprQ/tHyvm1pKX851MjBaETeY9VcO5qS+R5G4XnbHMajzGVi\n" + 
                    "mALgpVO97LcEm9V2jRIxZg1nt4urmTO5vmFiccZ+GS5AXVx2ZAfP1RAAatjZXhI5\n" + 
                    "2xiYRXN/ZRGDwh7a+KDxAncCoMSA2VNI5QMBFS45rSCrZWQ6xVroEcs3SJqLBXwd\n" + 
                    "MQEhQq1fWVxylOryvn3KwGLsgCbdvx5SgEReFDy65uzjrHvpFVJaMm3j0TeTY512\n" + 
                    "Tga/ffR46O1Qe/hcjYuNvGap2u9IOiIwm26k8ibtsUH57F4hdP9ndAqHKuOdRmxn\n" + 
                    "0Ease7JLGcqRgiPKUF/LWmz5LdV3wr6Ch/dS6zzFaWmG2VcUIX66zNUiBuIUKrk+\n" + 
                    "qRuQ3w/df622+URujQIVKo2GsZPsBiiook3kKaWGysR9ch8byqZ0AEAJEzgbFSIU\n" + 
                    "I2atA5Zy9XhBN3EB86Gw5BSTtfdEkCW+wlYWlF9dAPkSPGGbR5cStLUy0o/tVfU+\n" + 
                    "YXIvEEEmwanLRH9GEOIPB9P6eaPOgST3d2VxXbFHOSe+jjGLg48YHWegFS0qFEz+\n" + 
                    "Po+RHL4IgyDlS/il9IHoCtcknwJMF2XV+o4HH5njVLcHlYnEzlP83I/wvfNkO6GX\n" + 
                    "5tGu5yJkWXt1nwx77iun89nEqCBqNxkSBB5XcOZPipXdr7VOOTJi+0mFbX0K/5Ui\n" + 
                    "UkvKTDe5lwRcEmuLqhl20wd6tVo4JaRilcz8k+7VjomzNlW6bZHauEHuRdt9NjTm\n" + 
                    "Mvp6JuLFnwNkxWggX/xbdVF8rQnSQU4HNbW2GdhEYVoNkq5In0oXk2nRyqXSSc+r\n" + 
                    "fWFgjruB2tYQGK6rqCk/Jvx06y+1G2yqIXrzw3wegzjcHvj1R6oRV+fLnGbfqdCR\n" + 
                    "unZFVJ7ysXL6NC7igQCcJmKPD6VPHD2gJifd53rsvyWjm79y8OQFty/DHP/W7XEM\n" + 
                    "9+yuS0CRGWAVspUSATzifXxMJhz3njYZCSKuDzLqEtjSPCSFqdF5fhlyS8CBqeDC\n" + 
                    "cihI+dl7Kw+RsaerNbWEOdrR4FzRyTllV0hGpGIp1FYPdm4ubXhhQwGYqGBKzu+F\n" + 
                    "HDJODQXk9t73O0i4hXzV4Ed8iE00MD6toJvv63hMS15ItOekx9chRwAerek65gUR\n" + 
                    "GTyUUw9iMhFtg8MrCj8qQp6tkb1D7+NUe+A5SEu3Sv20gI7hQcplPZa+lxqksszo\n" + 
                    "0vUC2t6Q5eXON8X0Rl4MYO5ExHDgjMaJsAVeHHqbRyN+KbRudVkzI8xgMhfZtiQR\n" + 
                    "u8m7VKXMS6BYFPuFUQz18pIrJ5OHrGq2Y1jAXH8xqOuAXe3zMlsC9pcvm4sriWt5\n" + 
                    "UMUyQvyKh9T5i54MSZtJLGlPVqcwrzJcCT+2wxQTrYghitt4OSHVx2ufofrWUVgw\n" + 
                    "r7ZeNzSzkPGxfBk9xqUOq4oiHxUq6E7AJsvsma7zVXV1LX6x4UJBchS1fBVDiuaz\n" + 
                    "M5r/g8i/kv/tiTYXqw1DsAm79p4aJUGhMK3QqtUuoipUFrD8nHN7MZvHb6i1kjc9\n" + 
                    "pbDEOVAfZ9veSe/Uzuvhh+J0WeSp0aIqrtcNQdW2ISYDHy32NcncX2RgQxzR5zFq\n" + 
                    "bjMEX8x00wYGAev88PIHK+bS00DlrR5xRvPO8LYzXltSJOInVVyiDhFXePW7ODz3\n" + 
                    "yDLuJRJFCUTJROZftZ+ORCYr7d3GhVfXjGaUzGsdFSlmeBGMpdZi4VDV+aZjGgwv\n" + 
                    "AalWz5b0hHrsZmKYMV/5hBcT1xQxbREcw+nVIvWc49nEHjGi719ovF4tXYUaVjAG\n" + 
                    "SAafvm+WwRN16OcZcJhOjVrDgF5UYqnITIeJY7qtWI8FeZQIsaVM8KgLSdY0Joga\n" + 
                    "T3BG3kuPa8W+jS2cnz3IBBN7xzCnprEo63rbtFGDNyJOmlP6d5JWzSKmcnjtVSsq\n" + 
                    "edYkjvkGKf2Es0jIfBMKVMiHlPtBDnmfdpkIwrNkgqYSA4DE59gbxLi8Lm+aXLKe\n" + 
                    "xbX0gJw0bmDvxDd8x1k57LhoaA8Q559+7rT+9RFhqM0sQ/AXEyjjwmdosvHktJ4G\n" + 
                    "+ze+URU0ghiCnv1bSW+Xeh/PY9+eEVY2B0ggTvC7/zJkfXbj82KhGPnZ3l9HCAkZ\n" + 
                    "/HR6fkkpaaMFQ+jQA2SL//2LSgXV3C10T1hHPvk6qrnm/PLx+5Q+gAQ3193bQGbp\n" + 
                    "2kf6IkB9LiR9kQK5IaluOFbG6QjlUNXp6rU61uVveiInGrnRMGnOKURqOI50DSpD\n" + 
                    "F0NIdlIVMSj7555EE3MVMG+o2tc0dZHmCOCofA9fXas3BRDaBhx3iBuPAR7crVzg\n" + 
                    "bPctMneFh824XCdcV7awbPMp1ZX6Zzvu9XuM0cJ50e9NTzeNQAsTGdWyv2nioPEf\n" + 
                    "/gwN49mJcZjrU0DYlQcP8HQdSATF16vuFmiQr+JjY221oDmJ1hitxo5BaSnQLaNj\n" + 
                    "XbPB3w/kMvLxbHJDmxbN8b+WTPuC1BR96qc1jJS7xA3hB51YFTJ256TU9Ivu0jWy\n" + 
                    "NYz/K6ScTPqy5UQiN2qKKXLfwwZFOWTKU/aMM9sJPvk4CuL0YmZg9iu4DaRsgX82\n" + 
                    "x8mmc7aKcyB9HKXvxVIlpHgJrDp1UI287P6POMY8daS52hRW0mc1WAjBdYzO2UKo\n" + 
                    "o7WnX9L6ss/Cb7cDNXeI8eov8dGnJkKRSS+NzV32Vq5EMZPUs8v1U7tsnR3Pr1eW\n" + 
                    "IGUQddhN0u24kpWx7NwAdbkgiRKraj4zemC9Ztq1d+/Z/24gBqOMfplQF3/Q/OPV\n" + 
                    "X+UuV3H/BlLKZjLqPvgk23YQXmfMzmJHCjC6otxcBdEed+rZpfvf/DhxgCj3gSue\n" + 
                    "zNZ7kvnkIKvc5tNZCO91yjXka27CEMyTjoslu6EGm1nf8kHehFXVR41pBumCi7mk\n" + 
                    "eP8mcmuSr9+bK8xsWINL9Ji/4XbjGzEFV3vjdFF7AqcpuIuQ01snWnEvbRwYXyRK\n" + 
                    "dlGYx15/gfqdYBkuE9RqPeCFxW7iV+ICojjQDyR4f7nAIoXFqn6DX2uYZ+R99O8W\n" + 
                    "5/adDnmgZ/uE8e/kFxh9wZPcdrH441X6YxXf8eQ0+j0lEsx5TVncG1qSsSI7z9GD\n" + 
                    "PtXH7dRB/TiAcatyQ3l/OgDRuDiWPXzGe3BvtCgYp4Hx4U3zq3iq/XtX1OFRWFvs\n" + 
                    "rDXqqkVd0wxzvuDTgX8ObvpfGZufQ2Jk9Wy53hZB6jfwHJrxvXbuGD1Raig/36oT\n" + 
                    "l19NXPXyHwU1+8/D2omj7Yhpj+3S3n8YhewxP+39XW6vwCVVdko4Yyt3PBmhNL7f\n" + 
                    "QdYPclcAv0+r4VEhRN7gdRiqIpeiC6O38H4B75KLNZ1d9/TLVLwM/aHXLV3MsuH4\n" + 
                    "NejCezasNA4mGqkg8ktMa3K93cjlk4DKgZsbtv5UK190CT2juFRtgVqL52rvKVGj\n" + 
                    "18p4GqE3lVUIAQj8mmkKFtOCwLg2GoNXPlwepQ5fakcP8v6iYoJCEkUcS+txZJ4d\n" + 
                    "SA8cueo0iBqhsXtym+MuB6D2DkRmJRpmhG7+eWO2bCvvqq9BivTdBnUkdLZjfi+x\n" + 
                    "QeJbJJNoKhVGbcMF50Yim06rsQZffMhFqrvGGrIpyZD8XowmIbUUaSN5E0ilmXjT\n" + 
                    "w5YlLULLR/SlH4VnpUGXNyyt5UlJgo/Spr9I0LkccJC1tPJ8JdsOR+A8yC8achdk\n" + 
                    "pdtSh/ftDvwFU8aWPrNxitm2FAV0psguzCe6d3U8zFZqFX9Vtz5XfqpW9djsRiwq\n" + 
                    "lWkv8XpFlaQz2DQVr1YkVmhMSkOQ0Xg85jjYh9TWawF2lO9QMXPLMct8OJPQo3p8\n" + 
                    "L0Kdwy0yujHSijj1tlswFiaq6Td3GZu/MIGCCisAMIIKJgQg1Lm7xURt5KtRGrm5\n" + 
                    "GcWJ6tG+rL83LMcyYx2m/V/QuMwEggoA8u968UXZ1JrStp+Wzj2djad+eeVo7swg\n" + 
                    "VqU52HkoFVa47yF7MO1aQwJ+89fqcttO6JaYQufr4KgvFilvjY0JK+jGTg13xkGL\n" + 
                    "ir/aLKJzS51QjXQ14dOdUcOy4MQjq89pJwmkgzWykTkDhfOCM0QICTMEmtIPlpBZ\n" + 
                    "DcXD0qYpTCrALbIuXwlHoB2YCwdWfJUHwDb3QcXQojDXlZ+Co0sYES74FxEVlWUH\n" + 
                    "0NYIMCKTx5mK3Ul7p1EfQW1fgXu2KSwulxP/5h4i8Cvw1HxnRywyjuLwbI3wWN+s\n" + 
                    "PtSKzg35TR2r6d93dgeAZzb7lcJs8DlVPqRCKd3gb20Vhy4AxLthTo0W7y9sBo+n\n" + 
                    "speXrUH5L3KNJH/ReA7/7Ek6ofDO3CflsVOd6d2JGPpcRZEcgPh/uySDU+AHEReU\n" + 
                    "yOZzuJJDZxgcYC1hEEEI7tERxTtwlwW8tgxblzhL1Z5So2aStleKRSxB/yUVl+Kz\n" + 
                    "px4uvkABYhqU2tFj4BW6v22asOp8vVq6ijqSYq9F0tBWKI3ddiwL7XpIiuY6MHxq\n" + 
                    "0xc8NBbMrB0fb5bm88fDOOM6i8nKZvi23YWl9waWMP5/s4vhGLhChHknTJjqaScD\n" + 
                    "4hpbbgTHbGOmTIl2Oh7BWf0ck/WcM2CpEnNrLT9LNV1OkMQfU6epTKHBfw4H0HFR\n" + 
                    "T6Xt0VCLsmntEkHH+3Bh54zXAkpcCgLfEqD4Sfv7xHWF4NNFNOj5sgqAzujEHBqy\n" + 
                    "abMgACdW+zEzrCvEmqMR5AjL6GLKVCEYypmpCK+kTZVOqAM/dtMR+6c7LEFmooAg\n" + 
                    "c6L3VoSSOwFtkk8Hs3EuvDVdnN6enmP0cLXq01tC8CrrV8LXMjDApFgP1eZ9O/8R\n" + 
                    "4Q9Wom7V1UdLXfiw+FdHdOxs34Vc70+Xg48h7iDJ7jQgEgvjsgFLM93x00miBRxO\n" + 
                    "MCACC214EOU2GTNJ0rL/o6FgnrSQ+YpMxK/8CLPv8vRfuPZPf6uRhDmrrq31U+Lt\n" + 
                    "mpmyWwO75J4ppB2J59FD5VVeelYM42mxnieWYoiyKfRSZhFQkP0a54KHJQLWaaHk\n" + 
                    "YLFSBdakrAsS3YPIxQK138/YzUCJ+FF8PevSaWiTALct+Wa1HpDGtuVqfCJlL6cn\n" + 
                    "5KOU0xAT5zqGMjvH+V/qU/BdWJr+GO1PaIJWMkuSnBPQA2iwL+ZdY+yn16uY96Hx\n" + 
                    "J+mGQuWqiTDbFquVNANb89nvlpCHjtz8x7ytQtBE6FJdPV82x+RWzwEhn/NpJ83y\n" + 
                    "hrzJTxSVIlVSedhsHTM83WRMwYfx3JvxGZOE31SSyeFSKVawQ4EXcvpGIVWZ+cLA\n" + 
                    "vQogFkJHWAeRzf5lZWsfflZyNHTG63zbGUwhjegHNNcMj7o9tRIqQT9SlF9v3XIK\n" + 
                    "QdH7GMvbFc+XHcmHnRRSC0stNeX1qlT21U5otMVlVbIQAyC09JpYDvyyvfghtl3R\n" + 
                    "f23xo5Y4dODUxvDoC2wU0d3pW32IAEL0XSUzTEr8n8+SynkWXKfaExpG6oCB8grr\n" + 
                    "zVxrH1O0ZTLBuKQBkvLlgUtapJgM9W/dxM1fv8IFKyY/jj9ziEtHd37jgfrwKqAh\n" + 
                    "auNMEPx9g1xuDWl/4CYadGraRqkrfPn+96bycaEWyCCPzr2nRVO7c8U4aKIqMj80\n" + 
                    "jeIn+u45Yl4ZkSi8bYmyrUR4f/PDbQ9Mn4tzgMKuzpL5QWEmOdy2C5CtX1SOanvP\n" + 
                    "ijPiQIA+4qaxIpwCmFR2gGRBh/VH76Q1TD3z0QfFOR5fSjVXzAbiwxhKIEIhutiZ\n" + 
                    "D/t9DvN9pdOWYE2GBEk8wZ+dZ7srz4SHCZF7+H4DYZAqVi73FIVVfqVA/VFvEPdU\n" + 
                    "HMy1Ub54RrrQnji6G+4CT+ZsCcUAdJed1Wp5SXnVgcBs7EfEOZM4AH+hYMccFUAD\n" + 
                    "cSbweaEBDMTRp5fjC3WWW5/K4QUH6Qkf/0L9cBVGnBZN/j/oaX/vNXjxsF8FD7Ph\n" + 
                    "nyU2JC1rURKSUg5YxHvrMSBuXv1LQUsXI7iKWALV8BZ6b2uyegQFw2BIPbsOXzuL\n" + 
                    "pimvWuWyuNfsbuk2pX5MM0LGuTKbKBcW7CgyGau1ttXpOOs0yx0ihvik3gAmtH3u\n" + 
                    "5WNkLkXpJdtcWXu/43G7lMPkn9+vW9pU1iTZytKEiAihxHsdRn6sg9u2RKjRZNKU\n" + 
                    "7yGxNQAwKvyWdlUUTUMty0n3G4fov+7HH7ojiFMKRqoJg4WhTLpotiLcFvOaescm\n" + 
                    "yxY3MN1mdyLqxIL++80Wms9yQ01b94+U8A1MTZhWGuYr6OO2DYwwrzQ+yuLWY5qf\n" + 
                    "JAtiLbh5H4ZQufiRSrwJL9IMLcn8M339Z1BpH2IKe8IER356ma1H+uUIQyOf6i6v\n" + 
                    "rSA0P3q+wwD1Ern3iJDI23+G+Fiox9JLpizpPggrmn1/PVHw7610PrGUp+q5Xbs7\n" + 
                    "tLTtvf4N6kq2AhPeaSL5jwyQrQCg+GW3TdjGfipg4GslFQXIUJkJ5uXcXS7bExE3\n" + 
                    "xjJeJezHJSJJyShrBKLT4oejBK7u0nvmQYD+V/CTQDNSDYSB4Opw5ud0oENetHtN\n" + 
                    "Xt5zEY6c+Ww7Un+d6/BCOcFaB0vM6zzpjNk/7TrOCKRQfblNN3ZnGuqYnMrJ9w7C\n" + 
                    "nO1miVOEKxd0DdKw3xqhdjanc0Ux97hHP3ke0OfbD2niB3khYDlRCJn4427W/WZV\n" + 
                    "di9/8tzUr10Dw4C9+TSw6xQUsp8Abomwrw/HSga848jXycC8SqDG4JB7qZWSYlbY\n" + 
                    "UkYgOKXR7HDValpRb1M74mySKhOlVkko8xjcfLH+8BOZ667tycRHEOQU24q5AORT\n" + 
                    "Sy8hNtQnOoL0gAOzClC3AF6aKg1qFTvYvd8RpuBuOVR7m/0La10ro4BYZuiTwC7Q\n" + 
                    "TaHUsRNijI1R39A/IMRSx5rpV49WLfjC3j/r/G9l0s0qBEcrUdp/9oLuFxs1u0ee\n" + 
                    "fNO6gEVj6ekMNbtpyCdXltigQHPBTtnk6wA6PyKHtRJ/mJoWjsZGVT19X+3mPZyM\n" + 
                    "T5WPGWq6p/FAlsFB1nVn2wxre8gYU9TkaEV4b3r8P656tqWE3c72xPKt7U1POgLW\n" + 
                    "cuB0ZOIM1G262TmJdLuGS8dPS0On9SPnWBZQNOJVSdGwij5jLn/2LWemZzUfX0pi\n" + 
                    "SD6u6LwTFCvKLOVRzZyKAv2dwY9hxPeYBB/F1BrKYQhQhEcmpGJctdaz9CveQO2S\n" + 
                    "i2NCzxvn0jN39FaJeubasqncyP/dX2OeUmwYmv0ywqu6Zm0LJ+G6s/4674fjnr6f\n" + 
                    "ivJ5oJXLTd00yKs/KxWfKhle2WwgmMjH1DGnnecj6I0NhW+14jOBr1ww1eh0C3LK\n" + 
                    "Y05FJXENgfWId9VehOL1DPyQ14mvYVVjnol4mp/oytJlYkjRGj37LuaThtllqPtu\n" + 
                    "NOJAzdaEx91BkoTk8GQPtIoA4YMcDEhSiGvSqxa08c3/a1vLux+k0A==\n" + 
                    "-----END PRIVATE KEY-----\n";

    /** Return a hard coded private key that can be used for signing
     * @param caPublicKey the public part of the CA's signing key
     * @return PrivateKey that can be used to sign with the passed in sigAlg,
     * or null if no as hard coded private key suitable for the algorithm exists
     */
    public static final PrivateKey getPreSignPrivateKey(final String sigAlg, final PublicKey caPublicKey) {
        return getPreSignKeyPair(sigAlg, caPublicKey).getPrivate();
    }
    public static final PublicKey getPreSignPublicKey(final String sigAlg, final PublicKey caPublicKey) {
        return getPreSignKeyPair(sigAlg, caPublicKey).getPublic();
    }

    private static KeyPair getPreSignKeyPair(final String sigAlg, final PublicKey caPublicKey) {
        // A switch to use different keys depending on the sigAlg so we can sign using the CAs signature algorithm
        final String keyAlg = AlgorithmTools.getKeyAlgorithmFromSigAlg(sigAlg);
        switch (keyAlg) {
            case AlgorithmConstants.KEYALGORITHM_RSA:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_RSA_PRIV);
            case AlgorithmConstants.KEYALGORITHM_EC:
            case AlgorithmConstants.KEYALGORITHM_ECDSA:
                final byte[] encodedKey = caPublicKey.getEncoded();
                final SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(encodedKey));
                final AlgorithmIdentifier algorithmIdentifier = spki.getAlgorithm();
                final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) algorithmIdentifier.getParameters();
                if (oid.equals(ECNamedCurveTable.getOID("secp256r1"))) {
                    return KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_EC_SECP256R1_PRIV);
                } else if (oid.equals(ECNamedCurveTable.getOID("secp384r1"))) {
                    return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_EC_SECP384R1_PRIV);
                } else {
                    log.warn("The CA is using an elliptic curve (" + oid.toString() + ") for which no hardcoded keypair exists for pre-sign validation." +
                            " There are hardcoded keypairs defined for P-256 and P-384. I will use P-256 to sign the pre-sign certificate.");
                    return KeyTools.getKeyPairFromPEM(PRESIGN_VALIDATION_KEY_EC_SECP256R1_PRIV);
                }
            case AlgorithmConstants.KEYALGORITHM_DSA:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_DSA_PRIV);
            case AlgorithmConstants.KEYALGORITHM_ED25519:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_ED25519_PRIV);
            case AlgorithmConstants.KEYALGORITHM_ED448:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_ED448_PRIV);
            case AlgorithmConstants.KEYALGORITHM_FALCON512:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_FALCON512_PRIV);
            case AlgorithmConstants.KEYALGORITHM_FALCON1024:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_FALCON1024_PRIV);
            case AlgorithmConstants.KEYALGORITHM_DILITHIUM2:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_DILITHIUM2_PRIV);
            case AlgorithmConstants.KEYALGORITHM_DILITHIUM3:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_DILITHIUM3_PRIV);
            case AlgorithmConstants.KEYALGORITHM_DILITHIUM5:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_DILITHIUM5_PRIV);
            default:
                return null;
        }
    }
}