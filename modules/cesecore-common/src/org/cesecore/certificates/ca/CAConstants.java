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

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;

/**
 * Constants for CAs.
 *
 * @version $Id$
 */
public final class CAConstants {
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

    public static final String PRESIGN_VALIDATION_KEY_EC_PRIV = 
        "-----BEGIN EC PRIVATE KEY-----\n" +
        "MHcCAQEEIEGrpEiJQlvnnPWqPVOT7LVD+h2RNw1orVXdu/HumkWqoAoGCCqGSM49\n" +
        "AwEHoUQDQgAEjFHZzIXCz4W+BGV3V3lAoXMqISc4I39tgH5ErOWKMdU6pzpKWlXi\n" +
        "gx9+SNtdz0OucKFLuGs9J0xHLJhTcLkuyQ==\n" +
        "-----END EC PRIVATE KEY-----\n";

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

    /** Return a hard coded private key that can be used for signing 
     * @param sigAlg the signature algorithm the key should be used to sign with
     * @return PrivateKey that can be used to sign with the passed in sigAlg, or null if no as hard coded private key suitable for the algorithm exists  
     */
    public static final PrivateKey getPreSignPrivateKey(final String sigAlg) {
        PrivateKey presignKey = getPreSignKeyPair(sigAlg).getPrivate();
        return presignKey;
    }
    public static final PublicKey getPreSignPublicKey(final String sigAlg) {
        PublicKey presignKey = getPreSignKeyPair(sigAlg).getPublic();
        return presignKey;
    }

    private static KeyPair getPreSignKeyPair(final String sigAlg) {
        // A switch to use different keys depending on the sigAlg so we can sign using the CAs signature algorithm
        String keyAlg = AlgorithmTools.getKeyAlgorithmFromSigAlg(sigAlg);
        StringReader reader;
        switch (keyAlg) {
        case AlgorithmConstants.KEYALGORITHM_RSA:
            reader = new StringReader(CAConstants.PRESIGN_VALIDATION_KEY_RSA_PRIV);
            break;
        case AlgorithmConstants.KEYALGORITHM_EC:
            reader = new StringReader(CAConstants.PRESIGN_VALIDATION_KEY_EC_PRIV);
            break;
        case AlgorithmConstants.KEYALGORITHM_ECDSA:
            reader = new StringReader(CAConstants.PRESIGN_VALIDATION_KEY_EC_PRIV);
            break;
        case AlgorithmConstants.KEYALGORITHM_DSA:
            reader = new StringReader(CAConstants.PRESIGN_VALIDATION_KEY_DSA_PRIV);
            break;
        default:
            // This will lead to an error
            return null;
        }
        try (PEMParser pemParser = new PEMParser(reader)) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
            JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
            return keyConverter.getKeyPair(pemKeyPair);
        } catch (IOException e) {
            throw new IllegalStateException("IOException parsing hard coded presign key. This should never happen: ", e);
        }
    }

}