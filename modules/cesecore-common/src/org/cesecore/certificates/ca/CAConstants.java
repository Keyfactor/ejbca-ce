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

import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;

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

    public static final String PRESIGN_VALIDATION_KEY_ED25519_PRIV =
            "-----BEGIN PRIVATE KEY-----\n" +
                    "MC4CAQAwBQYDK2VwBCIEIErU1sdUkfufFIiIjeyB6XCqEKR4dFtTYejBjH/jeM4O\n" +
                    "-----END PRIVATE KEY-----\n";

    public static final String PRESIGN_VALIDATION_KEY_ED448_PRIV =
            "-----BEGIN PRIVATE KEY-----\n" +
                    "MEcCAQAwBQYDK2VxBDsEOaEFdMTDqYgfCBO+L1X1gkY/MtsRCkkqRIRaf/w0sZL8\n" +
                    "MHdS7JohG5RxniPplORiTi/F/bIkJ8GZ7g==\n" +
                    "-----END PRIVATE KEY-----\n";
    // PQC keys can be generated with Java code:
    //
    //    private void makePrivKey(final String keyalg, final String sigalg) {
    //        try {
    //            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    //            try ( final JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(baos)) ) {
    //                pemWriter.writeObject(KeyTools.genKeys(keyalg, sigalg).getPrivate());
    //            }
    //            System.out.println("Generated Private Key for algorithm " + keyalg + "/" + sigalg + ":\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8) + "\n");
    //        } catch (Exception e) {
    //            throw new IllegalStateException(e);
    //        }
    //    }
    public static final String PRESIGN_VALIDATION_KEY_FALCON512_PRIV =
            "-----BEGIN PRIVATE KEY-----\n"
            + "MIIIqwIBADAHBgUrzg8DBgSCCJswggiXAgEABIIBgOAuQOAdv/O+QxiRQAvg/uvv\n"
            + "wAQRR+ifQBRAAO//vgQQQOwPfgyP+gBwt/fvwwgfRfRPvxP/vCgB/COPxPfw/h+w\n"
            + "gAgRxPfvvOfvvAgxO/hvfeQhhQhwhBO/wAQgvwu//SPywOhgQPAxQQfAQAwv/vgR\n"
            + "/vevwgAvwvOBiQQPgQABAgxPQBeB/RQTPQgROwgxBvgvyhggv/xvfwvwfxf//gww\n"
            + "PfgiOwfP/QPve/e/PfAvvfvA/fPwPgRBfwwgfA/hfgRvhRPuw9vheQPQQuRwg/vh\n"
            + "QAwwwvgRAOuvQfewvgBQhA/wPuwAOhP/uQTO//vAg/AxRCP//gRwPfRPvAwgAgB/\n"
            + "wvhxRvPAPwgfhPhePxuvRQgRPRAvwgh/vQOxhRRvwx/gwBAAPgQQP/uggPwfgewO\n"
            + "fvA/QgwQAee///wOB/vB+vwvgAPxPwe/xvPvxg/v+wgRAPfeQwBBPhvvw/APwAOe\n"
            + "//9ffOAP+/CPP/PihOhQOfPPgfA/wBBA/uf/+PxPwwSCAYAADwcEMIH4P4Hkb0EX\n"
            + "0UMIAIED/74An4EEED///3YXn8TwQX8H4P0QIQgEAMDoHwHzwUQQDv70QAL/8jwL\n"
            + "8Ub4Xj8bYUEAET38QAAgcDwD8T4L74AD4IUQYT8sAH/4T//kH0APsLoEH3sEUfsI\n"
            + "EcAPsEEDj74QD3oL8MDnjsAwILsIAMELwELoL74AT4gP4EQIEAcAUDsb8IMUMLoH\n"
            + "wTkUMIH7kAAH4PrwAPvkAYDsgT8QUUAEbgLwT4UMT7/nkAX4L0IMH0HoUcf7wDkQ\n"
            + "cDz0MDsAAEIEDogQcD8TkL/4IIn0L3ogMDz/0j7wAEED38cAUIIEL74MHsoT/gET\n"
            + "kHsT/oUQQEb3cMcITzj4D4sEQQT8QPv8XcQAHr0IIAIUD8EQfwDgkEEH8YP8L0HQ\n"
            + "IUP37z4AP0H8MLzv3vvzcgQMf4L74AL8IMIAHQADz4Uf0r/z8AD4EbkD7wP37nzg\n"
            + "AEP70D7oYEP74T0T74b8DUEET0MP37//30P/38IHsfv4PsEEggIA89ML8eTw/OfQ\n"
            + "4+3w0wXtFRYTBwXkMAP13+ULH+v19yv7NgXOFfsT4PP29PT35dInzSjxwRQJDif7\n"
            + "JQMSE+QE/zsU7gkBHekS+Qfp7zr9/TAtLfj+FyQfH/8U9RfE1RHr7wfb9vvp//jV\n"
            + "7NT44f4c5Bn+0vzpARwH7ScMFvnyB/rzA9nlGAEyEvkd8k0f1SHuRSAXSx/4C/r+\n"
            + "DO8V+uXk6fvS3t8SBv8TBPYE0/0I3wz4FcD6C9gF2d0TDxvTGQ/3Ju0NGfQyIvQS\n"
            + "/RTaDQMMJCrm9w/yK9u65NgaBiocBh4d19346xEZ7PTtCQz3/+HvBN4SEzMr8iH7\n"
            + "GinZ+Q71DwDkMfYhCAk9DiAWCSP8/RMD9fAdH+fGCeUr+xQr7CsS9tcH8vfVEOcI\n"
            + "Kw7lHOznGMvILAkdBAYNDAnkI+XlFPP8KQjxBQYUCfgZIvHcCSMV3wjX/B0dAAL7\n"
            + "QRP+APASEgIcFib667Lq1/X2GQoODRkF9QD09fz+Bxs1Jvv58hIexfwhGvjtBPX3\n"
            + "/O3k1u/94AMI/hsEAd3y9RsB5hAABAvkBw73+/vU7OEL1/oDFREOKzD/DREDAigw\n"
            + "8AIOCDnY8AT/Jv1BEB8fFREFAfj7DgEb7/QT9AoAAQL9EOny/w/UySbeJBAT6/3Q\n"
            + "+8nfrREnAgIWHAAm3fb0+AwKDR8rEu0wggOEBIIDgLcCCScVqQa9CcmKfOCfIrD5\n"
            + "SoTQnhYsgxBPWsmlcMlm295vUrwHyaPquhD5DZryqfIUiDnXTR2yiS5iAZyvA3/a\n"
            + "XoUrHG2d6Rdn3dz6nKoF5YCFYGiAaZW9AMiENLGYCslCB+DVGyOrCpnt8vhE51IZ\n"
            + "sHbliJ9xd+kYpApOb52d0uAZUctnvH9kDu8MeQYBSXbhJbl9JSsJWLBTHNeYCSlX\n"
            + "HwSamlYjg3GB0NLwgE8jDR6JK1mRuoWnmDhhLprB0ehLGocB9MHlW6UwclKJ1cgm\n"
            + "vFkw9lF6QPIKrHthaOYaloiEapXJtFWuLHsbVbQMed/Ly9TjIFyA+ehRDYXMxOiD\n"
            + "2v1mqphSPFtYrckExTIObpPJRUhPhS+3iLB2m+QstVjW0nmbo4LtgsD3b+dmZtHG\n"
            + "9iLYhBZQGtyRRw0wQooFgdtHQFCDHW9ImFWGgRPeq1cxdFlPki1BCc/T+Z7bV4yT\n"
            + "QkwOw5vyPIJypKkgTaQp5MJ7MwZ04L4dTYNtoTsKWCcmENRa59RXEL2sB/eW5JAS\n"
            + "TTtvGdQRSpIYTacqNSpuavNMcrVa+6W6kNudEcihO945cIhv9zUtokPGPDPTGJWC\n"
            + "TvsmuAcDCrGogD2tU0yNY9NhgVU9mnmo1cCeS2WZ4c3GYaQpg2fzgFV12pL5npup\n"
            + "Z5DDObfHV5PRpdtlF52ctoBaPUjRc31FBzJH+IjlCMZfz6dkLkAEulwqcMjPN7UB\n"
            + "YKfRtEfJKDptCSFHUoreTnzguEbf7KRp2zkqWeWAUjgGXmhVKsVUB9ic6Q8udYNd\n"
            + "Grc4HvN15tp7Dxy6tO0eFr3CJ/XuSPF6Hh+X/+hmmVpzO7gC/z5A8KR2bt2quKEh\n"
            + "B55mBgp/BctUzZdW/KsVT09iWkHpbYXhAU2VNlzdPwh0+FRjQER/5kNGgAIKIGEo\n"
            + "YtlnK7zsN+H/4mhz2p7F20T/B9iDgE8cxj4OkXjtX8sSKNkUnoK/V1Gx9k/Z9V2Y\n"
            + "KBlIGPVRRemJt89OpyAKOLFZTD2pItvj7LGzhJax7AH5IpHB0FqgjgflmWsyqVCs\n"
            + "tLg3iZ+9IyY1yzoFILo+ZYfJVK1fjF9YaqVUHP61ZfnG91ZqaFBebLEVGM0DX8Bv\n"
            + "bp25lIdrTBmAKUdVjYCm7aFl9QQtLipXyornN4ccNsRbWXNNUQqzQ+PKC/Gkszso\n"
            + "3DQ6h6oM4tNT1kH7u2iH\n"
            + "-----END PRIVATE KEY-----";

    public static final String PRESIGN_VALIDATION_KEY_FALCON1024_PRIV =
            "-----BEGIN PRIVATE KEY-----\n"
            + "MIIQKwIBADAHBgUrzg8DCQSCEBswghAXAgEABIICgNBH4wOB6AIBdEDpOiD4fx+E\n"
            + "fv+cKMIhg8DvADCLg/+GXYv//4PAeCUAg+APvQ/54gADWUPw78IP/9EPgvfEAgue\n"
            + "D0JxgD4vxBCIJBE2E4P/+PxB/8ExOd+IXOh74Qwd2QPgF6L/+F+ABBi9kP/+CAIf\n"
            + "+B4Pui17gv+CUAAh+AhQe93wgfD34vhD4vQACEPCA+Dwg9/4XwEDzPhe2AJQ+374\n"
            + "RBCAIw+F3/vfAL4ADAbofh5/fA9SH/fCKABReD4XvDyMHhgGMAwf8EA/gGEH/jBw\n"
            + "HAG9woO+AMPR+DwwAftwAxeB8BCc8Inw++L4S658of7H3+Q///wgd9wpid/8YQh9\n"
            + "74Ag6Pvfh+AffjGIB/+B8xQ/CIo/eILwvhILu8+AEPx/94QjBJ4Xwe/0Ygl2EItB\n"
            + "F8m9jN8ARdGEIDA+EJO7EL//AD4Je8F7/Q/AAn/e0AIgD+EvglAQBPk6Hvf/6AYh\n"
            + "mL34+fEEQR+EAfheFwPT/CLwve90QQA2LIBC8AQegL8fu+8Avd9CMIv/6AhBA+EQ\n"
            + "veEIQgCGHehBB8Bx+6IHOfEEJA70AQQdB/o++/4AQfIMf8//7JADGL/jd///hi8P\n"
            + "QB+H73P6EQIAeB/nfACIQvjF/ggB6QHt/AIIxhIAYAEAUAC9AHoQj/sHw/H/pfDJ\n"
            + "/gP/AAHQb6IH+A+QoB9EAAQfEL3fjD8Q+CzYABj/4wBd7/wgD74mxh/sQPe2Lvuf\n"
            + "KQQAhF0Idf6YnOBCMwRd6EgBiCHIhfQM/eBCcfh8FkHwgFsHwECIn9A7/3uCR/5A\n"
            + "i8PoAe8IYOm1/pv/ELuwCL8P/9D/3/9EEBNAIDvQ+6AHu/B4PRAD/Iwd8LwwfMIE\n"
            + "ggKAJ0QyB8HwO/6Hgid6EQfj8DfBAJz4Qh6bweDGI4AAF0P/C54fShILm/gF//Be\n"
            + "/8gBc+AIiB8AOti9z/fDD/2+eEMwPfEDgvfAAAvjF0YBa7v3xeAEGgi33/SfEL/Q\n"
            + "7B34SC+LwRE6EIuBGEgAg98QQiFwIPi/4IvhF4IAcCAIRBEDZ/F2AAwiH34yDEEA\n"
            + "Rg/0H9DD0ICAF4PQgD43A994AQeAHwRi74fwFD73Ri94BRB+IQ/+KAHRkGAAy+IT\n"
            + "gO8EIXwgH0Yw9F0QhCGDvt+9wXBkEAXPdLz2wBMDYBbIIA/g4MZPk77hAgDsHxfD\n"
            + "oXuaEH4jdEAYND8L/QjJsBA+AD/wAHsPR/CT/hhAAI+DEAQ/CF8RRE8QAfaKDvve\n"
            + "LwP/aGEJge6PgCdAH4/6GDhRCCkJwgITfwBCAPzeEMJgdIQIeE+IIf/+AAekEUQj\n"
            + "BAMfN/HcYSdBsBvBBvpCbAP+ukCEYu+CAH+D934//EAYBjEAPxC4Egw+B8Y/BCAQ\n"
            + "/B4Iof///vweEMRcd+AIg+AIAvfB4Auc+IAN++H3/l94H+C4AXuACEPtfAIgQj/0\n"
            + "3O8H4QhAF/4BB+Pg+hCH5gBBoPQB4IQCAFz3SdCYYSg6H4/kIAf+iCIPvEN5AQD9\n"
            + "8HueAAnCiGIgBe5/XB+yIABDF3+Rh5zXw/58YAkJxA+kKIIRDEHgPe///Og6IvxI\n"
            + "IHoheEAIi9B0PtbD3wvgAEAQA8EwQA7wHshCLn+/6bgih+DfRAF74Qe58H/D2XIx\n"
            + "CB0IigAXeul+DvwhMLvv7AIAQ+5onxcCIgvCJ/3vCFzvfh+LfP8+YPgD/sIugN4X\n"
            + "v/BwPvgALhCdEXwCf4Dgy9/8gASCBAAO8fQM5t4e2hMO+QH86gnkCg34FP7+HfXs\n"
            + "CSIq2wff9x0S5/P97w7s1R/hGCHvBfTs8igzEBwJ6iDy8vYD2tz0QBndGBYi8+X/\n"
            + "/RwNBhC46Q7l2RUBGfoJBQXNxvnn/gwH6fEC9/HiEgEA978pFej49tT3BwgTEOYY\n"
            + "7CnnDTvs2/oSEeEIAvnuEv7IBu0tILn57QHw4x0b5/jw9RAQ2OvQ694DB+z58gsb\n"
            + "AAxDAOrxEdIZ5QwBHAoIC/0p/+nmyt8a+xQY5vQyD/H1DxLz6RsO8fUhJN8B9Mz8\n"
            + "8x0o3RTA5fLfJQTK8+r97wAk8unl/gc68QUFHej0zvoKDi3Zzy4p8xDH+/f88fob\n"
            + "8f4WECf09vIEE/Hh0Cn8CwoPGOYLA/vw8gfi6g/xCvUAIONADOIoHPsK7e3f+kQg\n"
            + "UwH+Jvv6+B0i+ATaHPH3AOz/6/MJFff/2hEC+xD3EwgfGA/0ERkP7gfx/fMI9vv2\n"
            + "+wUX1AsXDerdMysKFff4Dg4nDNP44Q8e9fwRCkMIAzTqBPvjEcb1FeQZ7SIk2AQg\n"
            + "GgfOGNjXYwvm9B8ANhDb9hbrFvfR48XzFQ9K6ffpD/zlCwJACwrz6TQd3PwH99wj\n"
            + "GOXkAOYEH+oSC/MwBuTizwj7FBv4y+JJKhHHGukBG+Y4Ce3xO9377scPH/Yz2/fw\n"
            + "9QcQ3SEHEdzrJBrvDSPjIiYMDRgP1tb3Cij2/AM2FQAD9OwVGdEMDNgKG/An0+/h\n"
            + "ziIlAtrtI+0E/fEA+C7199nVHDPxFO3z5PYFHQW/FtAV3yIqBCzZFs3mHg4g5O4S\n"
            + "1hPz/+78Bu3R4SME7f8YEvwP9OwNBC2wBgm3Bwnb9wv8CQriSfvz/9Me/gEJLxgv\n"
            + "/hL/CQoP+Rfz/iMRDgADEPEnDenvEyDdEB7+DObl3foY/AX4+wDfK+0VEePq9xDg\n"
            + "+TkI6+wH6BYt7wgNIx//7QoN9gvqBRr3/grXCQYTC+vy7PADJN8N2fxZ1yr43BsK\n"
            + "3/7z7yL/Eu/HGAr4DwHdz/wK/xHw3Pz5MBP57OsZCwLv7gQx5AAzFhMgEw757LsN\n"
            + "CSjzF/4kAQohA98F+AjL6uMh8RjyJR0GE9QvLAv72NH2Cfbq+wsuBPAeBgYZ1gUJ\n"
            + "2v4nEQEbC/0P7QEoLfIt7N8TDCYO2OX/8AkD2Pj6EPn1E/4dAfHs3/QSANki4Qr/\n"
            + "HPYbFA8BAOny5e8YJwLZ6twNMBfux/rr9wwUHwsS+vICFvL0BOsI4twU4//kHOvg\n"
            + "BfkL9ukAxejl/wwSFhT3/eX9D/3FLd0UKeIF3fboIhIG4/Ht3egJF+3wFhgU7Svy\n"
            + "HAL+H/cLJQoQCePw7u0pEvLhHy0Y+wnX8Bf+++bR9Rr75QL1IQcHMIIHBASCBwAd\n"
            + "/Mizkl3KJg4TpFzM+WfoMDvdnVxaXjCWqkx2G+oqSFZmHkdakWc1F+4XRW3YClc/\n"
            + "RgqSIbgAd0AptVuwmnGUrCgHxmatGzKm0JEHPLt4SsNcWG03AtXxN9MsGEQsuJ2u\n"
            + "dm5x2WsUXS9gEbnB70LZsRTE6RsP9gHyiyHgkVZCoMcXjFETQdVseh2Q2x/UCgKS\n"
            + "ns1Q3b72MMG6gWk9qQ3UQXOGSXRwr3uEZJ3HKQ3CYVqhUBWi2HtxkGPBiZ2VZuRy\n"
            + "Lh71ZXwZJY1Cv7mlNYTfC4G/bsDgZQiaMcHgCVjibkCEOOjCUFee7IzVgZcBpaTY\n"
            + "GOBPHhEIkoqLZqUDGdtJm4TFclQU0Q1OAmsxzFezDSYoofYqHJ57dw2bUPoTBlZI\n"
            + "lljhb6IJKviwKITrOcTwEKlL1WcB4vZzoV9S1peGNKBCD3WjejyU8Zr9VBSmosdc\n"
            + "zd8mWJR0kbGxqQ9PXUI82MOY1wZ1iUWl4wO/k9XLSD1gSmYqInneiVxiCbz3VgOA\n"
            + "USy8ExYV3adl5eMmxCmvZrdpl4D3I1xrdAgEnoAwlCvixIMC6FmrBC7Yi1WbAxaG\n"
            + "CVSIswKAHKk4AVLU7aykcGEItiRpZ3XMxFRAKy6SLNmxGdv9m+EIMfEU/EGNBEIV\n"
            + "Z29HDrr1l2KjIlnXkPNDZyAe9JMIy9yVwgI3ZQrdNfkwsFVGDAFy/dsuWzwvLXxK\n"
            + "g4iBoNGWy+hW0w2x6ZIyS6R6QmFVRGG5UHxAWWXYxgU0A0qWZlMisUaqLZaJk8xs\n"
            + "wOcsbZUCirOxQowrCTXU5oj+dNCg+ySQ4AGQ+UWujbNDUhORyJzcc1iYijkK+7Ph\n"
            + "A4YCxBNdPnbDIiAlbyqIO0ASz6z4L+qJbEc4APHw0KhJrnadiZ7q3L5pabjsHyIR\n"
            + "eX6FAFq0NXWLUWZRDrbpMWm0qJFmyCymKw0HnVB3MHPtBUB4ROOOUyu3QsbC/VvI\n"
            + "OrbyVyPTmIDgWXIRAdK0OdigRSYDXs0WemJe8As1xXtd42tqNGVnb2T+C71ux2Js\n"
            + "hW7J1tXN6cVIhIibjaogGYF45z7EmYxZIWH4jUYBjV00aG+MXS4VEIqSj6UGQuek\n"
            + "glGYAYE5+abmT6h2iKTREC+GkMdc0nlPtMhIfeWbog4vWYSVmJ/he3HEhzQr1DP0\n"
            + "WJlooVh0elZSe0RywUdWQWYh4AohTo8ComGBYORlxVrBSLUPCU1JWI0TdW/TpK6y\n"
            + "i/nvwlKlAoJ0FppmZLDqUgXkdVASVDVIf2uyIYaiZ9O2LIibsghKHx6eBupAYySQ\n"
            + "lIRkBJ5YjGBZruWiAK2Ph8tIJClId9j6iwxzPXO2SxszpWiURw3VbxdhTIJOWzx9\n"
            + "fYWby9yeMmjmo1IXeAgMfElVjmQP8QFmXgY2Frji0cXbVh4YZnmgHbJXbA3RM8XN\n"
            + "PYA6yItde59gPBLL6C4pMPPgy+IrHzCB6+bT/SRBSFF0XWdAOlXJ1thMksQ7m3uv\n"
            + "D4YisRgqYbdqjZ72g6hFrWUy6c8u7QtwudFVVT9DiWy2H2slaPWGllwBLqe45dkK\n"
            + "w58u4rpkpsm/kn7T8vzMN0xe1vpy5YO22I/KlyAwq/AzoM3W+XTEilOPQe4TXRRo\n"
            + "JBXfKV6KQRrTwg5ekuSflsYDwqOl1am0uzynaNpOnqhUbRYlW710AneCV0JcOmb6\n"
            + "GsAj3WaA7XLY6kNxcjOXDl2Vl4mByQ8FJX4y7HrKDv9NNZBJA1GtTJb0KHALlUJV\n"
            + "8UvDjYZZZBgX5a5YRwa4SIUEolfdArrfLFyx2djWWUq1DsrYeJcEz7bsGSJ2EpNM\n"
            + "CvwokGYXI6UH22pPQ4pcUlsMYmk9vXs3PiafSHYksVYcfjbWCLvc6fGurSGXAKww\n"
            + "WQ7cUqfepFsCKrpA1jhCWqnBscNZr7DJSX+UMDUyQXaRakeJ4Vzl7t4MSsERke/N\n"
            + "0CldtNY4n/OFgWOjYJA9jZj1u/xLd3jBvYODi+NTWuy4Ngk/a/rhe4JWtYR9KvAN\n"
            + "wv+P1QamKFw+pvk36BTHhTUxnxvPHXY5VeQXyOg7OD72EG+Z+LBqpEH5VDQstBRV\n"
            + "vWIvRzVf5dUPDIqAjcaymEmzvch7DR1XdVaIK+bJn1BA/giF1bJFQjfUpgtsouJl\n"
            + "ew7ZGE4R9Wr2V/tBEispa9cwosFexZYpJm4EmZQJS/G5TeiTqtt1AF62wmGM4Kg1\n"
            + "EUkFrI4unui4rtZzNgEm0andV1KxtDlPIMJh4XRQcFzADNolyJGrgzCKVLek5/RT\n"
            + "GXzm9ZLVaj7POY1eFRUWAketrOMpHpEmw8EEQDmP6vqDLmAVjtTyJ2S0ioRCJCLa\n"
            + "DkFk8qgKi39CHWTAxu6Rfci5CwcUXYif+0fHsFyUNpkY3gqW9a+r5muPF+hB9HGJ\n"
            + "FRBGvsISFucbphVp51BJ\n"
            + "-----END PRIVATE KEY-----";

    public static final String PRESIGN_VALIDATION_KEY_MLDSA_44_PRIV =
        "-----BEGIN PRIVATE KEY-----\n" +
                "MIIPPQIBATALBglghkgBZQMEAxEEggoEBIIKANZtlIrsQuyUQrFpWTasbp5xtphB\n"
                + "TfqDvQvSsIZzx5YTR6RvK9ljyfJn2UWXyDWBNiOgbZ/9rtzIo2Z4nLxfz9dqqNLx\n"
                + "3sHWAVSrz9n/nergE/MwWVMzEawBIFc8UGe20ST2/G396+XKJPVsl3UzRGqsh18K\n"
                + "n4JOWMKr5Z8qCSERIgZM2kKQjLIRC4El4kCCGDMmCDAEWRYqBJUsSyYCpAiNQjRp\n"
                + "wxINEqNk0EhOhAglYjgwEjKQicBhDLiNgrYhTMRQmDQG4CBtCKIRgiAkAMlMGEhO\n"
                + "SkZx4xgQGhMNDEENgpiIDBIO0KQg0MCAYMaBg5htoBJBzEJmDANkJMRRYsQIirhQ\n"
                + "YDaCCiBJWcJIoAYJ0saJA0QFGBkAW8YhU6YoFCeFWRQBSDaEiaYM1BZtwbIBGqAx\n"
                + "G4GIibJQQARpyzZEhDYIQDKQE5RNSwApYBJKozCIkZRl0CJNQpaMU4ZEAqgAQbCQ\n"
                + "HAVIXJSNIQVoIMIMRBQlITQgCBRIAqEM2kARoYaJEyFSGEaO4whAnChIUzZtITIh\n"
                + "ZDJyTAgKIxAyIjkMCbhEHERGXDiEkEZxShiF2xIN2JAg2RItScSEBBGNUJgADLGA\n"
                + "CMJknLRQzDIoAJYsGMUpCTcRYSYCGRAI4JSEmjZIgRQpmigC4jZugzgI1IZFEBgm\n"
                + "EhFMRLAJU6JkGQQlGYkwIKIRRDAxnEiOo6KMBDgo2MaQEDEEDBNpyzhuYAhxjCQw\n"
                + "ISABIQQtIMdsEgQkgbKJ0jhqAoaRyUZFAEVoSxAkzARxC6FJQRSQCcMskhJB4kAQ\n"
                + "YpQEigZmYEAKQRgoUgaAEQCNkBYQI0NQHAJAYSQwCxmFJCJFVJQsmwJF3AYlHAki\n"
                + "G0MNEjBNIEUJETIyBBYhiyhlkBRNibQIY5JMCQBpw7IIAgdgJAmJzDRMHEdsGaVk\n"
                + "CKUgmTIlYwBMQKYMYgCCxAggiyRCGxMhA7kwiEZshBZqCZUAHBZGCQYtSkhMExgF\n"
                + "wChKAohNUoiBGrNpkqAAIZYlIjlym4YsEaVBGBkKyhgmDLBJ28Ix0JQAFKOFkUhO\n"
                + "oMaEYoYBwQCGSbBM4hAwQIRxUwBiW7SISMKMDAMgAEkSGMIB2BRQEEUJgZiJCYgp\n"
                + "AhhNQogEwMJB0DRKnDKIQDhgnEiI3CZk4gJi4gKRIAUwFElwCMVR0BSOnKZklMBs\n"
                + "YjRSnJBkY0BNCAeEVlCJHIGIxZs7C+a7kVRhGllUuGEPU3Har8mHMHohKNkZBCdu\n"
                + "Xz7vrYueTQ+5vp3xDKiL7xkMUExNQVgEyCmXYfywRgXqgiBSQiHBfbWBTuJiOGj9\n"
                + "QdvMpE37dIXXzw/+BGN1nlhhMneeABzwtWk/NGemnplM6MtjWQ+bElgq4E4j3h9Q\n"
                + "2EuNZKo75cp+TXt84nxbolGwENdnTJOqeoA5rzdvf9PILuNVP7A6MAz29fQhKubt\n"
                + "dSaU50SYaBSJfkK1XhghzCZgxG7DYD1Ebie+QjIbvHiaggZgUWJUjpTXt8g7HjUU\n"
                + "FU0Wzoy0ycYXlBhUcSdr6KcCIdR7bPp04iG56LpZKkpn+iMbZyMMM5WMHyVVbPlD\n"
                + "q2LwZ1eD8xJJ5heJzlcBNxZvhhGDvc0W2/d2wUFLrVPCIAaW2CCJqvM0Rx51/3ow\n"
                + "Ic7tB8103nFToeE8UsAfTCPlLBo3PLzjhtTTQjd/LZBaQh8Uc5g3YJpr3AUoJZ+f\n"
                + "r+qrXRpd4afRM6SDVhcAQOK9TB/YHRSvZQ3HeqxTqsDi0IQl81Hsj2ECHTEKAkSw\n"
                + "ktvJMUMOFqnvluSGdQSovrw+tWEk73VbyRab0cuMlbnwOg4tRmUIDGbGncYDlqFj\n"
                + "p1Dt1LuWC3NvrklDOMhi1yfqiWf1Tm7KSUxHo5GCbxZfkjpo65gv3ayfHsDI7wMi\n"
                + "dpDkLbP3Zudy71zmlcvihYDiVZgbVGiQcHUjssFq85TDUN1ihD+ZG18QHsdFljDJ\n"
                + "Keevw3fP0kji3Zo1MuoNNjkBaaMw9i2GfPrrnE9dbSNlHBdYbVjIk6LBXs1RFIEH\n"
                + "CI/AJAVjqji/rB7jZeskqxGdt4ZUfi7YHbn8qdGPydotZcihgfnKzTwFug512toL\n"
                + "JYZ2sOnalwhLICvMSQmFmZoKMHH8BdIYsnjce9psHe+6SXE/i9qdOv6X/5Q9X7E5\n"
                + "65xFdadJH8xLcQ9jTgkjyKOMmVPioxAdLnMLUeGBDDf+wFksmW1gBVQ51mwrKINt\n"
                + "HNidMbiw6u9zgfbFNPwO120Ran1K3zMxUpvDLWP4hpyIpf/y0rXZVVBeu1oB1d3W\n"
                + "ompEpxdMr445rJHZZlb1g2jHXwai6vX2ik0Oz8N/GvaWYnuqjtTakfYgcRtpruvG\n"
                + "brXPydwHsaS2HDDsg4ZEUydR/qNQKXdUjjabD5QMtOL+atCbQgxFmZO858yUESE8\n"
                + "/DzZTLKD+wbbJDKN2DsmvNCLZdSqf/11DTZDz57u+xnoY688++mdX7LR15aVPWlJ\n"
                + "sm3yD9r3l0uURY1MNKf8eO+G6lyEX279Dz0HAzDRDyV0vRY+hC5fo9VrgGfntTz9\n"
                + "8giZTrmfpwQQju3rt22vY9A31rnHxA3g82Xx7YIWXCZQ5xIbhI9z7emir+3QrrTQ\n"
                + "4ahDM3Vkhcphc4/GIxNxXW7rlBDIyIvAC+nBZAfAaflqUC0LTIp7UzKGNgkw3/0r\n"
                + "NRG42miyoMFYu+HXidLupXsUQ+0wD0QrHuPdOyuL1gL5Ltl8YXfbDYQiPVGQ1Blq\n"
                + "mThHtiBuoCKMo+K7OkAoR5lBEZmRjTR9nj+LpwCp6OX6WMsNPoKkJnslJToRDcbq\n"
                + "aQs3/aJKDV7LSwtIMXWsJVOnjGoGt4k6Pl8W5nAAp2blvIhvZGkSYehmjW3QVz9y\n"
                + "gZcaVeUxUc53tdPT+vWmxmYgWZQsZ+l/1czsSkBJN396J6fjtgKIgCoAvd8/3wUq\n"
                + "qWrri7qH/a1xRy40X2USyFUbs5I2H9suX86BWPLlAa6ij4R3me6tp3mmtSjiLgHl\n"
                + "0NaBeAraaq9fI5Nueg+JKhulAQjSJxl8kgg1UnQb0woDhJXrO+x1kRAzs7bB1j3J\n"
                + "9gj/jFPkpBPcc41XF6sJ4q9qfN+hJ/jo2TcGYMs2DnGHmnKQptL2pksCQkltIOP9\n"
                + "6rmKiOS3Z7yocbBuehlN44LcAx7R9sLnTbFQVPg1JAURe5js3AjZ/YS3+Empwu/X\n"
                + "IPYK4cjvXCOM3sKVer7iT7+rB4HBoR8G+dmV9cZr4DmTw78IUdKcrjSvjTNLGVkr\n"
                + "TuXbgFlc3JvvVb+ZsalOpvSNddyw2xirN/SlX52eLdTJQwbqYYfyCUBmrMqkwOkN\n"
                + "aUlCB8P3PokxZ+UrWngehackFX+KTA0h7+MiaeIl7MLxaE1OFt2acaHoenEAzuu/\n"
                + "CeCjkB/UPuAUAgYEnEl2qLVVmE8M7j2nuDsXzhHxZm89AIpVhgphCZFnQuKBggUh\n"
                + "ANZtlIrsQuyUQrFpWTasbp5xtphBTfqDvQvSsIZzx5YTukdgfcdhJyM0jq2JfIyX\n"
                + "2Nz5zviuq/DSSpz10NpEg3Fen2AEZPEleuOLFIQnlddNgU69PN5KvdoPLBvoYAGt\n"
                + "Zr0RugvfTG0rHIfcrGc1GaSJTG9LjX99yhX7h0CT2QXEkhTW6bYB9k8ktpiI9Whe\n"
                + "Fqn41QJxncT2ItSaebInt8X7M+3VfPtXJdzJQj18HLqKcPx8AQI5bewSgLQD7mXd\n"
                + "ED4Vycze1oACxJK0Kz5o5xmPN+MiYGb8hgH1sOGUXopvzL86x4IIrqYEnUFVTg8g\n"
                + "CvxO6y9/LL8uy/Ntc71yGHPk4zez1PkKOZmF3mJweVVht3azRcAmtmFnBIibqXY3\n"
                + "YwyMWCA3EhObuEd3igvDxEdrAmzFZ8O/sQm64Xa1+thArmKlcxV7Yz4/2AdDiHWZ\n"
                + "8r8XUmAbHcd4YlWG1dhGmlAbHFxukAN7gM/12EdaQYsraByJW8eaSe/rTSO+qT4w\n"
                + "BflT2hk/nEGR/Ss3+Z6CRd/GNHxf+wz/300aBoFsRX692Zchno6jhLg5S7g4AObR\n"
                + "7+hmp1ki2Fm0yGujksx1QdtzZOM0hFOV2MkhUZC7CAHdFGwGKyM246Hf8ASWN8Ou\n"
                + "df7ElTG5OKyCIZFIJ10uYplAMg4ZmzOwr53bTenlameoCGTF4dwZYnPtx58SeHQO\n"
                + "YlPEi9oADX+OKZIS0LwU0QAsH60QavCuoWAHvB5I4zHfKhYyekhls3mejmp+rSI7\n"
                + "DKWGUc2qwS5iEgKygFCeZ6aCJ/5FsIWUd+yVvrhmx7n+98bTY/ic+mKcH903Epn1\n"
                + "d8FTpYUXHg42HBNmNbw+QjJstdwvbfigroB3iqKyB6xFIraheoiuaV5wA74z9lZu\n"
                + "VMKpfcZjrcxSTwmc7bkKIwiweSVCCBOg0SMAv3lLqvhQgBOl3/43jul9n3iTdaJ1\n"
                + "XUM1Cjin3IigbvTJs9kljKV4BAKcc3QbzP5QfMUUSrnQHfp2QjDSk3gXrXncERgp\n"
                + "1IJXhVUGpBWBdPRp4kcNOyT+aA9KOI1KCfrhlMpB3vJm2rW990kT0JDgyAtypmt1\n"
                + "a9xy4Q7D0IcazGSX5NqTZZ+JV4SwgBcqhmx7tw25IjnEiGqUmBcQBrRWW4sg3daO\n"
                + "rfQNHisq7M3MhrvSclF+xAcxxRLKR9p7epKxGj4mOlViqyA+WfiwGZChApjWI2HE\n"
                + "t5464L0lkAuyLssm8qMcXpDp9LLzaeHGeIgQHXqglxVlNlRRdbojYW+CqJiiU+Zm\n"
                + "oFsQXPsc3oyyAU/GUZTcOhlA85yZJD04OGwvnGQ2tsMAENMJu/6UZxh8XzJRb9u8\n"
                + "IR6sr+FGCtaUfkGMPr4KJ1tPlgJXIUfgHiIWXRnTFQMkUgH+weIRCeHYBoL7E5Kh\n"
                + "1wcXxEkNLDu7oYy0BPZ1SiDey3/yMtnSX65i2ZdGOzTSON/XsW2+EnObVJT4ny8S\n"
                + "P9y+RcZZd+4ly1Fmp5JVznT8IDTIuKwsLCXr0zb0bSKoqkHVjZwdHg9Xfq5fBxeA\n"
                + "bMSPatX1j8aeW1VhryhUwgjW+ovIvwZEcBV4Z5yr+BChDW70a4rt0j2qdCQbdHg+\n"
                + "mMMYmLI+uQHT+0i7+DJYHSerXOOu6LfDGiXQ0MX4PDGivyqf8z5Ji+fQzxgHPPlT\n"
                + "8kQs10hQSg8RqlO/xDkANetDWqTK09uHP9fu6j8dqBjCEEeD2/tkZv3dGFuKo7g7\n"
                + "4pWNUkzNb/F1YZoKrTSeA2s=\n"
                + "-----END PRIVATE KEY-----";


    public static final String PRESIGN_VALIDATION_KEY_MLDSA_65_PRIV =
        "-----BEGIN PRIVATE KEY-----\n" +
                "MIIXfQIBATALBglghkgBZQMEAxIEgg/EBIIPwDhsq8oHg7aYKLVlDIW9gkfoO4Dj\n"
                + "xogyEC6MKtOJGCa266hn/kcg8Sj3FNIFCdM46ZK6P6NyoJs8qDz5I0FZ1shxqyLP\n"
                + "sC6tpaMI1SC4K7D6ngcU9XcSENRXROXOlzPCV6wYWADpg9quDaoVKt+APVIccqcI\n"
                + "KTptF6ynFn+MKf7HKBVBFHgYQkGACHcCNnUVdGgEMWI2AHYEJVGGVQFnVyYBIVBW\n"
                + "JoJ2cWhRaBFhEGCDBoQTUQeFMVgyAmFnYmEwaHc0UBM2h2FmIUAAEoMVBEU1ZwBz\n"
                + "cHEIURcigEA2Q4FWcygECGKAJoAWA2UwhyhRF3QSNjI2g4hYWEh3VIJSQYM1hHgH\n"
                + "EydjgAaDRVE1F4EiACAxWFcGchdBR0EYcoQWJlWFCDJwIQFWQxIXgnQXN0M3d0M1\n"
                + "BnE0cQZgYhZzAydEB0FgJURBBieGgBZTMRIEFBhnYXATgScmVAeIg2GBIhEVElJX\n"
                + "A3BCCGAUM3JjhBhBNlSEMARXg2gHgCVBFgWBWCUzBUYFRCEwWBAldWhlY3UWFHYm\n"
                + "JSUjQ4NxEWQRhXEkdIdxWFZhRoeCEHJmFEaESDIGN3BIUzFYARASExYURWQWFAEm\n"
                + "cCc2IFJGEAUWUAJBcQVmOHIFUSh2SAgTUhJDEoNwaIhTQ1iBFwZzNmNSdAZjURCA\n"
                + "ZENYUXMHJUJQgRQxE1ISd3GCdlRBKEAgEihCFHMAV4AYGFZ3dxB3dEMydCNjNIh2\n"
                + "WFUISGFnckZ3gFgmBjJiMIdxUCNmJwQRFEZmNmWFgIFnYRFkIGMYcSZlI4R4ImCF\n"
                + "ZIdgRyAXZDBHgxYXIoEydlBVNiN4MCFDOGMQcQQDQlUTdQMlE1d3gIZjZYQVJ4hh\n"
                + "VIQEeAcEUhGIh1AnhGYwUoYBdFgUBQADFWaCgmMmdGJDhjgXcmFDBCgQNyFkKDYF\n"
                + "MUBySEMyBQCHQzMmOGcCZSaGiHRFZoMxUgAjQ1FDFhB4E4VndIVBUXEAV1ZYcTZ3\n"
                + "JRgEInVIZBRgE2UAIHJlgBJyBEVCZWQIAngYSGeEZhMGJBQiV4MXJGhgcTREVAFS\n"
                + "NYBwJTVXBgIIUYVQRgVAVFZwNFAlQHV4GBEINYiEVDMEJXQnIjc2IWJoOAc0EmAk\n"
                + "VhNHIIVjSGg2JHFSJwh0ZiQ4IHBIY0YGADIXdBdSAHWCUXh3N0ZnKGgwJBQyAmgl\n"
                + "GFdjQIgCQjBlMyJVM4YQJgF4UwKCEnU2IIRmN2NjdXcigEclVBJDJHNHhGASNBOB\n"
                + "ESAjQndQgSJXNmcTIFeGQjAHZUFDUxQIg0CDcEEyR1ggNBSBB4ESFlMxJkaFRncQ\n"
                + "ZBAgZFAohwdEGEIDIhZkMIJwhTdoVFZQUjFQVWMGI0hXRXR3E0BIWFNyEoNnJzZi\n"
                + "ZHd2g1MWRldwgCFoF0iCWGYIZ1UTJEgAARBUhBNhEihoURdWdGAGICcGiAM1EiWH\n"
                + "cWIVYhQGgmNUgoZSNCdCMEhwRYeFRwBXNjeIRRcIWCFAJ4InMwUichdHdWJEdwIU\n"
                + "BhBEI3giUXRDQQWDeEBjIBODUlc4RjcTUoIAhlCEWHBkIgNVNSggdgMQQWEXQ3EQ\n"
                + "RjV3YnhlgGBzJiRSMINWJggWhWiIV4NlUhhkIignM0UoQwdTUlVQV1dwUEVyNWRo\n"
                + "hwUnRlBIQBKBggEHcEBCeAIRU4MlQ1iEF0E2GEdxcyEyYGJSYWZBJ2RDWAAkRyg1\n"
                + "GCWAFgBTAwcjNBQWYDIzc4MxcnKDCDdlQkcBNoAABFKDNUQANCR0E1RkExaINFFy\n"
                + "EhQkIkKAAiFkZmRyAIMlJYdAM3ViVwQngBgQUXFHcQZ0VgQlEBJwA4UXgmgwAFYB\n"
                + "czVQeCUHEEQxFDgmYIEiYhhzRBMzIycWcxhohSA2N0gCQWGHMTKIIkYhIGMhOIcA\n"
                + "FgUQM2ImIAUgc1ZigUNDdUNFF1ByghIQMWhncoEEYHeHUBAkMGAEFgM2Q0FEAWKE\n"
                + "hHQCNDCEQGNFNlM1BRNwFlZFhDgmg0Mmd3EwdVhHBSJkdyRVOEUUQBMAZTAVRRY3\n"
                + "gXV4eDhIVmgDaFF2FmeEYDMRJiNIdXGEhAdYiLqMuSfkE15v7QCky1GGRNVzBZdM\n"
                + "RXg4uL2eexqhc34mR3b9WWpEUy+L80rjU0PTj1GR3KQAkNx0BWNTFjOXdNedRXkJ\n"
                + "cOfr+t5vXEctj4IeVu7RPPfDr92NkATdymOVTOzdR3eq0c3oWPjKVj006hnoUgDH\n"
                + "9d+n7Brhd9+6aGh6D5acw20i5I8ASJt7Tpc979xsE9gE/LJ75eMhChLiCSiEuwyQ\n"
                + "hoRxZvIcI0pA1oCcirrrWbHhFtcd2XQzfGOTjjjoY3PkGwXOmN7KiKGm8FG55Jvq\n"
                + "JRulH3kf+c0yMSIRsuscYG92qWRSfDQbJwAag7XKTpRR1ESTWLJH+cm8HtRDp2yh\n"
                + "m4e5zY1t9il0IWZYOZNNdgtzcBt5FYnzdujJZv9vGpIFZ5CG/vKOl+pCS1MVm+Cf\n"
                + "lIJrGlLuh97eqagruBtlkbkanGCQMzfLGKK6OjYB0Q0RW2pRFXwgmuPTqrCHJOVC\n"
                + "2hGZsY+kA49/43vTVQOxytj98j9S9uK8CGXRDEenHVlCMV0yDFADwm9b/TO0QAYS\n"
                + "nyl6mgyxsLWsDpyKX740MN1xGCJNfEr2NyaUF65TKgUhIbSf/actuqrVD3yldJaN\n"
                + "eTQl42IAXDB8onkiw71LUfccEHKV2vhTZg2e8uybDB/PoLYo1iuLXXxXtpUxk5zI\n"
                + "v8B9FxQjSh+Vq2wXXyXKEAdZo1oZez+6pHJly4BVrCVZgTXbd+yFnh5uyp0bhYId\n"
                + "vErbiQ0bxTK8v5KFtJHbafhVqUf7SdZLEBcWFrDFUNnUplLPvFZgVdN1gDFLVbUv\n"
                + "uGXWljNeHYAVufkaNvuH1anpnh0+nnnk61VF0Ud5VaFNMqLtaxH+1IV9VXF2rQHq\n"
                + "Yt51SlgSGneaV0DPnRSIclkGH4egvGgWYyYaVZWWqFmI+qEvkRhtx9VfAOrZC6kY\n"
                + "ZZu/n0GkCze4lhNynHugN/HIHqOJFw3DKKzVO4uiPjr4lypgILYfvp6znJXHg60I\n"
                + "aBs9w6skTue+eZnrWw1Ox5rUpzvylP/gKlmx2PNhgSMDsKVGKUIRGPL/VbHY3oNG\n"
                + "ZmQ6yMF4Bd/Ay4/Sq0F4wd0Cgp9Xk6/GzY5q8HhnItFwbI9Zg0Mmu9CCDP0fz7pv\n"
                + "HzNfB98GVzPYRRRBPIQVIhsFtGu6wi8RagYJvMePSENJDLaJR1XYuP8qgZ/mlXCr\n"
                + "Orz+UQ/otkUqZP+VsZbWv15aq2PWWneO185KAccTBcraiqnMcaU7qGzYEtxBQnsx\n"
                + "jCDAetoin05RBlLj0qYt62J73AGSxp7uJofxlIQpTr3/mECAINQ7MoCBAMLwCWys\n"
                + "SFqgu1qTnZrPA4c/y3Co2WMYpM35P9vuF/dsVi184Eee7TGBkba8svsu2frUw91o\n"
                + "dyGLVroQBsVzFbAjwXsK0QGMdy4Ua4b4O1LHGiTOYnYqFwrGFA7yTQygfOsXf57R\n"
                + "9AfX0HZ/5QUNyH7TO2BXZyWNFAOh68H51g8hnZZix41ks4hdosYO9zevTQ46MTjx\n"
                + "oi41g98IS3R5NijFaFXZilUrph/ZbPDi4P2qXyfHoxr3efcmmvrksvi+9IKLxTly\n"
                + "aL/PBAkNHy44a0l0ujRk0fGirRlJgNxbJHL6MzvPXdF3r3bm1krO8STmOAWrTUSB\n"
                + "km3oMd444wPqD5DaEUhqP3HeDkdM8Jr2wp9z+Y9Y0vphhtOaxr3Tq1d7QPHqXiEu\n"
                + "hMG4/xt/d2+HYGEO1QtMoYrZfMbp6xr9z8fHHwLER3MEsRtEHCBaWgcO5WxYwEcV\n"
                + "hoZ7FD7AtpnMqgeUzjXl9aPgPiRemlY04nNZjm5EoLFJlR94Z/DP8qY/fuNUJi6P\n"
                + "e91HLvoKu0jz2BoMr/6FQUnKQqDbNskjK6o4Jat0Thf/l0XxIGkY4C1zY2Ut92a/\n"
                + "5OIB5IruQyIewvSNXWnwppKTQUh5P9s594L92o/SDAS9/vUcrPuRCFvp5EkAw4hD\n"
                + "0f8B8nazXGncdeg36vsdAViZ7GJdIVlN6q8pzFAHy+MZwV45DA3MjGllXMRdOVJl\n"
                + "WjR4tQhdKJD2ollpG4KLpEoFKvVe6+15hmO1uJJZuQqJlKqVXrt+sk45zFQc4X4i\n"
                + "N+PRjIWYxbm977r1iBtCOT5cUJtbnfsNM5NsNuCHCdQE1fxY2XDb/zMntwOwFKx7\n"
                + "yWx0CjLjtEt1bKfzeGcuj0Ep7b7Ieo1IoOuM4HJwRE01HvWjP7ZTZbP+iTUi4LVR\n"
                + "kx2q1Ch7Vo5FC65CxICBShNvwdJc0etNgFBmMduFGYJTb5aAvY9M02SIiVt15l4g\n"
                + "M5i31QxxI3Cw5uEBUjtCYCsCMXG/nuheWZBQRtjxrlXqTcXKxaea7Ab0XF6R4tIz\n"
                + "5J7nsMLRuEN6rA6PHDRAzrHJgZ9XQU+Y+Ce6jGGalgvXPwxIgFXacITQZwPDnv3u\n"
                + "i0pcTvXY959/MvT8Z1pv05QnUgzUzeZScMTFdsNkcV+aXNz1MTGSO0L33PBwsNgv\n"
                + "quxHU27Gwj7NsMiq2v1htOR9P2e8nOGPUAi2YQM+8k++eN/NtVml2CMVlpOl7P3T\n"
                + "atJfsxtks1cWtMtSWIIfmyUl94LNewfRZIT5+zwfBxh3NgwJ4orHzMaV7a9LThKQ\n"
                + "Fh6UM2epgLfhvYk+N81H2RVtt/RWesT1wx6HeY/mw6gz6dNqogl7UbPs5Cmdk81d\n"
                + "HXE6Yqru+/vOmG/u2EbIZpzDrjg0EodCmGNxXw67TPrULeBEuSsZKSajoId5JEtG\n"
                + "2XuqDq0JUNnXafCO2g5TXGTVfzAbxOpksHIrRw+WEnl7cL3JWWakCpK0uQ2kESuX\n"
                + "vx8vPaTYaUmHAJqwb5ZN/rqBwAVclsNSBQtAVEah5avC9mxCxGcLqVvrDbYSoRx7\n"
                + "G3IzaUdjRjiaj6y5RhJd1KOYFgtMfK1jgkDYRUHtHAQxvdnGi5G+ehG6EpyzrqHU\n"
                + "a265fjs/577ONrCdl/gUm7kiExJfs0rpH8a83E5OP45SGj85Wlt20uU+gfFCZ64F\n"
                + "BLz6JLlVJCIPDW4ArGgsNrEQqnkF0MDl3xyGecEPW6OioiNvAojdHla4uhDZ/s++\n"
                + "2GD7uEzfa2z3RjhpxloWMfVOmsG6JgW+O4Qej+tw0/j9cPpzDU+TTAVDy1rUSyjy\n"
                + "BuhFfopsZ2r0I4Ck73F5gfj2fGNKTH1BdnH4W8Gv69OC+d57t9F/ORr70XISmAcA\n"
                + "1zLOnnrnSTQd9p9jnS75DA+HsW5qAZ37Hfz7+tRv3jOhoz4Sf/l74OZ8ynzub6Q2\n"
                + "uMyPFPFuyAnmLXomh0ar8MoGnvalBZ4y5FR8mYd0G6UCxA2eAWF+QbBBdt0iSAIW\n"
                + "aLj1cAjIvHlTAgLv1fzBqvXllNjAipv5mN2gGYGCB6EAOGyrygeDtpgotWUMhb2C\n"
                + "R+g7gOPGiDIQLowq04kYJraX6fS8M7O4YKucA+ccG9NwPC9YTiRrPJ1/zY8gslP9\n"
                + "Q56qYQB2xh1mS55B1fXcP5rUZT5RzGsgjMNrjcks+W5tEZNkI3P+MZ3OtjMEEqyc\n"
                + "ooiNmcc3wAXAT0x0ogIXr4V6GOeA5mRRP7Kd530jZs6kvXkzFszAIFZgF5S0IaXF\n"
                + "kprnZjW409qDr8gtLGxjpQCHpPZVM57FymFdwVfQlJC4KOuPjlxiH8pxfyEqaCvd\n"
                + "ZLjXmbycd4OQZivcJHHnS5A3aDLl+E0WN8uDl7i9WMoFtuIu007T2goUhZlqX16q\n"
                + "9K2lMs0iM9Qz7Zf7OJnY1N5d/uV/vdWvIjzkWiK7JeRF8TJVAYWqaLDAjZ5HuCWx\n"
                + "h720MO9PH4fD+AbqBdcEyxtULe9SykVdPIbZYxfq46bUQGUucSRn+5Oxs6HpaQvT\n"
                + "duy79qWbMZsVtvg/o+rcvVGERoRZNwJmYisWYKy+yLlnsVzSruS48kmg5Q9/L/0h\n"
                + "RV8OTo7lxwe77PngCuee332u4lE914IVcefSK0oCgKjAR9G6zHz5xhWzA4hd+Pim\n"
                + "V17FTiy2mdXda+XEkPvusWX2OzB3HlHJLGrxYVOduLjzpnPyhfpW9qDfsBfrwzW5\n"
                + "k8LT/zQZU+CW+TM0a6vUXdyT0o8/s1V/Zj400zgMp3cGfm/RfZrotH7/96YIC9Nv\n"
                + "WMntXy6XOpwg6ukLR9cWdna0ohwMwpsqZOUjmByKfTGmyYeMmnwSJ2eHLoRMsZuR\n"
                + "RHhG+8NIghxNs/JbBx6649JWVVSZI9wv9AVrGmmeocRafd8PwxMm4VMod8s7miG9\n"
                + "/x9huTZevl7QwrnTSD8Nj6iwn319P/OP9Du38GXz3+UqCvZulbPuIQSS+Fkuw6TN\n"
                + "iq5xo1T6DZV4HvEx70Q+ngmGCiudg5EroORibGfpX/6WMVT8kdNuUZuoyiDOB4t/\n"
                + "gbEfmx3hf3bnPzrZwn2+S6gi9jn+T6wNItBnxoYKC5/Fa+JckX20+YQUKue8GzYd\n"
                + "M5E6tO81twhp/Kp/bi3l1aMIZ6BOJq4G8xoQsJD/GufPmsR9hKM7ZOzeNPeaQuNr\n"
                + "OCfZpS6BC2Hyg/47cVNHtIt6TUzFimQ1NRZqF/iybV5vY62gMcf48lPIZTF9z+cv\n"
                + "y3UQJaFAXdn70hj9W60XeCI590atzLAJ1FdQqiExgMRRV4VAs/rEiq1/cUCjOzTD\n"
                + "bSwHBUY06hn3w8KnepVImXxFfPFPUfpreTxFVKGEieUsTErLgkysjqMVJAReDj3m\n"
                + "REzBqXNOP6ywqHQ9RYDIh8cLBTNREwudwpPOkyH+3yHIEbrrI/+MkpwRDeycpeLR\n"
                + "IGJ/5FnOmGZvdht3d3yz+QVcYimYfIpAU1ReJrHmlc97hq9Qcks/zoXesbji85DU\n"
                + "2HExxfsUpxFWaaXzacGZTFfJqor0QtWPqjEcd8YvH6NQKww7y0twCerVDIzyZFOF\n"
                + "EsF85E+7JUXtCgCkB1Hnw5KM3aDH0R7LJA3xQnRpPKHXBjZkWmTx1VpiAx0R7lBR\n"
                + "RQzRkq9m3w4ajI8f9AHqT/FW3gxCZmiunNadJR5LknkpVIdn1B/AkdBPk7x9GZUR\n"
                + "okYgEJ6CCCqdNVK6NHrpGP0o7sqQ9xX9cLw9QUlLFIue5Wce4/udi3AnHJTrcPhu\n"
                + "Dy3fSLLLdI8qlSUxnp2jFQ5GMwOEQe7Y9N6nsvkItbrCv1hziIx9oa80EZlAkdcl\n"
                + "0n2OVJQwEO2Bvxs6fXPH5C7pSwyNPnR9X2SAIPHYMtkCe55wojmYDByyA3vCMvDX\n"
                + "2UscH+QOYl3CgssbFlzwtSjAhlPtwHDZa3u8BjiwxUG+cs9zb0Wtwh1honpSvOyE\n"
                + "pPKGW8UD4GKx86wQmUKxLin0GjFw+mLRxx4lpJ6kU9K6xdlCgCFw8Vnddh2GYJZy\n"
                + "Ntz0zbTEHVxg7yOWl4DyhTCPHMGjJw7RzSKQLGWmnQXQvRLBYdcFowhD1lUUdk8c\n"
                + "SfvZ4vYFLRG0JpDFgzG1/OrK4xoT/xNY9s4Kv7N82OTi52Pqc2g7lQfCUn0+vj54\n"
                + "oHl76Jyfunjklqpv00kvsXswlL0nYEA5ZIXKBKkFrnG/9Vkqk9YWTpTcJzEbB9ge\n"
                + "m0h973sBzBmaoRHrsb8FJZwU8nlpY3+mmfz+72sypBsbDrqukGkOeoOoCYUa622S\n"
                + "Wb9/uyKYg/JHfzv/de9TAzQ+xNy5uk6Ch6SKM4aHh4uZ3l95zFAGYo4K2Dye5qse\n"
                + "5txeQnrMP28xINjiEGNqPOW6+LU4PaczLOhYcXt4rPXfEIlCmw1ihRYn8GnVJThY\n"
                + "jWTlzM0GhwKYz2D+8t9oJAKfeynb4ZhTX0HrlRx/EawSQPOhhu0otFybd1wAfN07\n"
                + "uzBRzVdov2im2sKe714M0GLDlY8BoDKLfPBU6Lajrq1XlyRAJDj4Y1SfMZMOLBM7\n"
                + "gILi3BCOTVBmFm3sBY77dLXLsgyySy2Z2GL2/SVYHTHntmWYExmQ/MJpZjz0FjgJ\n"
                + "hN2+C9DS3YHoSoZH6XKJPHRsvBtwPQeOZiVt8JuWckxUkQ7pgGqkFoyQom/C/cWG\n"
                + "wXevmtpoc0ct4T5OEFRh618=\n"
                + "-----END PRIVATE KEY-----";


    public static final String PRESIGN_VALIDATION_KEY_MLDSA_87_PRIV =
        "-----BEGIN PRIVATE KEY-----\n" +
                "MIIdXQIBATALBglghkgBZQMEAxMEghMkBIITIM4iaT6zo2u44qXai5IEDAZ2+5qG\n"
                + "1oXDt/0wHVzapIzgrDx/U6uWWr/B4OwOAZwT9deTo6rbuesw8vIemvDQq10jlzYv\n"
                + "eHLlO9VrN5G8grWNqnwiUHJEfUyPVLe9t+wqQAYR/wo+BzqcJsoJMfxZEFSZGPQ1\n"
                + "I8lnvKutanlV0KEx2QQsYkAFxDYkGjQGXKaNJKZkSrYtIwFJIaAxAMAEGUQmEZYt\n"
                + "4xAGGrGBIbMNEKEtYDJxYyZt06BRIJYJELVxA6BhGxMBACUgEbdkkgQBQAAqGrNh\n"
                + "GgIl5AQFgDABgKaMG0iS0YYMmriMBJRxEyeMojKRUQKFITlgGkaMGDJooZAtWAJR\n"
                + "1DYAg6JMwqJFQhRR4aYhEEeIkCQoAblIpEIiwxJimqZtBCJqS7BMIoEtULJEI7Rs\n"
                + "YLINQwBwCpFom4BxEkZlJMeEooIhmEIFCJGEGUFKFDlBGDRlAbMRg6Qs0AaIYCQw\n"
                + "0ZiATCQCBDguEreBpCZlQoaECoMMHARylAJoiLBFGkWNEzllgyJAC4gRGjQN4pCF\n"
                + "IpMEVIAkxJKBw7YhJKNkSjQOCacN25ZlG0QymoSBgAgEQaZAEgZxoCIg2sJtQkQl\n"
                + "iBZsgBJsGyQw4ZAAUZhME6UwWgiEEDUSSQBpRMJhk4IEQDCKVKhAGcdNisiF2zIp\n"
                + "JBWFExlI3CYgY7BBk4JtSigh4QRQpLJNpCZB4UIEA5FEGkdNIQGGYSZNEMCEHIQM\n"
                + "GMEFpBgR1AQsSrJRYJAsWxCFQ0IhU5hISrSFCiJtEABxW0SQEbdBwrYs1LCRBDYh\n"
                + "47hwIrMICAIsSyCEGkVB4IIoGzmJg4QBEhYNGKlsUDiQAbVF3DBJGCmMXMABSyhs\n"
                + "UIIJHCcgBERomcYFWsAwIscESCZtURZwiIKJwhKKCQmQ0gAIwiYQAkgywMgtQ4SE\n"
                + "mbQpDBdBmTSB4zAohAhgmJYoCaZhYLCJCLRxUzJOGkkuoBAEgshhTIJpRLAl2kiJ\n"
                + "FJJsCkARYAItgiQEEMBtkhZlgBSSI6MwASkFEqGAjChxAoQQSJgJJIcQkUZxlBBK\n"
                + "gyYskQREiAhSo5REiUYoYpZJUBJGSgQpFEdQZCBSwJRoIYAkwjJyEgIMBBWKICII\n"
                + "IsJgSgAQoihumzBEIoEETEghEDWIDCJiCaBllMCJ40SMGiEiybSJQQggG6VQpKiE\n"
                + "JMEQCbBsnCgEGkli2gBq4sYxXAgtpDgsE7IFwBgCpCIQA0MO4bJl4ySSCqIx5Jhh\n"
                + "WbaJoQRSiUYtIUJtY0ZoUxJIAEMB4MQgm5ZE4ICB5AYIQBQRXCRQXKSNyEAxkLgh\n"
                + "A7VgmZAxCSSREReRYkhKkzaQE0KN05gBkZANk6CE0AIE1IKJhBgmjAgMkcRBzIRA\n"
                + "QIQpCSNGoDSN1DiSGgcOQUAwATRQCkRGAAWCkKYIUjBwychRAYVICKGBYEBqYjhw\n"
                + "FABCkMZQ28IsSahlZMaQgTRxYkhQ2jQOY7JIiIJI2ihIEBZsWAJwSEJMkUgiAbYl\n"
                + "BCJRCCCBTKQwXEiGEyYyE0eIpBIp2ihGATBEwRgJZBYiwSKR4rYRIrltU7QhDMRR\n"
                + "UsCJihRAAieNERVCJAFFAzEFmoQEmMZJ2hYp0TSQ2gQtmBKMBAURgAJMWSKCw0BK\n"
                + "GxJqCkVFoUIIJAYGYkQgyTJGyihuoQZGCReJwkiKyRgl0qZQAKEwI8CMHKdQESQq\n"
                + "oZBF2IBpI0mSw6YkwpBAJMON24ZgAEhiCAZNm8RFBJNoWZQFEwNAGLMwUciJ3Egl\n"
                + "EwZx2jguS5KBGJSFCbNNWkQOIcYEAahJE7AxFCRQE7FQGTCMEKEsykJoITBMhBaO\n"
                + "06JETERulBQJwQiBYhQw3DRk0EZEC4GMCSGKoEYQAcckY0Bmo4AlSLYwyqJxozKS\n"
                + "CCNhRBJNUqhAGLSRIZdxAiUoEZVRYjQsJCVRELdtC8SE4ABSIQcRGhNCEKMg47RQ\n"
                + "G7Np4IJEFJUk5IRB4IiQAbgoGpAkGpdBojaBkESMIkkhIzUgwjKAkkJB20IKGTEG\n"
                + "3LAgBCiCAwhIoCgODDUgnMZRiggqiAKQ0KSMHCZBAJEIQDYywSCN4qBhzDBsCDUw\n"
                + "25ZNECaS0UhMUUgEJUhAQFdutaUNhcEpiV+L4B+E4+izeV62rHBnZvYgzgXbvWZm\n"
                + "1L/lWpaPm+H/7qVx8xJVuPrXQ8AD16wuERLwUrm6rNtiVO+510TvBoPb/TuSEMtZ\n"
                + "yb2pvJC44NDdddWGdyx/kzYTIZS48or9L/5x6leUxs/yvxrx8fsMzWQYQsVxhUh5\n"
                + "vG6JD/ILzHUUHTae8Ls3kVVaIMtFWIdA1TcduHG3OfrIHXh5Sd6StjFP616YDeQr\n"
                + "YKqbDS8uroPtTddH/8ShgV0/aQ67tEhx1eSz3GchCiwGaxlblB6Xc0LPrRpZl3X6\n"
                + "pc/Ar4B+3ClN8oVbR2VVQJ2VoLWulnF//ut/+PP4wwYpCOrVlI8shqr+81T5/J61\n"
                + "h/CmnelskQUwUEGjTxayknBmF16rJkrglZZzycQt7pgd8W/l+H9RsWebf0JKWWBn\n"
                + "uuLIH845yJMv83QHuu2Ok0MhS73s5ZnEbxCQb7zmxUL7RaemoFyDARh+wVWz8xBu\n"
                + "tjd4nTRBfVlJhvE7GVSoxgdlEKetDnJ2IKYkeDELv4UVQlVxZmtfVoG1kYsV1xNe\n"
                + "s6LUO4bRj5G8h7hDdrh4Kg0HEsSZckxy/TEQzVI6cs8bo7d4WHq+xxQ8+OQPAD4T\n"
                + "bQFO3LzgOc2XatdajPVGj3QO2fiVqcegSLrIB+xwclZJGd8yw8kFNO2+ZdVBzV/M\n"
                + "Mwr51GQDy2inR1amACzVvG+ROyFEUirGoiE5k4n/birJc/fEFoAmdvVjquTucqRz\n"
                + "UMpZflWD0L026jlW2XsGUo2dtW3yhD6Aici48G9dx4W2TWWrgz5ZP/ZmwPvQQajm\n"
                + "w2dtsB3g7Aczb6KOv1iH7kS4s5Zan0VJF/nOOAG1ztk0ModJxb56S0yfRSN+3bI/\n"
                + "SkSEXIJxHGUEbdXBU+B5W1f98mFug5Sop6eW+QMWIAGu9aGH+w3IMCNO+LNviNfo\n"
                + "btF9XbwIiWabyu8cLUDjZ+O8XFr4LNhdk0qDyFdYUkmjfUczGK9WsBlBFOYO4wIu\n"
                + "hiJ9o0iBoxlHObDVS+lrkSVolTOFv9OrtW2JKXyJbbMbYoJG6V8zUY/oPmMrooGI\n"
                + "nitFqn/DoS4bNG0dhqM/27BrWTZSip/hSNdR2ODHlFPnXhgsIuSYqtcSZwgaYVqc\n"
                + "33lqUCzL2nVA92+/P+AEz+B8ksFFv0R68YO3IaIaidsd+fafPgsb571a5p2WY+Sx\n"
                + "3zYT+CsD+p1105SeSKoefW4Ia9TeMMGKL6ZY9wD6z41OSNT8WZlVAQhQNdpzGA3j\n"
                + "tUjq7wdqikUluAR+jiWrU4rN8f8Re0q76q+kP0TpSnJQt+UmCUHxGyjgfl766kIz\n"
                + "RDy0SJO/zIwntDIIVtAAUiOVmC89IVdlMIZMzvC2ETPhiiHRK7ya2dXhzRFkt3nx\n"
                + "E67krDcwqS4MGMSkEcHY07y+FDgQFfki2ToyoJTmnB2tW7oq2w4rH52TyyyEzzPA\n"
                + "ZO2IsF74v3fld5y5DMFcjOANBQZMrF+xm9X2vDUa1df9s4aHs35e4DUT3+baQQJF\n"
                + "/ZzYNM89PbWTPcm604hlZWV28kgKcH3lGCAVDZzFT0fQab0rV1dTwdiPU2DtIBJd\n"
                + "X+lXj1aIkdOkAialEz1LK/yI9bIUpVN4AATveo5kLVeONmrVdxDYcAE11pR5w/Fw\n"
                + "oMn+ZJGnC5WNyqFoXyEQQQJ6bCFIC10luQHvKos4CKnZZiNtMEOLK/0ImC3uXaj7\n"
                + "RuIVwoWqKAvNVXhhwcOOZjwrmjDwlRBvnfolS43PXSozIxIvkok16hJctzrWq2EC\n"
                + "muTpZ4eCPceYxynqqHbhhND/AflU73J8r8srLJTV9T1FnULtDOh1/oJ/FmFWtcUA\n"
                + "CkNoMxQ2wv0o/GHgB6kMH/kTGaTgDiecbpzSQwDkqfi8xO3b6iEf/RbnXp6/h7Ht\n"
                + "FI/wIq/KJw4KOnMoRZxUS2G+MOATDkqFN8R6ois/23TSI0BYi8MfSsUQ1IdLjjMG\n"
                + "HMZ25UbrpjbzikJ4bdO+VzFeL5Z7Jpn8QuFfMkVm9YFR7k9v6TUHlXLS2W4TC1bm\n"
                + "62FJxI+DhpcfNHIH6QP832zwzdNPvdLNYhXn+C9dLZROrDP8j8jRAWw0QP9Miqul\n"
                + "NC6DH3KXjCH2ErhkwYShpLBQZMA6Inbv0yCtgAlNhVY3NCseTcsefYEy+byvBiMA\n"
                + "9TA4IJFYAvppwrhXqWIW/UwBzLHEqaxrMrIzy7ZOBOU4xjegWyyVFRyeQRvP1jfy\n"
                + "qL7NFZ9n2Kr5CmaJCLMQKN3oYiZA2R8zJuiM+kprMeDQWv3la0xsR+DG63hIODnQ\n"
                + "+vdQMWgCQR2gcDF0iMkwGvZ/MgcZEggDVZ9Spx8GzmQyxpSMWpa2GnHH5k6DRu+g\n"
                + "7B+7cjzsOSSfYSd3IDJzu5tGGC75gIvO2cXdRSPTWI+Ec2MrGtkQLu1Mw4XoJFZo\n"
                + "RYLqm4oH/8MR4snm5/sSiE4soF5ijyPGaVQq/DorbyDhJmYkAeSqva9S14JwXlVQ\n"
                + "3n13gDIPUduvKWPRAXQGRr2Y9218Bb8SaxE2mV/rmP4AtGM1bLC+WJ4L/tAH+aDG\n"
                + "qL0sB4mosP3GCBrfv7sUtVPI9nVul0+B2gfDt9Oi02tDNNnihwvaZYVNUgLapEQk\n"
                + "zUR52Gg8INE9/rvThj2I50ghcXxYVsiEe2y/fniuAjvBxLRKdDRVHTiAGliKhhjW\n"
                + "/V0K+Nr9tqbMqIoTNmXgqlIQW2LVQvPd1zFCKaw6cqYpwusLW0+2V330fgT6ObGI\n"
                + "cx07W3wsZvvRV65uWY3U1LHzuG1AkN81tH4CSsmvACDNHxvZ6AcQXeHHvOvN/VWS\n"
                + "SGN2h7Au7IneggsioodOL7E0VVchpFdMzuNcgS938QL3K1ODAwuhhtMrjTZDiiug\n"
                + "6BmzyIkZW0Bu6bOXRNzLnZhSw8kkUdf99qq6zTT+ZU513i3yXCT0DCxbq3n2O1NQ\n"
                + "Em2ZOvn4qLnjje1gp4Vbq7B4h222PI2GadiCduS05p6SuJS/rMRIufqYrjmJ/Vso\n"
                + "3Dk7k3zoCYJbZOpTqCjC9W53EpIQ16KbQz7Op1w2W23UkvvjtkgGg0hj+A7hkZtY\n"
                + "87TxZr26CTJzP2wGbaswQnfSW5mT5U+GhqjdYWUpEYUGN2W6rleK+iMrBK8yEhcX\n"
                + "VldBT1VBdVyIyRgCvgRpjbN2i6+uQNsPhDWFHt2S2HFR2Ogoh7xcPXgzfJoyYhUi\n"
                + "FMtqDGs1ThRQmRX+SQeDMGUfnxat5qb0vg63wNOckXJQxPv/RRYPeFKGYaCe3jfU\n"
                + "dnXlDrd2sDirByoJ5o6pWtWmU+v8+WwxLa/P1Mp4TXfP2ArlW5AIhwNbs//AZ3yx\n"
                + "mmfAPsmuRUVOjX4q5De/l3ka60VDXNY741N1fyPI0cGlbZNo7EenmIiLdtdY3RHC\n"
                + "jg7RMlEaDxvXtSz7qg4siGkVmKeyJWtiHbK7l5QP5LYbyAbcSOEkDoBhyPVCAU/l\n"
                + "YuD+kh0ptJG+XMHVyQn9ORZU1a8QDiG9nFq+MEjvtElbAVvOKeMHV94eNIjjRhgw\n"
                + "V3+vHhgrSw/9z6l5A4LDQYmEEafz/9EVK9hEdkEqgavLVc9ox50hjCAwKxAbiKdj\n"
                + "+AYBiU1tJlocw5H3fNitXK3n5GVbGNBrfLPfJuZqshDBCpoqwE+fDljLdkdD7GyY\n"
                + "PTduRwxo3XjuLYF9u59+RwxiXblbQlmryjVCIH1GP3CWOytmI5Zr0YrvNYPsUMY2\n"
                + "WB+XFyj5l3muQYBeT9nJJtJsxLXXQ4J4tE9iIgJntlN6xoeT2Odq5O/UfS9riu6q\n"
                + "t8azumfz2siTXrpPFIc59RsXfkasstSZmQPUnVouIZMsPOHHlcjPma75NaQjGeex\n"
                + "ipir2gwzeJ11f3y0axDD+AQqidQfBVr40F8K5PnnQ1/g3S9DVqQEG56ei88rryz8\n"
                + "L5rLmkURM5cy5v1gTmetytYEqpsQsmDZgKEtBm4XKIgP9LjTVCk7xcbsDsrMql/w\n"
                + "ceoelOazsE1EJyJdBeYHATHal5WyrGwtNHo6QfRSl8VPpzTyMD5AExyIIGaMAMRp\n"
                + "eAE/B/9jfpZYac+k/x09e4Qf97selIrilSSWAXAHenYLPt6STUS9ylemwtm5m2i2\n"
                + "A+4yG/t41MfbeGGvt+mT2/3m6Jx7iYAbTaHEu/SVk1NdRxDfDhvEMFnj02PtoEKx\n"
                + "7Rlpmm9HD+RTV/QvE6cHVADkdz4h0vUq5pJlZQClgRc6RuLj+E4iH3xtsyyDJabw\n"
                + "d+HwQKD1KzKSdPwCmKLXiS5jpojbiGkFnKK418/y/Cq1XxjDMqLGsakYqfEX5X7e\n"
                + "mEVWhAZ2zC9dsHxTdmKqiqYBXc7Ej1MXhxxY4MEO6MzLEa9BpJQ5wurHyeTIa7PB\n"
                + "H2CtXFDQ0GM/qcXJH5ABuO9VZGWDoh76z9j3fBmFJFWvvhJGdDxozXCva6lsy2w8\n"
                + "PFsWQ/bnPxxiIlhBtRNxh78gxYRmXaGVZNHiCoGCCiEAziJpPrOja7jipdqLkgQM\n"
                + "Bnb7mobWhcO3/TAdXNqkjODMulYKdKHBmR/PjldNV5eOwOEm5rMrq6TFDrqlZwws\n"
                + "ZzSy8S3Dx+GxOhMSmWSEfhmY5z3wS8s3YHWN2ZPU1HgPD41Pqz291wgL+cIxif8x\n"
                + "oGgxm4Wofhrw+8B73jUSxJBxxfS5xpOXMiL5Mg204m+QkfRjl7bdJyXFiP/RZnDB\n"
                + "4epYAnI46pd5Pu2NYV4iTkwXZjlSl9qZPzHATahWbin9l2gv6GzISdh25nFSCUbO\n"
                + "TExHmNqBo5B1hyXpTyIDnP/OXehrcELUoaoXKInSoKg3J+DMbMNhqKirH7Cf5n3g\n"
                + "eRQm9Th2IJX4Xhkofi2bTqxh+q/+TLP5A+NPAWNojbP1eqa0LUaSVjhSw+nuhb98\n"
                + "4qEWD2L5vdCrIl+doXT8Go6EdpuceFnZwlsCdOAcOb6a3GLT0mZj1Mqvnd1IG59K\n"
                + "ooT2rpq/HE1SqWiqh72/l8jLXCqzv0nnBP1FLohkNu54IeeIBnzEh/dYi8mGCH3a\n"
                + "HQCArRqmskhEMXOGLhYbXpr6ifXut7foRBWVIEklXjsGnObXHXqimEvWK1Ss8eyk\n"
                + "miRCdcot2d+ZjKLKV07QzB0zi8hI+D1zQXzkckbElxyGkEgeBP78f0N+tydm6vEh\n"
                + "cK/4KP/sGg4F+bsiVtPQkEkuuMLf2n3uAtz9ZRfvtT5YTZ6TNIs6L9RgOeHeMX3Z\n"
                + "WtYVPNlkMY0iNGOQIMlrV9MtQzgizO3WL4l2y+2E8LQekNZa7Ywc2v0hWMyBFIT7\n"
                + "1auGR56+2qpyZcAu047dWOJ6fKpyNJRuvGfbcObeza5VUmETauJiPJZBSSM6gfdd\n"
                + "QXsoKkVlmwXM5Hz/uo7dYUHPaZfMEqt3JcS7Q4C4Z4XSEaLoRp54N1tUjyjrlGLs\n"
                + "W91F91X/EvfdFm68VGif79op5qdBOxkaBm3hEDLufiSvzsNC5p61ujvrKP1Kbbjk\n"
                + "qmmBPIctjfK2jg9SomnKBGwRoMmLNxj0zeCYfxv9/BUtfAOTxEWfcWKy32Gu2K9F\n"
                + "ygaKi9MiaR8BFdCV0g81j5+AZHOJH8k289kh5yxQEolmFZQK9lZoQnksveQ3/RrA\n"
                + "pltg4t9FznHDonTa1eQiTXDYo7BvtGeGni8FO4xDNKKiIRL1AEo5lKhqbQzJyadS\n"
                + "dw7Wz+m2LjoV9ljpyPNKUuFtmDi4f/Nrtp38xgMd7R6+OLgh8pP0eaXzbx2g6x40\n"
                + "wgmxuVwUnG/28Z9k4wisg70OUNT7O4uf3fOKFc5a6l3yMYUB/P5pFn20xIUqg/MO\n"
                + "m/uRY+APbElytpnM+ZeevIadDYTKNNzBlrpr81mn+iPXxuHuN2bykNYvDKnjHFdr\n"
                + "SMZXMYUmstdS4xAIDBtpfdr/uBXUA9ujuz9wMi/3aTeYdRjI624DQbMbRohLjLBl\n"
                + "TYAkRsPjmShnEOLH6ozI5Pyl7jUUq5fP8LAY6fcMx2k5zMYvRAdwqRekQjhT8DwX\n"
                + "/vBhuRFp5NqkRvEtY8bsLr49MG/mXVtE5/vlKHUm5AVvTnUkYGJ0jAs0+q6n4+5w\n"
                + "dirZQP05nkppEq7h5BI/370Wa7Mq3VVipLOKRr3MXYp9K1IKFH8DXUxCKE/xMq+H\n"
                + "F5svvKbVfIEhBhGJ8s3uwkeZUWNneDwVD15TObYqctVRn/YSuZhwEQH8eLJfbLil\n"
                + "MOv4FVVt3Ft3p+la25lmaXpHxGLA/q8eiiGxhhic31/XBCAPM9+yLT8qz+uE2+Ce\n"
                + "yzFlMKD5355yRkJWKBsYb3RFN6j95Nv1y6VrEtEMWzoKl3k5LqFajmniNdj9X2ud\n"
                + "ozXX5k+Ms9roo2mozzLfgsMomt1o6rhBd/3xSyRvVB2IwMjT4hncLB3jwDQG5UIn\n"
                + "Awq3OZGjeASpBX1SbBwh9OehDTyVmUToiNAm2JQkc+t8pVSEtKj6kiCW/uOTnz9O\n"
                + "usPC1X+z5jBQdqnhKk9pE7MCqWGjNGKDFtWfHR++aGxVEyQzaiko8a5IjzF3qC86\n"
                + "hUjU+EBQuBefh5cWUVEsHm1C3WpTdP9aobqlZ/ocRdRFf/oPSxOF6frzYDhJI9TR\n"
                + "eFV+ENXRJc2S336mFtwL83sDBMn9uf4gbnm6Hd+y62p8ID7YcI+x/2KZNu0BP3pj\n"
                + "PgoOcN+xJXkmqYaQq2/v93f7XgFyB1QeQdvLRp27k5J97sU0hu51MIILwvo6EIvp\n"
                + "i+hdP7SFvFlPz0tALa2DuxihaKCOo83EC3smrdcSAfuuw/23Kfe8iHEjOJ73HHSh\n"
                + "wUpdmstno2H1AHanUzD+7Ij5y4WNKCiuHrFwWHZQC45UEBlIsDknOhv6c3PGw4Al\n"
                + "56ztjslPZhjHY4FNjAa6ljVbOZXjnUIC9WLkHmGMuZL/CR2TMfbROAc+qNoRnIou\n"
                + "x5FdtU30TScZ0uzt4IszYPMizR2rtTRsN1lmlYDC+ppp6VSiFpnZuVeCZMXZQnhI\n"
                + "hhZ1eZ4yTNUb8MSvfvHsI4dSZ60dAdo/sdu9ubOihKF7vocfODaoqkrdX43SgqCG\n"
                + "F6a5lIy42Gi055nfS4EAJlyHipaJSASArgU7U325Z2dCxsBwi4yqv7IcsH8qq6aF\n"
                + "JIXGEEecnXEnptbONTOYuVqomXD1orjW5LMMhfs+8m6DAxA2+DQekI9GfTleSLXN\n"
                + "V6pyNczvtmocxtzCOpbiUcfzgMdxtIvzfdKyZMr6XkZLXAzLeCZgjG7fqtaQ7VX7\n"
                + "0oGYAI4hjVa4VBEVy7U6IwfqBle8ons1lmYfD52BvNEIuTgMxWmoB/k6qMe2uiNj\n"
                + "w4g8sItXqhuyVM8I/W1p+mC4rclFfa/kSo4TLPofM7hh3utkEa2o1smYjsNiqNX8\n"
                + "LkwWv4M/f3QEhtx6PL8JZs5xcXHOI16eDX7uE/WWHf3bqH4SXw3LCCeq3GLOSVQS\n"
                + "p0yV3nsGTwtKNmiCH5C8zjESgosyR950t2xcUoYOurAaEH5ZZT9jsCuzj7LzHfse\n"
                + "qAdOHnLiAhX5hy8DfiaSAilsepoPJTEebzQ+BhPkWCP+LNQTTtv7CFJHpPP4iIhJ\n"
                + "+PZDnqTQg4stN/Gzpt34rRq3NkPlrBzHsK9AiMEEnn8jDI8xQqrRnPnkU66Q4zB0\n"
                + "foDw5XET7sefB+jhmIKi8qSs3EgrenUkO0FHFhcFzpSAGVZDZljvDG7or4BHGcq5\n"
                + "/dzYMjt7FjFU5dNyVRS4WwU1WlfSHuG7CtsfF5dtULSiFsVnm+u28qPCOsRHC8OC\n"
                + "SGu72FYmmsz+Q8MXq8DGYoUC7JuQ+U1PLPKJYLM/BLp83sw2kroPg26WjBntHcUm\n"
                + "1+NLr6CSc9UIMu9hNsbH3fGJzxlism0Hc7m2GQBcwPDC0/v0m4F7Kkd79KS8jikm\n"
                + "mUjq+gN+AstV5YG6JJvpj5//NAvjYuTYNRCDJZ+0ACSgvyaMKErklqhMp8E/1Jst\n"
                + "L7LsxImp6UTNSiyROIReLgiOdSS+WgeN8KGo16272sGU\n"
                + "-----END PRIVATE KEY-----";


    public static final String KEY_EXCHANGE_CERTIFICATE_SDN_ENDING = "-Xchg";

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
            case AlgorithmConstants.KEYALGORITHM_ED25519:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_ED25519_PRIV);
            case AlgorithmConstants.KEYALGORITHM_ED448:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_ED448_PRIV);
            case AlgorithmConstants.KEYALGORITHM_FALCON512:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_FALCON512_PRIV);
            case AlgorithmConstants.KEYALGORITHM_FALCON1024:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_FALCON1024_PRIV);
            case AlgorithmConstants.KEYALGORITHM_MLDSA44:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_MLDSA_44_PRIV);
            case AlgorithmConstants.KEYALGORITHM_MLDSA65:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_MLDSA_65_PRIV);
            case AlgorithmConstants.KEYALGORITHM_MLDSA87:
                return KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_MLDSA_87_PRIV);
            default:
                return null;
        }
    }

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String INCLUDE_IN_HEALTH_CHECK = "includeInHealthCheck";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String REQUEST_PRE_PROCESSOR = "requestPreProcessor";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_USER_STORAGE = "useUserStorage";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String FINISH_USER = "finishUser";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String ALLOW_CHANGING_REVOCATION_REASON = "allowChangingRevocationReason";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_PARTITIONED_CRL = "usePartitionedCrl";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_LDAP_DN_ORDER = "useLdapDnOrder";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_UTF8_POLICY_TEXT = "useUTF8PolicyText";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String ACCEPT_REVOCATION_NON_EXISTING_ENTRY = "acceptRevocationNonExistingEntry";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_CERTIFICATE_STORAGE = "useCertificateStorage";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DO_ENFORCE_KEY_RENEWAL = "doEnforceKeyRenewal";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DO_STORE_OCSP_RESPONSES_ON_DEMAND = "doStoreOcspResponsesOnDemand";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String MS_CA_COMPATIBLE = "msCaCompatible";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DO_PRE_PRODUCE_OCSP_RESPONSES = "doPreProduceOcspResponses";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String CA_SERIAL_NUMBER_OCTET_SIZE = "caSerialNumberOctetSize";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_APPEND_ONLY_TABLE = "useAppendOnlyTable";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String CRL_OVERLAP_MILLISECONDS = "crlOverlapMilliseconds";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String CRL_NUMBER_USED = "crlNumberUsed";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String CRL_ISSUANCE_INTERVAL_MILLISECONDS = "crlIssuanceIntervalMilliseconds";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String CRL_EXPIRATION_PERIOD_MILLISECONDS = "crlExpirationPeriodMilliseconds";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String POLICY_OIDS = "policyOids";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DEFAULT_OCSP_SERVICE_LOCATOR = "defaultOCSPServiceLocator";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String GENERATE_CRL_UPON_REVOCATION = "generateCrlUponRevocation";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DO_ENFORCE_UNIQUE_PUBLIC_KEYS = "doEnforceUniquePublicKeys";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME = "doEnforceUniqueDistinguishedName";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DELTA_CRL_MILLISECONDS = "deltaCRLMilliseconds";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DEFAULT_CRL_DIST_POINT = "defaultCRLDistPoint";

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_AUTHORITY_KEY_IDENTIFIER = "useAuthorityKeyIdentifier";

    /**
     * List of supported fields when calling the WS createCa method.  This list allows the caller to set fields
     * on {@link org.cesecore.certificates.ca.X509CAInfo} during CA creation and may be changed when new fields
     * are added that should be exposed to WS clients.
     *
     * @see org.cesecore.certificates.ca.X509CAInfo
     */
    public static final String[] CA_PROPERTY_FIELD_NAMES = {
            //@formatter:off
            INCLUDE_IN_HEALTH_CHECK,
            REQUEST_PRE_PROCESSOR,
            USE_USER_STORAGE,
            FINISH_USER,
            ALLOW_CHANGING_REVOCATION_REASON,
            USE_PARTITIONED_CRL,
            USE_LDAP_DN_ORDER,
            USE_UTF8_POLICY_TEXT,
            ACCEPT_REVOCATION_NON_EXISTING_ENTRY,
            USE_CERTIFICATE_STORAGE,
            DO_ENFORCE_KEY_RENEWAL,
            DO_STORE_OCSP_RESPONSES_ON_DEMAND,
            MS_CA_COMPATIBLE,
            DO_PRE_PRODUCE_OCSP_RESPONSES,
            CA_SERIAL_NUMBER_OCTET_SIZE,
            USE_APPEND_ONLY_TABLE,
            CRL_OVERLAP_MILLISECONDS,
            CRL_NUMBER_USED,
            CRL_ISSUANCE_INTERVAL_MILLISECONDS,
            CRL_EXPIRATION_PERIOD_MILLISECONDS,
            POLICY_OIDS,
            DEFAULT_OCSP_SERVICE_LOCATOR,
            GENERATE_CRL_UPON_REVOCATION,
            DO_ENFORCE_UNIQUE_PUBLIC_KEYS,
            DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME,
            DELTA_CRL_MILLISECONDS,
            DEFAULT_CRL_DIST_POINT,
            USE_AUTHORITY_KEY_IDENTIFIER
            //@formatter:on
    };

}
