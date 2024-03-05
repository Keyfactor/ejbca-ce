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

import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;

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

    public static final String PRESIGN_VALIDATION_KEY_DILITHIUM2_PRIV =
            "-----BEGIN PRIVATE KEY-----\n"
            + "MIIPPwIBATANBgsrBgEEAQKCCwwEBASCCgQEggoAZN6/WWPHjOOxc+9Grxm01Mvl\n"
            + "3vaNZyjDlRWlQ+puvT8JH3VgZtu0uYNdNOwyd98NZ6iJuttm2PS8ZjZYyYyi6Q1a\n"
            + "paomaQsdeSCcJnSgh8pVlWOcxmZqAPdSStKIRkEOpxNazi9z4is+qw5s2Mh5pFVx\n"
            + "8lakCuiw3I/zESkB373UGArcoFAAsoQQtYUJCUlLyC0bIErEFCTIFErYFi2LSFGE\n"
            + "tAzURoGMMoUjAIXDFJBZQipBEIICwIwJQSYAkDCLMEEktUGTNI0iF2nAwDHCmHBc\n"
            + "xA0RF4nMNA7iJoADRC4QMSRKFAGhRGDbBBHkImpJpG0MNEzjOEXQSCZakC1YpkFS\n"
            + "AgQBkGliGAwQNyETNIRKti0bMAYQlQgQAClRSG1EKIBDNBIjCArUoEwDAClZKIkI\n"
            + "I2HEFgJAJDBaxA0RtghUMCRJEkpAEi4kxCAcuInARkwhGIGMMEgAMgogiIWapHFT\n"
            + "GA4kuHAMFkjYpk1SSEQYIW2ERhALGGQiM5EiMkjUgiUDQTBJEDEJsZDcIG4jIyHg\n"
            + "mCnJNE7jNokjwkHSBm0MN1LjqGGkIBEZNgAjMWggFmgAI41CuICEppCTOGRAtETj\n"
            + "uAwBQWjJMG1SpgATE2VKSIwcKEQhpSRbJk1ABJFLQIAIR2gkEYqZIAwYyS0UICzb\n"
            + "mGRcNGrkkgwKpWCkwkUJp02LhEDYqCgTNCQDuCSJkBEagYRTkIkBwmEUJUCZRGJB\n"
            + "smxbMG6KpEwZKQHjCAwDA2HcwhEKEXAKEyIhKVKhwkEiQXLcxE2EhEgQiS0EKQAi\n"
            + "RSkjA0IgwiQSOIYUSE5KRk4iKCFbxG0REohLAAJUNgjDlA0DpQQaCCqUwCncyFAc\n"
            + "RWGcCEUhwIjStGkhggHINFLkJAqZNoKDNgUTGHDaFg4hljBckkkalAkAMVFARAUL\n"
            + "gigUhBDTgpDINoERMYIiMi7MCIAJQi5YImQbNAISQwlEEI0ShUESFowJRRLgSCKE\n"
            + "JCxgxhHUmIAigTCKRA4jASgkhVFDsAkjoVAcR2ghRQ2gwmFSQAJQFmYcpkFUEE4A\n"
            + "RAKEhG0KJQAjiA2iJjBJAg3TFo1gBmwhNiFjxo0ks0EAxoyQRAQTkCQUQGgDSUwY\n"
            + "E4YYximDCGUAIoXhoCnLBIIbJYEhh0jawE2DhGTilkWQRGDEFBEhR5GRGADQlmFk\n"
            + "MCykQmQQsESYFA4IuEw2x/Oy5VKDpDhlkElQyN0o58kpVYCltOKIOPq+RffoWiQY\n"
            + "1nHWosGGzpNphmE1r8O6O97gxyIQT0aSHcJR8Ac9TPGjXeCWfZ7gu1+LGbGoTNFw\n"
            + "rMsNEC9pk+sQSKdA/PxO6SzrRD2G8Z/oRyvbgIHgQj17oj/GJkBUuRXpq2AC6zKP\n"
            + "8FAlPbjhiD4YvGVfu9Wkr24ThZWIko/HZeWlD20L1vdGubt4kanq69UGqvRi3S1u\n"
            + "Wx/BYiQqYbutHVngRg1qOPWiBtSCA76CNmz1HCmd0TextUpSx/+xQ+ycIm5VHyu4\n"
            + "eWp9IafzGA7rjyl/rdfGUXBboB2kDh0ESEm1ChYudImv2NPZWZYl3Pc6XN6X84aO\n"
            + "GYG/GC0dgsocgUFL7UG59H1jjWH//F4H3PcAIvrgbzqXefFFQXnimdwaUevZ9gmZ\n"
            + "1ColJk3qiBLvvklWLh1efkTgXkmycnS/0v5vFx1ENAoQQ7KlKv1Tihho7ruxiWv8\n"
            + "lmja2lt2Ct0hxa2bYuzXF5MlNoFocEcTFrDQ1jRu7im9K7qgFuhcleS/U413nZMb\n"
            + "/eu7YPdaMNzCOjKrIhxi3qECIUBviJvC+FtI5xTDKYVea31k8HcEo9NcZ8nQ2O0G\n"
            + "pPxnm3vZxDIzbVAF1d3yrUa0f4hYYgjnGLtbYPs6+WKCCocsRl3Zp4upvg3fd2qr\n"
            + "YbhI5Kf0qPyjYOKUwP6KGFqqkXUMKRsnqxLPoONC/KoKITEuqhUZ8x4/rlg8pBUj\n"
            + "Y0kGYMaOTsTPuJgy5oqTDGd2MU2PdD2oZvJpAeZ8kQ2YdOuwVBdkWjIZY9RzGIkq\n"
            + "1Hb1XBkMPnrhm6OxAGrWYbQB2kmIBgglnvbx9cPLqMyYNskhjInBLf7uk/KQpRYR\n"
            + "tg/0ZITnvxeuoPpnD//tG6H2lDE5ld9FWHNPClQjZtWdYrLX+pVksrEPpj8IxPbf\n"
            + "XD1Ph92YN0wDYoiDKAbvaZqrHGfwszStdFppVVcXWWijisCNhZO7N+nAPMod6WPR\n"
            + "O/KWVjggT2f15e8uR+a9o6bpo3jASFqRTMjeS8LZhPTGGvaZlOMiqYcuDA77zglo\n"
            + "PwXyKXrdOuyNcdkCk7zUHzINGBVR+AI063Suzp7hFrQTsrt54ao3o+fa364Dt5F+\n"
            + "TcRxzhzHO4krWDtJ+RVhw3Ug3oh/AYgAQqOHWGFS9rNP/pbDV18veqUNBFGur30F\n"
            + "Ur8PJKylXT4LbFV5ZQKh8ybUWPcwNjr5id82E51oX7Oxa5ygOgaI2OgipuABfFcN\n"
            + "8fCm5ZxszwuL/oCBdwuEk4A0T89nr8lav+4mpOMK+6CM2/AAOXaLyV6ue0yQayZb\n"
            + "HufwgWhy5QcpMOEeoASo+biACiY3KR/AeENU+HITa2AMrh4Hr3lzDyCATDq1iGG5\n"
            + "eZVvcAhAw5korIZ69UP2IFMpU72kVo5LKtj7bClEKvd2wjqecri9GJgSEo1FmVwT\n"
            + "XYJTnTq7vr35O6goptnFMoM2rhMS9wp5ctR67x8r6cvUzlPbtRjv1FcICHdLEjiM\n"
            + "HSuhifRpj1GadyvVoCtnNXuXCLtu6zYjBu7liWKrB41FGlvMUYAUG8F1FAvHrFZI\n"
            + "KsVKwKmUnYH8cMA6ylRda3vTueAsSJqS90dncAXaYQqA7WQCy1OQzbLEel+21FLy\n"
            + "++Kq5AY00OC6Xr3D3Zl+jcUhOeafFzH/MgKvEQE6KfSUVdy4wlfVxI+uyBzvTJhY\n"
            + "mCDF36Tsdr+Y2j39LXNOE6p3O7C6cnPhKwuKtcTKJHcOxF8fHygEfC4pfGDjoZ2E\n"
            + "oLVOob2te67850BnwAVUIf8qGxOgfFRQNdtJtSrd3shHKdfVD3bbobmFWS9wWkUq\n"
            + "0hqfR0SdOv6AtZ5V9TyjYSiNPRE6vf+KHSiJh6jEzQlWL38MUpNXbTwdhusi4DTP\n"
            + "DwU8XsiuHTkTyz4eJKvcUHcUzGejwQJTOVtlowPVBEhe1WzP5n0G56FUzRPhODZE\n"
            + "1UyMMS1APLlVqr04YGpX2P2eFUz0GKRYeEKNDJtQhSaK9RueQFOcB+22oDbZ8Kdg\n"
            + "qRfE1SPMx34UbnMowsWNTgHD9VK320nKwzBeVCp1oRhFMzTdRpyEtSRYt7knKxTL\n"
            + "mY8Aw6fzcBGnwcGEAYyTIk+wCNANgkQcjo/ib21MQPvdZapwfuFh5jdpztaMTfRg\n"
            + "Jx6lwNF7U3EQznj6QSBDBvVTtmm/rytzXR9WurX3I/BQ0eILzfCgfEV0iBXM+IGC\n"
            + "BSEAZN6/WWPHjOOxc+9Grxm01Mvl3vaNZyjDlRWlQ+puvT88/Y7AsnIwq8WYkzX6\n"
            + "Is/GLNej+DwR40jHhGxva898bOCq8IUe5BjChg/R41OMHyNLPVQ6SbE2RsfUyrGe\n"
            + "2nc4anTrNMOIUFwSAxGFnbQatS0cwGROJ9pYmXOoZMYrGIOAAj76VRRGruY6GaTB\n"
            + "qGRJdmJ6ayUtNIWoGCD2zWE0JwYWyLfNuGXzXp2FZhLKnYTg+cjf0I5HfH0IGQJw\n"
            + "w875BcETcKxFv1+uPpPTZ2VAgfxAfcA9XsUzDIaEZgNrzeSsLV/D/JybpS+zQ/C+\n"
            + "jHQ4p/m4dpd0uPNg27Yk4HOE6HuUlQGrCiWr20xkqkeWOYZYd0w8kNaODp/8IKTR\n"
            + "yvZ3+LeH9wA0AnO2G7CoPnVUCGrRDjdHUBGQe1L4QoZRJyTukLChaN4fZfMVAp/4\n"
            + "17Ckvr85pe+WDZflQU0z06tjf7nWLCkdp32lmaWg6OYmlpocMd8hE0YkyvaU3VSG\n"
            + "NpsWbC1+b20HiumFTZyNRBg0XH4nPRyXntJdPymx+uERMaMMT+UUspeUSeP5tZrF\n"
            + "tFZkV8e79j0ffaR6zGN2RsIqeWF1VFwewXecYREuiTtv6iuRaZswkiQc7o5bxuUv\n"
            + "7bsaNlRxD2S765VM+AHKVXwesa7EUdevXzB+v1eZbeXQ9tSKcww5czpuDU2tQvRp\n"
            + "A9yx6xtDJxS2sb78VqMFQbF1nzyaFcvb8v7HoNBHcdl+/V34Z8Xh/VLrDcNL6nC5\n"
            + "BDlyJfeqxLPL33TpQV9rSNHYOkmyokRHNfsecla+wHVf/Qf433RaSYLUClhDk6MG\n"
            + "f8kqO1rnkRCBtKWajUbeitV1BWwcKNqNaGT9UGsXSKjIdgDeqxrcztZAQm5hAbHu\n"
            + "19DqJ7iTb5x2juIYsY0FsOpz0qvcqx2VOsufLPS5ZsQSEyAwCyZFv8r3undLe92u\n"
            + "p+Nckl3WJUrEx7utFVI12pAPsL+1ILGGEVrvBd5E22FaxQDQajUxTEYavZiAi5u9\n"
            + "6Xm4Cf1QYRv4F8vXvzEYjzgVqxYzMVIeMDp+EYMALeO0tYc6pNWos9wm6TuMn4cf\n"
            + "UKKXV2pcuft190VGAdTiIEfbS0q5vE8X4DbYSRMNB/s8VF1sYwvTfDSTPXmmHBqe\n"
            + "hVMvzJXYeMHTfhdpZ3j6POVwflOnwZRVj6qjOppFjIW9H1ajRE2SgRGCL9mgG4+l\n"
            + "nLLu8VSIsQT4GfsgLz0jrbW69/e4Ka6xa5YdsDoq2RXTfzFIuLs6+mvj7tn2TWKd\n"
            + "1YgZb45xcQvksZBgMYsaQ/aMqNXo9W2P35UfjrdtVhiv41aZMX+88O8+4fibUfcJ\n"
            + "OtBuDZxp53azUP7+wIa+W6TUrLF1o2X4mzAowAs1v5EWN+hF6ZAC1ltVRjc8RjcN\n"
            + "zugkG09EuICtNUCm+jG4HMd2QnjA4ySdnEWYe7bjDBq9123+BOVkWRfOEYGvdByW\n"
            + "cZgAf9UoB0W6xEuPiooXbEX7X9v0CM0wNNBPf3ETKMswbXLOgJmbqof7yF8s963t\n"
            + "Wsv36J6Rebk7LGIafyGcY4k9v+UQ/s91OYoztVtrNNfBOCiXq3jE8pUuNBLwAT7t\n"
            + "9WjJz3bqOj9wbYvhgE/l1YVzHAz94VFsjX9ZnF3NBC+PV8wcBbdPyVxoBkrNNhcr\n"
            + "A6YrVUGf4P1Kf+kxUUsGJutS7j/zloukA55y+AhXEpMAuo9OJQL+G1Di0omGKSF5\n"
            + "e4x374FxL3/YxZcI98JAHLncLQ==\n"
            + "-----END PRIVATE KEY-----";

    public static final String PRESIGN_VALIDATION_KEY_DILITHIUM3_PRIV =
            "-----BEGIN PRIVATE KEY-----\n"
            + "MIIXfwIBATANBgsrBgEEAQKCCwwGBQSCD8QEgg/A1j1Cp+0uoJT9MjCxi66edirA\n"
            + "kYT+gcPzcozNg2/doCsOwG55SQh+YsBb5p1Rz5E2Ix6+wBFkXvpIwC7Gcuyhs5as\n"
            + "1AWT9fbulftOdwguf7mliVq3jotMmmoG88IW/MOZeQqQ/+QhuLoKWrnVRiRa+tyG\n"
            + "jZtDgW4iW2uenfMEw4hTY3R4MXKGgzaFiHWDVXUIeHF2JBU2clJBcTUSgzeGcGGG\n"
            + "BlFSEGR1BgVyiAQFJ4hGZzJ3g3aGVXUwCGAjMSQBRCWGI2hieDOHYRVnd0ATg2Uz\n"
            + "doR1ASCDYycQUgdyAGh2QCM3dGFIRFRgJVdzVXU3RAYDBoYyR2cYZ2hQU4V2FUNg\n"
            + "QGRXg0GHImMkJBaHBQZ3FBOEdTQUczdlckKGEBCFUThSVkiFcGBweBgGcYhjIWiF\n"
            + "NEUnMHJoBAcRQVKGQwR3JWNRY0hgAwFwckeGd1FkNWYzaIARZkZocFEnAhdmEwRC\n"
            + "SBhWWDAxIiWBYjYDF2JgaCBnVlE3QDRhd3FVMmUxE1OIVDElhFNwRiYBKAIYZhZQ\n"
            + "RSEVdFFYUHM1MzYhQHAxaHMyJRMXYkWGOABEUBczRjFCIDgxAoVVOIYYE3gwYjNg\n"
            + "NyREcVN0A0AHhiWDgINSIjZjF4gGEhhlh1ZhRAVzJTh4UmZoOHFxdyQhGESER1g0\n"
            + "V4VwB3NXeAeEcQQ4YRcgKBdohlZEhSNyZEUEBlNmgQeGFiFmITc2VnGHhQMAhBVY\n"
            + "JFFGhBYwRGdQQ3dyQFgFSBNDMnQgMDdEEFRiE1MzeBYVYYCCBjeDNyFAclYlYhFi\n"
            + "I2IBQHA4WBQ0JYFXhIhXESYIKCURNYBEhFF0WCJlQxAChCByJXR0gicAcyR0Z0R1\n"
            + "VDJAAzMwGIE4giU4aGMFZgUkYYAyUidEdHMViENRIYgXiDgUEBUTZWRoFwVwZUQm\n"
            + "RUJiJmGHF0RVQ3UWFGJFWGYmNEV1WIADFVAmhlJiFHZlNoBjhkZxEhcEF4gUYQZQ\n"
            + "RQZ2cDF3d1ECc1CBaAhEUwMnIVVkh2MRQ1OHM4aDZXJmBhNAE4F3cWZCUxU1Q1Qg\n"
            + "dVIwcEd4d3Q1ZnN4BVAIMwAAQiRjZHUBMQB3VhIXJFdkeAMiVGVVRTZ1RzYEcESF\n"
            + "FyU0IyU3NWZxd3YQQXJ2FgMwUVclEzUlCCYCY3YQIAaHIHJ1WCF0JiFWWDJkFAMW\n"
            + "chOAcCUmUmY4UAMVE4FySEdVFzKCA2JHETdmA1gYRCF2gSVFgCdnIVJyQVUUREZh\n"
            + "ImVVR3ZAaHVDhHcGBHF3NyVFARIgASCGgxUyM0glMgNWiHJjJ4BGYBdESIhyZXIk\n"
            + "VxhQR4E1IjYgJRCIN2UwGBB0NkEFiIZoN0RRIjd2I1FUNkdUIFJGARWFdldiQgMT\n"
            + "ABYAECN1VzRHgUBCZhYAOIBxM4BiZoERQTBSFgdoNQNRdSZoQFZYgyUEVgYAZUAA\n"
            + "BzVCCISBaCRlNTImBCNBdjeHMScmM2dyBDAFNwU4SEaCNYGHJFU4YTdyYDJldFgg\n"
            + "cIc0U0UCVFgzV3BIEEBXNwMTZ2YWgnVmJFNjMSRyFzNnYIdBJBd0YwcQBoRTRhI1\n"
            + "QhOHgVY2YRZ0Y4IjR2NiIBdRhnB2JoVYeEFYVmARUWB1VkchEGNFhkGCN3RhhggI\n"
            + "d2Vgg0MlE0BUhiFCMiRYABUQFyViZHEoN2UTFmiEJYAEgRcmAlgGNIBFVyIRIXEk\n"
            + "FCBzM2I4iERlIjeHNncjRXZ1QXI4hjIlETOIUxQXYwE2EoNmQDMSFUZUV2dTRHVX\n"
            + "cWJVaBWAMnNhEGNFNEF3AyNwBkZjdVhAEkgQZ0coEIBiM3FxNTdUQ2AlZnaAd4Rh\n"
            + "hQQHZRFRADFVgidANEKIU4dBEiNHJiIDMWY3AQYiYQKIUYgVBGaIaIRRg0AkJlIE\n"
            + "RlBGgFgDQFV2ckFGIISEZYIQUhRiNhU4MiU4YDFQUgUzN3M4c0QghSZyJGRigVco\n"
            + "eEFTVwRlYyB0Q0NldTcUcQMoA1JlFyYFQFMUE2gSV1MCeIGBM0aAI2Q1YlNCMIZ3\n"
            + "BhNDd4JQNwAjQkhgUThmRmBigGFBUEgFcUEmIXeAfUl9ayDF+gefARmhSglPlxJN\n"
            + "1a4shLWfq4sL6+j/REVD9YctEr4Ex5ywYAuK/WNWfWXZZBOpONcEhPClivKPjW4C\n"
            + "m6nAvqV5+a5b7BgTv8jecguZYyL5ujTdn3wzbZ5c6a4t7fflkEvBbLVfRUYxJk4r\n"
            + "p6mE0enp1Ecj3HBNtkjs2JUKK2UKYXOcWtPhyKUbOJ6FVtOlJdprx7MSY8tK6RXv\n"
            + "ph5pRwDDWZy2bxtps6S4VFCnY1sfOkcPgixvVhUnhFhBK9YljHHYdMocnNUbtNl/\n"
            + "ZpdzeWjLEgtKpawsCIkLPWNEx49QDdzfba37rcb5oGSXV3csp1ZB5GYSj4wM9qrU\n"
            + "4mZ0d7gRVrPTnby/OTOcDWAkTZbXjYbu2+k8CcwKdwgFL4tBDsj5ER7jSi0XVL/i\n"
            + "IZRwEK1nq15B/M1PO9zuzHopvtTTTk3pFSc1GoSsIYyqbbqlqWRGauwvlALZDuo8\n"
            + "LcPxFQbOrFrR1PbtjEVaOt4GM6mrHi9+CpKJcS47K7vdY5h+xe5inEw+LlGZmG4j\n"
            + "WtsGh8VDk0bNS88H3ZPvf8hPxtTnHAwtM+7Cy0Sc2iSYTZGAM0GYaJpOTN6RwWcv\n"
            + "mGPCkBpCOCwUnvG0iY3WYGYO65qBGlk/L5ObS13r0M+BrJrtfc2DB1R+QyzuOUHs\n"
            + "SHIq9449rWZHirGQE6OPg3EKAX3eZcT4EuZ3e9ptwq8PPXZrn9cXF50VQNBbXMl8\n"
            + "Fxrk2Bp2nyF5uqoImY1yKZgY7tJdpHIRRrTtHtW33GAHjkKkcnBpWnRDGts0Ldna\n"
            + "76DY/TqTmq4pAB+9EqdKkXMPWQjoD3E5pGoZwG486zOqLCiizxIbhWA/JWSuo/H8\n"
            + "02mG0bkoKj/DP6e0GCEA8nuVmjjb6pzASN5M0Ifu33kxsCeoooGoFg1vwbpwcIk/\n"
            + "5iz/u8ZP9L73Js3rFfbgcybWEknAVMqGrEL9v+PDtMSFotnUapIkEbwKiC6aF5DK\n"
            + "PtpGsxGbDknBjHnrRa9cO4xqAEYbNuw8WNW+cR3WdIe8tS3TJZgSNR1DtHClI98c\n"
            + "uI7z8XdEJqRhYv8e0nE/mUthcUhXvuUiLaEmvwT2p0d4hYxECgrqEQ7w0pXo+Kx4\n"
            + "eg0fErwDYwVeZ68iQneocJSM8FvGddEXGXWY//mfZF/umwZxZF+sv1Xd4npgau1d\n"
            + "V6vBmTxkK6dbDabCATx3frxCm2O7LcDMNRipyc7KQnHGRZmHhyekEued9i06iPQk\n"
            + "RF/PkraE/M+NJTBsGW1OZXifDjQkkLfF52FYlviXLO9h/YYTQW6v7naBf7sdXVVR\n"
            + "Wpnss+BMOvzf2udXBtOR4jqHJ8loafCfktRq2tT/sA22+6WAbXWiBt+/FxxZSLBL\n"
            + "a6TC64g5Xpc2AumHoP76i9Cqmwfj67yXDRlDSTd/3Dv39du5mZyJDwAhD+DLiiSp\n"
            + "eZzRdDeSNquR5DQyPFZF84HXP4JquDsyfotV1iV+fxt7MU1N/ctK3PfoeBM+rI1S\n"
            + "TCsO3C8ijIQzohffITFPKJdIIXf0rVM9LsffNUB3OPrgGTnMIYJZzjshYh53Jx+7\n"
            + "vxc5nVWeL0ws3ORC4wyVIRXIqxETAVdViTQMe9caPDgbKqNNOehG9Tgl91dSgilh\n"
            + "FsUIoPL18uVYMujwy5LFPBg79AB0yp8M/vPLjWs+LclHPMnzQGFCYp4PHMmQYUyQ\n"
            + "q2cRJNmSQtr2ROGPN5oTXFlPRtmahwftdS1fox3KDDFOu66FkJIr4+TOEqFFB6Yj\n"
            + "DOLwRhu5TV6b8GuzHtE8DSF3DH821NZUCi6wqKG7MmaszZd0VrovhDdgw4AhKR+P\n"
            + "g1s6VJO04aGsYz1zUUYz2NmicbAMTI3YczgP85aiH9nVcK13oUEDKa8sTF3Gq2Tc\n"
            + "mSYhpGL4xRuG3i5cLlpGgzLYPewhaLPqYpMH9RqN9NMKx9gYYBGVUi17VwTvtNZL\n"
            + "PMTtmNg2yCfgujPUxQXaIVYdHhb+drHgRCLkAY5QY4JZ+YoMNYdj8ZjyYP7WtEoh\n"
            + "LVjxgnLv44ZJP5TndzeVH9jMorde0rCOT+NibubzTNnicM7SQ+AMEYAy5N47wjsq\n"
            + "bQDVD23WdxFGUQIGWSNp2AJ2+eVOMMChcPwG7/HCYfKsBycY4bw54rQ6vNca25lQ\n"
            + "RvcUv2Z3TeUkNpYhBfRhoFwMNFF9N4oC/MD8mUjVsKGG4YqeOFWDPFYiOnWK2xFR\n"
            + "U1P9Jy6o6xeKLv/OjVTkTFrDvOJHOizXDuY1QRl1B7kNj6/PtIHZewCHY66JsaJS\n"
            + "W/at2XPtfg6e81TY4W30k4ytL9gAW4Lv4GVWImoonWdhMkOCMPfKqZYNhh/MYSLA\n"
            + "gTiMFgP5jwe7BNBbCFbs2wVeEEgmHbcWHWSfZdyz6R1uRkGraGmSDx7QWPdXyqwf\n"
            + "yD1QgOOjvEF4nOPoWUjFAbePsM4ncj9EA7jY2aNPQDkYSLBaw/6GomC21HhrZ6Go\n"
            + "URaBj4MZNgmjXpt1wvFlmQ84uWdybc4BchDR9TIjg2shC5JV6bT115ZeXBKgbXQ4\n"
            + "e1qpoZhZ0FNUODboadoIubT4FZ556RMjk35ncoI606KRUc+cTclNMjSgqNXSsgjl\n"
            + "73CEsRz5z3gXMkaL9IV0pjK67jO4I8xMumjyqtRfhjkd0Jv1P8WBAUpjhjmF8oHw\n"
            + "9YzRQCZlCzBgvldWyxp5ed4huw4GvwUKg0uqhO1zMYoIPWma6qC0DeHBDe9kySm2\n"
            + "8sUAWGNjsmZJewr9EM1kt8r+cpUqIc+DxcCMwHAZtU8t2stuO2iOaV0v5WZdEhAl\n"
            + "d+BSnrurCPpgDgv/LSpIiwe6vWIPQZ5VSR9jQHJUiCvgbdNbT39yEMJAmKQDzN/b\n"
            + "zxGwW8t7I95PnT2fr7Ypy4pxsz6GApekkAMD/TrxLBVT3dvNVOtPTylTXZ7QB8JM\n"
            + "2lb3VVOKhgvtvUAqJrc4X1VA5gFYJlDdZGaxuSQdm/cHdUP8mGO6pIPgzFPmqg+X\n"
            + "QsI+GkTgP49t+9fR3oVeMa8VloIuQ47mY5cR8ampvoFuWWi/oYL7IPi+n24HfwpR\n"
            + "uieQk+qJLyf97u4+vsioe765ciTShbVrrQyaHnah9LKlFce4WMge2lStEtfuWi/j\n"
            + "iIKq/urxq7WVo5A2LJbjc935glayfikLGguET+z3FDRDOJJz2r3KTgwKaViTfn8F\n"
            + "xs4jaWIYYLDfMoRikedMysBZ7RRdLA5deYDvEAUaLLmuVhCOj9/S+VMT2AwRw/SW\n"
            + "jz2lEUQ5UPGwBljTm0bRqd+zKsT6Tr1zB0eK9j6YBrZ60CZTt6LtsvaOld/NKcsH\n"
            + "8R8howgXhIaajRx6xTujzzp3uidxWrhlr6ff1H5ygYIHoQDWPUKn7S6glP0yMLGL\n"
            + "rp52KsCRhP6Bw/NyjM2Db92gKxF61ftwA0iOC7LW697s2nkN3Qp+yLFnrDp+VJ6m\n"
            + "IgqbprohS9mVTtqbZACfAhHmDghSgPKnUgQWytevMbN+0YDqvHiS0vQ8jT8OI/yc\n"
            + "1zEolO2DhKAmKXjyYKtnVDs1HMPtKaGYv2idRj7gdv9y9I9lC1bvKW9oQFSJib4n\n"
            + "y+YiVoASVRIAOhoEr95o9JkLT+00mwmuMJzo84hWxCZKMMygntmNeg+oLgXiV/mL\n"
            + "OPM4a5iLwhcoKtTJkqtffKDmKjOHlXvzs+kKAMtprnflRQ/sq7gpJXNvvuuUfUqM\n"
            + "q0NKKQ2h9s4XGGh1FUCamAQ8Ij7LKLbcxgwS9vxC0lkzseMtBpCfL1PHqH/14c6I\n"
            + "jRLrHkt0T74RHanz2gGFoAQTCjA7ns4DcqkmoKQtRUDW1dOzy4oqZKXoLFJZLaoN\n"
            + "oNasdJ9FyZA9hXtU7T36/LJgd1PFpADsav053JRpn7BuMEV4bw/L/i49+8Acuh/0\n"
            + "zJUVtYdczOzk/vrMS8vXe9XQJXJrlLIdJr3sGJ3MuizkZ9D1Tx0YLp7gH6J89BTs\n"
            + "F7IonEC4BoP+ibvoMJIJWLRFqh2rU3OMWcOkMSDcWVuJ1FVfpMfmXtC/auH08CrR\n"
            + "N+E5qv3wsVTuR3zqH2RotQSH75kaaD7N/wH1vbgccz33duIwF9g2P0ICFfdeI1I1\n"
            + "PQb8g43/w2LVK8cZhDDQe85SsApjnwzuzbHSVWXxEAWGd9VjK1T2IhnJbtRlob25\n"
            + "jixHWQs8GnAA3T0gOB90kOltL6Ru+y+GH8F3a5p1BFdskKz99FPBBu/RLIjtnSiM\n"
            + "hS9vXvSXosyHT85yTpwdAA2EV8o0Ln4iebdW1GvaZx/3YJ8fylLAkRSXlkXQRJy+\n"
            + "T8WCWCDP0sFJ4FRzZZwh041VQXM/GO+YZc87KA1Tf3XW4dET162yBTBcKD8p6fEd\n"
            + "hyWJaFp1dCbQcKVW+4OIHbHqMbbTnAGbGPeqYHdAjfXmUOUXRz8nJby4Aa+zcgah\n"
            + "CFqyfa0vIWZjVlJlhEpu7ruZ/TDBI1AUEmXzp1gzeX6u7DjlQ1k7Ih82DutEoGoK\n"
            + "CpAF6n66hQx9i6DpJlluJSrsST9QRLE0+dd8fthldVFIOMpEhM37UGsV9u4orURH\n"
            + "7IKMdmC6DUIYPqeZ1NiXzEt+76T5kZm3GysINgr+xa1kSy7YEoGKNnukDZRpklHc\n"
            + "wg78ia326x/fl/u1fhxuXyMObIh/j/c+/2m5EK+h+yaxi9331kHx8SWiM+/hFhv3\n"
            + "SYY3jB5V3s+NYhRjFsh/b3Xu2vPxlRnZKwcl2D0BOnMeKWv5CV9LujS3gzAvr/tR\n"
            + "JMMdR74JMLP42cZgUUyoUbOM6jzjeGy2NLdsbRSHs8nsG5n8HEaftHXV3EEWgPhs\n"
            + "i5Z3KNO0GZKz0W7t5EignyshEwJ7C58rY1iqb78XN30Yi+S43pfMl2NPMILYUGV+\n"
            + "V6Qy1lnnb/KL2Sq68qgHFWXnvyFnTwXz7k24jLzvrgFFe1C2F9JAMFzmhykCFmnA\n"
            + "0JKMOtdE9urFsD6zkdApD+6Fw89jgnA3KZUvYgdVjbEdHCNmAAnwZKryoSciP+WB\n"
            + "CRCyqJ6fD9ASY6cCUIFj59op5lmJXn5SFpQprO3xBZfDL6UaQZJMmMnLh8oh/FwJ\n"
            + "du+B7Bm/CoxsCJoNCk0fzIqvUD/0I4RXEuBmnUSWX2sQBMMrwWTphmqfaqZgy214\n"
            + "AXEXHmpV0Mx40JnUWY7VVWJVf762VjDGs3dL2HZ7TIDUsKtVuZLh1EDUtHl9PoHi\n"
            + "+9ePUlSHAFktWR/He1OA0d4/tjMp2VLZODbNJE8XrLMnv23UqC4Jq+f0cRbaPpkn\n"
            + "24isbeFjjlgX0DHruHqME6urkhRj7H3JCKbBWJf6dwpyyH1wBMsC8EpSTeqQkcFD\n"
            + "J6af8Cf02Q852buZ23mqwf447LUo0RgSM1YnfU3CnNOHx7Otx1GyOS/JtxEZSDIs\n"
            + "sN8+h/Ek8luregFy07rRrk9ZCB+dT+muUIhP1VjfJEkqwRT1VRGoYgTcqUBO9A1e\n"
            + "ILyliAswD36/dr3iK7fqNS/e2m4kg183DPEE/Wk2B9Sr1s5HAGxTQkdbjS6DQsaI\n"
            + "6AzWnk/EmHtVNnPKEqdxCHq6EUx5KT045sdB7LLRvKr2R5lhXIsou7xhB0tV415g\n"
            + "U0IfGD8ytC7+xE3PHvuHgQaa4UUeMJUnqgchHzIBLtHyApFliHuY0tmMUY4gVZys\n"
            + "1O2VJFBv5kHuJnzqCQZ56W81NfmdcLFu42Mm4eDsx0tNqmG8tNowymliVpfrAkZ2\n"
            + "H9k1daWZu2llwKmLDbxaRbPI2cxkGiV2kHoV1E5M5tQHAPL3MCahBox5i1IOofOJ\n"
            + "mf0EqV68NuAoAE7AdLF8Y1Q48ZXnifU0xEAgCNlcfO+0hwxQ0E73CFq716xsNVUx\n"
            + "f39CQbQerEcRDoJpZuceI7HBNAyJ2vMKXEp21lKC5Qawf2aOvXa7H9OPDia8Sy3C\n"
            + "voxuvFNcE3xblv0gBVUmUGYhnaFvqPJlpusw5muzzFBjh5YrPbIgQqb0jqcl+Ksp\n"
            + "52DtQw35cAq03gfUqb3883V8QA==\n"
            + "-----END PRIVATE KEY-----";

    public static final String PRESIGN_VALIDATION_KEY_DILITHIUM5_PRIV =
            "-----BEGIN PRIVATE KEY-----\n"
            + "MIIdXwIBATANBgsrBgEEAQKCCwwIBwSCEyQEghMgN/vDjyQfCB2/GaTipNQSqVsc\n"
            + "yCJ1ZRni2cWpFllQKSRSSy8KWTr3z0vkAEJdXOpNsKFKXnN1jH1mvvEq5t0tg5Xq\n"
            + "QsSQ5sDiDAHD0ciEFLy99KYQ+FwrhnfHRM2e8kDPjpxensJJOvJHjar1mQMwz/z7\n"
            + "EYKtOPYMayG2N/NkBiMENQrLIEEkFRAEsgCEwiVJBg2UAJDQqAyQQkZCiEBTAIlL\n"
            + "pGESRURBSA0iMETJuGgZIYEZwDAgyJFByHEhlGBLwmwitxHAtAHbxjDIyGQjt2gD\n"
            + "mWVcBGxAmIQisYwYqSBUFIYABo3DRiUQIw0IwHAaBHAMA4UTKZBTGGLZgAgDxwzQ\n"
            + "AJHcIiLIsg0AiYxLkBEEFIUZwDAaOECjIFJBRAoLkyzcAg6JGGbcgmEhRWiARE4R\n"
            + "BCUTwSBBFGwcw4makG1Lsk1KJGWTtkVZxhFYSC7AQG5cCGEYBwkZyYQENgyRggHA\n"
            + "xCDhFoDcxA2BCFKhBFELIWDitIjJMkIjMhFJRHIYyGCKEEGAEE2YIoAICCDMpgiT\n"
            + "GAgaBpBYEmGjNgAaMoILGGASkYDEskiQNCnDxokJGIpAAhAiEREQpIVTkmCkEpBZ\n"
            + "pimJyGEkQiKSKCYKpmAZoEliFEoCNEQJIIghQ26TmBAYuQUhNnDMmAHRpkjckikE\n"
            + "CCjSODFSNmKjtE0BCWQgRkicNG0IASzSuHEDhyhkNArJwiDgxCXYGFBIMDGCtHEI\n"
            + "ATDUoG1cxmwJCY0DCQWTFCwbBUGINAzaGJFYAmJSOEEYoABcBkQDpIHBpiQgkEgj\n"
            + "JggIGCHIQopTokUcs01gogHUspBCIGnTxERCNpEYJCXZNg4iEBHSyAyLAIzIyCwK\n"
            + "AwmToC2hhiCJhEEcNUUEQGQMBG3cQEABNS5UiIAbBSVAyHHawiSkwEiChG0SxEFj\n"
            + "pCycSGQjpUUEBkwRoykbASgCyUwDJQlJAAUIpkxJkkzDMhHiBCYDIklkSFHaAAQI\n"
            + "B2aCGGngEEIJsCUbBSCIKHFImAABEU6Qto2bCATAsIXgMg2KBiIiqZEEx1GAEEIQ\n"
            + "p4VhAm2IMm1hNHATmEiQmDDCSATckAQIR4AgKHDhNklSSAWTFISURGkkNi0QNnIT\n"
            + "NJJUhnBBogCaRpGZyAkZQI1hpCWANkaJhAjYmIkTh4VLllCiJmybQGaMwARZsomE\n"
            + "pCXkEjBRREELISAiwUWDkmHjljHKEDIjByoICEjLAAVCxkCZNG0BEIzckgyBhDDa\n"
            + "kiSQQCiQkkDJCEUhmGAbOAohs5HEQISkBkgihJFjhChahkAclEhkkAkikmiKRooC\n"
            + "FGZBCCkIswUIiWCBElHYAkXZoFCCBFCIQmzJJjDTkCwJxYlLwizSQIBaSAKIxCgY\n"
            + "xUAKkiHTqIXUmHFjFFAQhyhkRjKiFkEKJWQEIXKJtEkhByQgJABTBogJGWFQsEHJ\n"
            + "II2kpiWZIDCRuA3gRGGbgAzaMEKEqEAjp2GJAkDJlgkjpShbQgwDBzIIMWRhhm1U\n"
            + "pIyMkCUDOAVjQIzBQIgkNEkbGY2ZNnDSGCjQBCDAFDDUEgUSxyRkSEqjEJEJQERQ\n"
            + "IkxchG0ZwQicyDAIyAmbphAbAQVYQmggAkDBCAYcuUFLQIUExo0JCYHEMg7IAC6i\n"
            + "RmAkAZCaEm7aAG0ipoVJtG3KQoJcKE4bKQTLIglMIEgUJwAQOWjcQG6hQHAEswFk\n"
            + "tlCkBCAZJEITMWFERIUSRyJcAo5jCIFKpi0TExEhKCQIuEjKBpECwwnMwm0io0mj\n"
            + "xhBQNoYgEknAMIjBJAbRkGhAiEjbIizKggghSA7algXYtmgQpyHChmDIAg7KKEUL\n"
            + "BC2IBjHJRIJCMoIUqUyChDGkhoRYBi6ZNAWBJkEjkHFAKJEbKUTBJi4MODECMG6U\n"
            + "JFLjMAWBRmRhFCbhlmFgxAkihW0DtCzJhohiRG2RyAEREQ0DSSIUMCEkkEnYQpCE\n"
            + "AClkEGwTMwYCtmDCAIUgsUVEFkGhEpKYKIUhESIEB2ijIkYJQQIACQnIECVAKCkA\n"
            + "SSRbAkoix2ACx0TYpk0BAILJFG4MmGVEwiQbBY0BJUVZpEzkCHFRsoiAEIhCOCmb\n"
            + "AGRcpgycphBBgijYNIKJxHA+BG/iKoNV5CFR2XyPxglDTe9SixMWFy2d5kel75S9\n"
            + "8Da2HCIXsxH1C801LuwqGot2GGShtShLybWD80drrRrmHaPr4kVjvVEm0ahPoxOR\n"
            + "SmLOkSO9wLb8gO+EZouKP/wJpIOxij6ygNBffImQDCi3QsC4X+yrc2D2undcz2ma\n"
            + "54N9rMPSBG0VEZU+8ylW94drdZbOgHNzcFMRyPszVQb9kX5YQ3aeVEitioZWeH+h\n"
            + "QNcnat/CoJjhUKa1qMWkowZfAUiOGdNmIx+n2l8qaL8tdJm7jCMfM2SaiSiER8Uk\n"
            + "ZN66Df4HUY/RK7V/Bv7MjC3F0LDHLeGssoeu2FQANsQlqf+eRshwrdERMXQ00O4g\n"
            + "G8QYMz6OZroz4rY+QAdHtYeN2/B2EgSpvUJ/ajalJYY/YRUeKF1OfZ1qL3V63yo7\n"
            + "Qhl6s5aQ19Z6/N/dpbGrdx/xqZXfHlDhkov1uklZvzhAS+vSLMRTp/U2XslhfNHJ\n"
            + "qbDnzComojtGBeL7ejb5qkJf/5nunLaMuWzYSjRN6dwFzhpBeewy+C2lFaHXzqqV\n"
            + "r6RSvX3cAghXkTGPdk6jQekHBI5YyVk1PcCmNFnoCyFTxCJRP1W6uYMbFFkup37B\n"
            + "WaJ22RndEe0duzVAkZAH3oM34goc3Zbfn+lWGJbyp1CZW3t96NG6Q3CZSIYPx4Ue\n"
            + "hPkNXlS/qAeovHBe1LYkHfyn1gfBfpyMACiBKBgZoPR/vBQ4ff2EnNCWKsQjhXlX\n"
            + "iH0CsjQ+4zNGY2gNn1Nb97huEoa0lVhIHFQ1OaO1Hr/9F71+2D7zJ703qVgPtHOz\n"
            + "oggSETm7XZVqkLSzAVvpjKMEy24VK/2O0GbySwS7P34u1dFun4HBeVfwrldZX5BH\n"
            + "uUFxg2oV5x97ac5Xuu+44R/HxfONg9be/j2eMENNuUf2dpNu+BVizYAfCKtMW8++\n"
            + "cGXYzqTdb9C6220/mnsq9620pq492JTqT0hSfuWpB3zZwYRbSx/Y3IZz8rbMIzTV\n"
            + "Kl5IFyF69Fi4/LFLi6S/2k47DK202KPwQ9BrNA0at6Lpd21IqVROaYahEClS1TbQ\n"
            + "wepUOppWXQXTWRjayP9O8M1m3RPbbm73rd+DvYJlYyb6IdbRzl2wXnS1g4YOEe2s\n"
            + "VloiXd3J2hpQXGiHoIRK9TtbY4MNGrrlR8gvrSFEva8O0P5YUOXRyIxhDVb3RBpr\n"
            + "7lewSB8sPUEtiBHtTD3W9W5mQ/rxkk9YzDtFJxNT6Uz6LKIA1s258u0IXM8PZgtV\n"
            + "qz7rCxsbZ9LmY8gDQrlLyyMlfqT/BoHIr0o0bk4ZGTmep+0utvEIq1QzkNDpmv2C\n"
            + "eRm7dTc2Im3bfNs1MTC+LNsPbj7GouXMg0U5JxztP/QnK3OlUBvIyjh5pkzWtASK\n"
            + "ciEqboIcuxI5pO0FIU4VEzier88nDn/CRd0HqFDkAuIO4sfro9zhK04al/b3un/o\n"
            + "pqQA9W67rCk56zVjSRoNRYR7+Zzw1imCB5fnUUaOQkJUONRjpwwjn88SK8XOQwi9\n"
            + "VrHgKZnV1JNbVUwVBjAKC92lv0IJG6kNiYuQTuSCRt0gq51nE1Pdqms3w1B0Vc/p\n"
            + "B93JMAxspqZqobvdGqxqqlCUKiVvP+dCLyeDmv6ei5h+tfTt9KrzYRdzy53Fm1F6\n"
            + "ID8ymhs/osJNw04gmt64Q8f5R9pavKa+7fl9/9O1KmTmUhEmrjLO3Rg2n7s8HCSP\n"
            + "1G9FePxi57EwZ+EFXeg3E7RWKSGJA7WOGVsOYbxp7ed7KKJ25b9y2qfxRc/3F+69\n"
            + "vtVsM5IS40kfgKNU35DBNCIwvw2k00xTY8PSo3+piopRXyXpbW97lVUNEVLEMymu\n"
            + "wHW3FR6rDhSFaOu78dgtHwo4YYcPUfsf0u2Buh858zTCrwxrfo1APXasft93BIpR\n"
            + "oWo2AjaIMVYFmyhV/7Gfva7+EwIZ6znKy3Rhl4bmIbVYdRsSTiwggU9a35WjIDFH\n"
            + "4qyrdMmFivuHujo5bykjFcpoF2qQkdnVWtCt/u/l0vTAq3S/aNDh0eJy2GOerhx8\n"
            + "ThAz2S8y329r6nFkhdZ2z00sNdwczifaSBPRIk71oIC7t+5+zHT45XXPIK6ueLiu\n"
            + "Fu3+gIm5SdpLRcRKANjmZDqkqhugsquY/IfQuSRjGt8eUMIv6+C8qfHLa88OJCOA\n"
            + "cWB2VI+kVjfrW4dYJwfwz9mSapW6lw2n0JeEHymxDcvSxyFQelwE5JU/xEJcBtIS\n"
            + "xru0gMgdZHfhPJHR7f7o9qF+dU+Cs2hVzpHYKUxtQr+jicos+nCfjR65/2FWWlIw\n"
            + "bG5e6EMBWWLvQpclvCcL7KZIS9PVXu1JqjSAgaKKsBLJUiqevYh5H9rGF0URDFrm\n"
            + "GhqhB3wTX/jVxPUx2do7fwavb5w6lm2mPJSZbROibaRyzsMIBQul/Rwluk9mNMxp\n"
            + "rGblTivRP0LbvnFEAt/3zMBdkWD7gqOYBAJRsPz4fqduhN39iseV0lq9HcYPySVI\n"
            + "A+ev5sA5RL7Is17NSBQ6laRCzgYjYcKkc5Axi8BR+uw1FyeIe6iO75krD3p9EieV\n"
            + "gCMv2G4wLmUmRSPtx5aErKhV0XTkVYY/xfNa6eZZhsqKKz0qelSoiWSWkh6djcHn\n"
            + "Tfrch/qvHDJwpUnWi5JbgTJBC8rXmQOooMEMoRM3/Fjx/Dxb2KRHBznH9F04eZPm\n"
            + "mNh0LS1jXSXYtJ6DWU/kZVCYGgcLx6eWe0qoVeuIeX7lasOupFs5q+MLLFq9vGqM\n"
            + "CuGx7rx/YHiwLoX9x4ZB/wXUx3GqDkNF940OaRitOiaXRN3ppQJ9yooFUlosBIbB\n"
            + "DRFvsYkBUyWTfr53edVatth0IHirQWH36gAUmyrBTGJ1zmymHnP/DBs32gvdA7Ma\n"
            + "Aqmt7qdFTK9YcXKSdAFBJyIcpu6wdhzUCfFllj+dAsrpqJD5spCl6SiecQMpJ+kX\n"
            + "iMPhSFOXaB48iIFmAzR77vwjEz2LQUcts49UbBAodqD7w2FFSzYwYiWiT8Zoh103\n"
            + "gUEhtOqObowO6UpdfvWx9+ctD5yZ7mq1GyOPeeW2187pMEH+JqhmbsfFcwHrO7VD\n"
            + "Z+6mUmcVgFTuIU0KEeb6vL+2yqgV/8Hx7ycZcAJ8+j8qLjwbI5M5ibp7DkunwI3U\n"
            + "3IklAdJ36XEMZIi2OdCkIJavTqbMapKtQjhnX8sa8em4imBUy1Yr95BaGe3LOjQ9\n"
            + "rkio+xd5ILxPF12nbkyh/jmBrahhKfhBrKPKelK7ZtvFNySNcxuTKxRrnSBZNy2J\n"
            + "rt1Q//Owvh2pUc3t1CqDlwZpJJccSy5/9AN9eu+Vb6FlBdnToT4Me2WD0Ti/M4KI\n"
            + "3v2INMfTp1d8dQVPxsrkprpjn0LRdkCtQsM2/JSyGc25flaOQ//liW3uoIW9wvck\n"
            + "yzZDMPruBu9XGZUERIXIR6DbsZT70JDms2DHKvJII78m4D+0uGYB+6ii3rPRspK+\n"
            + "F84GqIFmWAbARcHQizVuMOImN1YJqzAk3VEUcC7W8k8hgTJpITdbr68hzPMl4OgZ\n"
            + "R9YdFGWaSpXFYJtpY8C94pp5YX3qQdR6nsv1oauB+j35+7VkjIPCdIkwiQC2WHIm\n"
            + "4zF46FYTo9/aw/Cj1Ii/ES338/IkwB5aQ5PCzIWhGtwmjfOLIP7yx+WMt1/kLF83\n"
            + "JSE/RlJmWmX62PLfxh+DMYzuoVIpa6a6h45kslnfXuPp6e0dSFjFEBnhmtWHUY2n\n"
            + "L1UoXSIyt5TGR96ACbuG17+Oq5XxhDq9PPVsw4HTguTJ7z8nByoqZCBoPMZpD3IK\n"
            + "G8Ja1KARZgC0iTTypaZCQWVv4yfqIjcn4quT6O7Jg0IYdLZBwcUQucoAd/9AO7TB\n"
            + "KOT53/P/2N1Mr4KIOIQy4dMAJC4AGe4aSKRrHQZfawqhRdCukyWktUnkTfyJ3zHr\n"
            + "T+Xua1mXeIwhq6YaPBsIPNtzAOZWVkvBD8dI0ehnbIiMdxcxQskVJdwhUC0v8Qoy\n"
            + "+9Llj1MJhDo8LnpFJYskiLFQR/jawnVmv1gsy0Xz8Qhaiv0qUdn5K+Ou1HRmsx/+\n"
            + "qPtrD/dxIxgLJVwS5zpDixzpYmgqnWStiTsL4BjWpZrhWY0FnUcrtNPVm0wIhTHI\n"
            + "8j3dkuMAaVCuTOznCYTZgjCCIQkn8KpeZZZSYYzetIHYNXpDdTj+t/DS7B7OfmTo\n"
            + "mUkNYVLKEIDXdnxW2PcptmLKqfouQ/v44pX3/z5vjboqqDoGHz4YBJ+qtuQZ3al3\n"
            + "KvplGp4pBZ3G+jAxgncfzKdgfnb7z7JpHwAfXYisCrD8DGB1JAdSS7XUO5+iF/mY\n"
            + "ybBZ1j1sQsv8zapdObCBv6+YF4O1rKZMBcAPk7hi58yOpzTYr4hc8IIiKh26DxtK\n"
            + "airkO48vDb0M7BSXD0ShSghQRKXAvTyblfWcg+jyRTo0w08WemC20ClYOx79GYkU\n"
            + "vr70ualxhjwKqoy002Nh63vaAz3YnSxxPBATaW6agYIKIQA3+8OPJB8IHb8ZpOKk\n"
            + "1BKpWxzIInVlGeLZxakWWVApJIJeCENP2ImpI7LmArf8XRtzXH8AkgsOfPorLZG5\n"
            + "38nOjs45WqFkcgmvhLkPWVXYC8iPCGZ5/RWNrm6kBwgubcpRbcBsIe8DiDqzIJDt\n"
            + "Rlb5gLqBGtmOzKsRD2xqtpU4nENbLTcmZy6gsjP3ehv3qlaE8+ot5SnPrWMV6cLg\n"
            + "ALoRmiLMwzaZMRghvuUARGO1TE+oU1zLXn18Ku7SU/DOR/GhFe6xrGlFciE0X4HB\n"
            + "vGoHkTyB/J/kn4et9lpBITBymAsiObguzXGqP4easK6Bg3iLZiN/K1N0oORz6AAZ\n"
            + "GfYV0feDUyX1qHndq1E/buDQVvtinzJuzgsvXpHRYjowF2Wta4epqaOguZedcO3x\n"
            + "4AIOISPygCTvWVnNrqsjK2/wn9z/oeurk1Vhr1FV1rpXmCtg+3UoCkJfM6pgpcKZ\n"
            + "9vdBFI5SIHNwf4kVSMh8J/XfxxPZtnzfD3fIVKzcZ2X/UUoJQ3KjbqIlpyx1EJwM\n"
            + "aFhJ6vv7zdam5BIphlGao1h+jOIruNr3xG6Txh/niksC8NhAul0Hgn//Ua6IIhrQ\n"
            + "nchQDHARU2asNDMRy3maGN3POEPj2vY8FeCxKYrdQQHkGBc+OcwFJBdOK0wSxb13\n"
            + "icF/AmUq1WPhe4UxEWJTUAV/jt0mXOPS1bU4gm4kdLdLVRVzELXJckXHFbA+zc7m\n"
            + "bvbHJRlP8iQG4n4LxQBwT0ldFn7jBMaZPg9R7QJxJoL2AUdBzzgw/Ybj+X5imj47\n"
            + "V4GKxgJwSX9ssA/5Grh3sQbAqUiTMeMVfuPOil/xegw///jHqZztXUtX4BIl2K42\n"
            + "qUwo9OdcQRfgRm4l9qIE3CUOwlWILogUDrqtJFHWrhXEWTgSMhmD5hY0RP1hvKWU\n"
            + "K7xrKOQU/ClZdZRtvswiCnKN2exHD2LtSzaeUu2UOVRC5vFG1iK3d5/yhKm6rmGL\n"
            + "+2Oxfe6gwC46dJlbq5sxDjOdAv1tWZ6oyny+lc0KaOlDsOz665ilUSMV57WWBlK5\n"
            + "dOH21dFXf4m8wfycjBhueCc0F9gabmxO5bzNaRQqWaVdl0TS6ENLyXh+FGH5j1mZ\n"
            + "ADKqmXyneRDaQaFgMQQQUiITlrz4AEaRW2zBsgQRoWt7Ji99vLYRiEVYxWOKz+Nz\n"
            + "tYYGH/7vnA5BQAIU5+vuaNI0TvWWOG+bPh/FH3JLP9bSINwdFCmfub+jHcRSw2c2\n"
            + "3/AgLt89rLHCTvNLr//Oy1bcVblVPonKJhofZH4NKkMzP53GmtrEIeSxf6Ta7cSC\n"
            + "Obm6TZojJXEJPJArXBnrXExs/So6hI81U9aYY0swRWtt+qGrtFhJDDoq1yT12Lv4\n"
            + "P2xPvftr3csV9xhDERi5wXHPT+1jLwiX1gR/VV5sQChSrhzpHggF/kUPdfdeHFdz\n"
            + "r9PAceVE2OYdw2cA8fVghqpAOG9mpJlycI2HYmjtIiGnDjeNoRS9N3nrh5rjMqzz\n"
            + "Dk+koCktanohCVKcNtpJ0SJh6pMWIIF8SK2fujFJ5p9JGRe6asY+1BWB1DU8HIro\n"
            + "BB20xW+VoJKPrZ8/19K1QdLEhTdh5NM2bRvTmlTwBOqXdIATFLM8iqBZTIlu1bkZ\n"
            + "LcNJcqvRxAVRNsEO96oQqijWKMC184cRsKWBtXReFeUGoi6U2XB1uIb75p1upEY/\n"
            + "eUiLnTzu5bemFrMQV35T1OasOe4Wqqrj/nLn/mGsAA6jvBrkS/bfZzirm5psg1DV\n"
            + "9L7mOsgcO7N5oc2t6fRI0RUeG+c1AFJBkjVdWjDWCJr80HieDruOrG4ZWGtT4bD1\n"
            + "V00f43ft47/LeNHTEWEWRacKryrQIH4ESEQ2LfyPSrQKtzm8YipuRCQ/d0uELsnw\n"
            + "OdaDMzCQ/Y+jj+xb/mcd3QN8U3dKsFdJB1n7m5Aqu6zGQ74C6GUbRf5E17bZQYw0\n"
            + "nhRxZAib/0qKD3U+/jLakT1kWWQZvVfCXaRDGDcAzWM26zRpxoipYPyEvzWBJeKu\n"
            + "65Ke3kBjNUDtvCzc1hNd/+ieqMN8x/zspA2wzpK5J6/79FJUad1cIoFlS1mrIjdy\n"
            + "3M+Adc2VbmYlQDW3igQfMhBFxmnzZ/wHB/vb9CogTQZAMfVB3eNOsNZ2fFjxQMdY\n"
            + "wxJG9/5+fB1pWenAZd2ImhsqseP46j/02zqP7KwExQrsZHjAB3HxRxaNFurDDW35\n"
            + "tkj4Y+HL+sx0CvCEhJ+a0V+eCW8cX4ZKPXyyrX7JBIXr+b0vDRUQyDLHgZCyJo+T\n"
            + "7xndFX2vufqfHU0r1w5dwwiieL27r/M8uji0rsfW8Eu83QxWqsBy3mHI5VOQMLfv\n"
            + "RULC7cNT56ridqQ9LVkEFrrCgxiDsGsPmDpTcl4OMxbfkGj7f15LiV96zi7KX/Og\n"
            + "mMeA6rMHKqo77INKDaKufY7h2oTmYR1rELYDS/9cVvxrvbLUO10SHuAjAc2OFrgi\n"
            + "HCqcJOw+r6sRFXoCTb0WA+BaMLuDIPDPxIsMfJ88NcYIKuFW+t71fRPErvGX+K8i\n"
            + "sg0Nh4gqxV5y9/gqmNfwem3FqUTl/k+j4PhdeBnntTVFtHyTKXgo8TCLtpTU5az9\n"
            + "I9RUMfqEonpwD8lTkjj/LXcLYIQaaC9WsXns5QzJvc8EXVQtYHde6fhTPyjfCCOe\n"
            + "LwSTb1K5mFKTRVdusHMAgEDLbubkSTDwhjNAzIN/TQI4Za265I0L7oMM5Ra/7poR\n"
            + "INuKDQhaXENZYt0iX5lSjhWUjqCyH7U4KVLPP5sQCLCZhkyHmZ4orBk1pW7uYiTT\n"
            + "QZwLi+jRBdebASAvGG0jgiAr7jlqq3rzowuGkNBCRSFL4A/VfOWKVLVdAjZ3Ysf5\n"
            + "7AE+grltOCsQf+DmI8WD+HCKWa2FKOxRpLDwCCBvuXWV4P9FHozAbteyFg9/Cefc\n"
            + "se0MmHuVpIroN5WRpaKrkh4lM424hZLJ7YA/DgJl05XlMSseuUup1eexLFImJuX9\n"
            + "Y1yd0g+8GiWH2EJ+HrRaEqmCJKMiS0LHFccSrmiUg/pJ2UdiSdpajTJcE5844Pm7\n"
            + "NtBcc9pwZOpsf0li0VF4Gh9+g1+B44uTK0SNsXcLDIlnvlNbhk21EJ09Kc2FfzIz\n"
            + "iyJMyqo3V+xnMe3nV0cYYl+lsz2R9UsBLGQDFO4aEoju3BVICUeq8w63pRDAch9+\n"
            + "5wFuB4u5Y+niIzYEJ66saQArE7gDP3ASjygavQlW1nsMnLRmC5w82U88wQpW1LxV\n"
            + "Y7WMiMtAxXiPjTPeeTHjq3Fb+3qkYjcwyH9ig+4N0AfTlEPUO8afBaT1muwQp7PI\n"
            + "Dz/eLh1X6rFH9P1mUG/9Oy46Kz+uXrBhz7zLEIsc9Jyjyq8XMhoe0IixoH4uf9Fm\n"
            + "UbEwu8k8h8IKGntQtAysDq9ggzX7QLQneJJi3C+M2R0jgMRXvAeUtS+HQgQM7SxR\n"
            + "3s1EVlLcJqlPPSAPJ/UKxwaEB3gpHhYckbHx4qde4WpS1Vk=\n"
            + "-----END PRIVATE KEY-----\n";

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
