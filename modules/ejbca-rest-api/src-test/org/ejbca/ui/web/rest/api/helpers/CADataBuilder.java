package org.ejbca.ui.web.rest.api.helpers;

import org.cesecore.certificates.ca.*;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.*;

/**
 * A helper class to create a test CAData object using builder pattern.
 * <br/>
 * This class uses some defaults:
 * <ul>
 *     <li>an id with value 11;</li>
 *     <li>an expiration date with current date (created at initialization time);</li>
 *     <li>a self-signed dummy CA certificate, unless you overwrite with your org.cesecore.certificates.ca.CA.</li>
 * </ul>
 *
 * @see org.cesecore.certificates.ca.CAData
 *
 * @version $Id: CADataBuilder.java 28909 2018-05-10 12:16:53Z andrey_s_helmes $
 */
public class CADataBuilder {

    /**
     * A self-signed dummy CA's subject.
     */
    public static final String TEST_CA_SUBJECT_DN = "E=testCa@testCa.org,CN=TestCA,OU=Test CA Unit,O=Test CA,L=City,ST=Some-State,C=XX";
    /**
     * A self-signed dummy CA's name.
     */
    public static final String TEST_CA_NAME = "E=testCa@testCa.org,CN=TestCA,OU=Test CA Unit,O=Test CA,L=City,ST=Some-State,C=XX";
    /**
     * A self-signed dummy CA's issuer.
     */
    public static final String TEST_CA_ISSUER_DN = "E=testCa@testCa.org,CN=TestCA,OU=Test CA Unit,O=Test CA,L=City,ST=Some-State,C=XX";
    /**
     * A self-signed dummy CA's private key.
     */
    public static final byte[] testCaPrivateKeyBytes = Base64.decode((
            "MIIBOwIBAAJBAO+J8SwhWzPlIWr7M5XanR/m/kXUVc6hrNrO5CG7xRvaTsWZgRik"
            + "/1WkLxm6xEl1HhOI6LnoS3iCgqcAU3sd9Z8CAwEAAQJAa3YN3Qdl3AUqFc12Gf9G"
            + "SB6f6gHVMOr1GgCA9eVACzrpsnaFT/wSCaG06kDLPlKmbyFN195tBIwG/kPiawGz"
            + "6QIhAPpTEd+Fr8PK4zRQm+w3fNZj1Y06nbiOZF9vjGK9Rj7VAiEA9PhFMoAzBvzu"
            + "8uWzM5Kwabu8eVyDMGJdE73MEY9WJKMCIQDZ5WtebUlFHhtOE4jWQqqZGAfwyoA2"
            + "AUSfykKiRG2cDQIhAM8Y+P8ZrIny2VvV3yrxj1zEDzGWiX4lGkUvRs9tm0j7AiBN"
            + "MMJB4MhGsvv0QVL9zmXYfuLx3ZB0xzRywHx9qXTDUQ=="
            ).getBytes());
    /**
     * A self-signed dummy CA's certificate in PEM format.
     */
    public static final byte[] testCaCertificateBytes = Base64.decode((
            "MIICZTCCAg+gAwIBAgIJAOYWzkdpDF7iMA0GCSqGSIb3DQEBCwUAMIGNMQswCQYD"
            + "VQQGEwJYWDETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQ2l0eTEQMA4G"
            + "A1UECgwHVGVzdCBDQTEVMBMGA1UECwwMVGVzdCBDQSBVbml0MQ8wDQYDVQQDDAZU"
            + "ZXN0Q0ExIDAeBgkqhkiG9w0BCQEWEXRlc3RDYUB0ZXN0Q2Eub3JnMB4XDTE4MDUx"
            + "NjEwMTMzNVoXDTE4MDUxNzEwMTMzNVowgY0xCzAJBgNVBAYTAlhYMRMwEQYDVQQI"
            + "DApTb21lLVN0YXRlMQ0wCwYDVQQHDARDaXR5MRAwDgYDVQQKDAdUZXN0IENBMRUw"
            + "EwYDVQQLDAxUZXN0IENBIFVuaXQxDzANBgNVBAMMBlRlc3RDQTEgMB4GCSqGSIb3"
            + "DQEJARYRdGVzdENhQHRlc3RDYS5vcmcwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA"
            + "74nxLCFbM+UhavszldqdH+b+RdRVzqGs2s7kIbvFG9pOxZmBGKT/VaQvGbrESXUe"
            + "E4jouehLeIKCpwBTex31nwIDAQABo1AwTjAdBgNVHQ4EFgQUqo2fZcD1YRfFkx5M"
            + "U9Iy9QwIPWEwHwYDVR0jBBgwFoAUqo2fZcD1YRfFkx5MU9Iy9QwIPWEwDAYDVR0T"
            + "BAUwAwEB/zANBgkqhkiG9w0BAQsFAANBAAqTNF0TWrYN4t1fOqudMfOvER+qP0bh"
            + "YvoMnA+KCcoPWC4bG1H22L7XPaIoprUarL3GzqkL6QtlYqLUniYGdno="
    ).getBytes());

    private static Certificate testCaCertificate;
    static {
        try {
            testCaCertificate = CertTools.getCertfromByteArray(testCaCertificateBytes, Certificate.class);
        } catch (CertificateParsingException e) {
            throw new RuntimeException(e);
        }
    }

    private int id;
    private String subjectDn;
    private String name;
    private int status;
    private CA ca;
    private Date expirationDate;

    // Private constructor with defaults
    private CADataBuilder() throws Exception {
        this.id = 11;
        this.expirationDate = new Date();
        this.ca = getTestX509Ca();
    }

    /**
     * Returns a builder instance for this class.
     *
     * @return an instance of builder for this class.
     *
     * @throws Exception in case of CAData creation failure.
     */
    public static CADataBuilder builder() throws Exception {
        return new CADataBuilder();
    }

    /**
     * Generates a dummy CAToken instance.
     *
     * @return dummy CAToken instance.
     */
    public static CAToken getTestCAToken() {
        final Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, CAToken.SOFTPRIVATEDECKEYALIAS);
        final CAToken caToken = new CAToken(1, caTokenProperties);
        caToken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        caToken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        caToken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        caToken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        return caToken;
    }

    /**
     * Generates a dummy X509CAInfo instance on the top of self-signed dummy CA.
     *
     * @see #getTestCAToken()
     *
     * @return dummy X509CAInfo instance.
     */
    public static X509CAInfo getTestX509CAInfo() {
        final X509CAInfo x509CaInfo = new X509CAInfo(
                CertTools.getSubjectDN(testCaCertificate),
                TEST_CA_SUBJECT_DN,
                CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA,
                "1d",
                CAInfo.SELFSIGNED,
                Collections.singletonList(testCaCertificate),
                getTestCAToken());
        x509CaInfo.setDescription("JUnit RSA CA");
        return x509CaInfo;
    }

    /**
     * Generates a dummy X509CA instance on the top of self-signed dummy CA.
     *
     * @see #getTestCAToken()
     * @see #getTestX509CAInfo()
     *
     * @return dummy X509CA instance.
     *
     * @throws InvalidAlgorithmException in case of X509CA initialization.
     */
    public static X509CA getTestX509Ca() throws InvalidAlgorithmException {
        final X509CA x509CA = new X509CA(getTestX509CAInfo());
        x509CA.setCAToken(getTestCAToken());
        x509CA.setCertificateChain(Collections.singletonList(testCaCertificate));
        return x509CA;
    }

    /**
     * Sets the id of this CAData.
     *
     * @param id identifier.
     *
     * @return instance of this builder.
     */
    public CADataBuilder id(final int id) {
        this.id = id;
        return this;
    }

    /**
     * Sets the Subject DN of this CAData.
     * <br/>
     * <b>Note:</b> Might be overridden within CA's data.
     *
     * @param subjectDn Subject DN.
     *
     * @return instance of this builder.
     */
    public CADataBuilder subjectDn(final String subjectDn) {
        this.subjectDn = subjectDn;
        return this;
    }

    /**
     * Sets the name of this CAData.
     *
     * @param name name.
     *
     * @return instance of this builder.
     */
    public CADataBuilder name(final String name) {
        this.name = name;
        return this;
    }

    /**
     * Sets the status of this CAData.
     *
     * @param status status.
     *
     * @see org.cesecore.certificates.ca.CAConstants#CA_ACTIVE
     *
     * @return instance of this builder.
     */
    public CADataBuilder status(final int status) {
        this.status = status;
        return this;
    }

    /**
     * Sets the CA of this CAData.
     *
     * @param ca ca instance.
     *
     * @see org.cesecore.certificates.ca.CAData
     *
     * @return instance of this builder.
     */
    public CADataBuilder ca(final CA ca) {
        this.ca = ca;
        return this;
    }

    /**
     * Sets the expiration date of this CAData.
     *
     * @param expirationDate expiration date.
     *
     * @return instance of this builder.
     */
    public CADataBuilder expirationDate(final Date expirationDate) {
        this.expirationDate = expirationDate;
        return this;
    }

    /**
     * Builds an instance of CAData using this builder.
     *
     * @return instance of CAData within this builder.
     */
    public CAData build() {
        final CAData caData = new CAData(subjectDn, name, status, ca);
        caData.setCaId(id);
        caData.setExpireTime(expirationDate.getTime());
        return caData;
    }

}
