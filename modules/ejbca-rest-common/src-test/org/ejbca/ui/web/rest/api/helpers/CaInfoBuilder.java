/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.helpers;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.Collections;
import java.util.Date;
import java.util.Properties;

import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;

/**
 * A helper class to create a test CAInfo object using builder pattern.
 *
 * @see org.cesecore.certificates.ca.CAInfo
 * @see org.cesecore.certificates.ca.X509CAInfo
 *
 * @version $Id: CaInfoBuilder.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
public class CaInfoBuilder {

    /**
     * A self-signed dummy CA's subject.
     */
    public static final String TEST_CA_SUBJECT_DN = "E=testCa@testCa.org,CN=TestCA,OU=Test CA Unit,O=Test CA,L=City,ST=Some-State,C=XX";
    /**
     * A self-signed dummy CA's name.
     */
    public static final String TEST_CA_NAME = "TestCA";
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

    public static Certificate testCaCertificate;
    static {
        try {
            testCaCertificate = CertTools.getCertfromByteArray(testCaCertificateBytes, Certificate.class);
        } catch (CertificateParsingException e) {
            throw new RuntimeException(e);
        }
    }

    private int id;
    private String name = TEST_CA_NAME;
    private Date expirationDate;

    /**
     * Returns a builder instance for this class.
     *
     * @return an instance of builder for this class.
     *
     * @throws Exception in case of CAData creation failure.
     */
    public static CaInfoBuilder builder() {
        return new CaInfoBuilder();
    }

    /**
     * Sets the id of this CaInfo.
     *
     * @param id identifier.
     *
     * @return instance of this builder.
     */
    public CaInfoBuilder id(final int id) {
        this.id = id;
        return this;
    }

    /**
     * Sets the name of this CaInfo.
     *
     * @param name name.
     *
     * @return instance of this builder.
     */
    public CaInfoBuilder name(final String name) {
        this.name = name;
        return this;
    }

    /**
     * Sets the expiration date of this CAInfo.
     *
     * @param expirationDate expiration date.
     *
     * @return instance of this builder.
     */
    public CaInfoBuilder expirationDate(final Date expirationDate) {
        this.expirationDate = expirationDate;
        return this;
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
     * Builds an instance of CAInfo (X509CAInfo) using this builder.
     *
     * @return instance of CAInfo within this builder.
     */
    public CAInfo build() {
        final X509CAInfo x509CaInfo = new X509CAInfo(
                CertTools.getSubjectDN(testCaCertificate),
                name,
                CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA,
                "1d",
                CAInfo.SELFSIGNED,
                Collections.singletonList(testCaCertificate),
                getTestCAToken());
        x509CaInfo.setDescription("JUnit RSA CA");
        x509CaInfo.setCAId(id);
        x509CaInfo.setExpireTime(expirationDate);
        return x509CaInfo;
    }
}
