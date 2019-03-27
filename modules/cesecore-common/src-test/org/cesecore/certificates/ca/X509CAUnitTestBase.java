/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import static org.junit.Assert.assertNotNull;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;

/**
 * Base class for X509CAUnitTest and X509CAPartitionedCrlUnitTest
 * 
 * @version $Id$
 */
public class X509CAUnitTestBase {

    /** Subject DN for test CA objects */
    protected static final String CADN = "CN=TEST";
    /** This will be an empty list of custom certificate extensions */
    protected final AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();

    public X509CAUnitTestBase() {
        CryptoProviderTools.installBCProvider();
    }

    protected static X509CA createTestCA(CryptoToken cryptoToken, final String cadn) throws Exception {
        return createTestCA(cryptoToken, cadn, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, null, null);
    }

    protected static X509CA createTestCA(CryptoToken cryptoToken, final String cadn, final String sigAlg, Date notBefore, Date notAfter) throws Exception {
        cryptoToken.generateKeyPair(getTestKeySpec(sigAlg), CAToken.SOFTPRIVATESIGNKEYALIAS);
        cryptoToken.generateKeyPair(getTestKeySpec(sigAlg), CAToken.SOFTPRIVATEDECKEYALIAS);
        // Create CAToken
        Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        CAToken caToken = new CAToken(cryptoToken.getId(), caTokenProperties);
        // Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
        caToken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        caToken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        caToken.setSignatureAlgorithm(sigAlg);
        caToken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        // No extended services
        X509CAInfo cainfo = new X509CAInfo(cadn, "TEST", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, caToken);
        cainfo.setDescription("JUnit RSA CA");
        X509CA x509ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);
        x509ca.setCAToken(caToken);
        // A CA certificate
        final PublicKey publicKey = cryptoToken.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        final PrivateKey privateKey = cryptoToken.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        int keyusage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        X509Certificate cacert = CertTools.genSelfCertForPurpose(cadn, 10L, "1.1.1.1", privateKey, publicKey, sigAlg, true, keyusage, notBefore, notAfter, BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(cacert);
        List<Certificate> cachain = new ArrayList<>();
        cachain.add(cacert);
        x509ca.setCertificateChain(cachain);
        // Now our CA should be operational
        return x509ca;
    }

    /** @return a new empty soft auto-activated CryptoToken */
    protected CryptoToken getNewCryptoToken() {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo1234");
        CryptoToken cryptoToken;
        try {
            cryptoToken = CryptoTokenFactory.createCryptoToken(
                    SoftCryptoToken.class.getName(), cryptoTokenProperties, null, 17, "CryptoToken's name");
        } catch (NoSuchSlotException e) {
            throw new IllegalStateException("Attempted to find a slot for a soft crypto token. This should not happen.", e);
        }
        return cryptoToken;
    }

    /** @return Algorithm name for test key pair */
    protected static String getTestKeyPairAlgName(String algName) {
        if (algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410) ||
            algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145) ||
            algName.equals(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA) ||
            algName.equals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA) ||
            algName.equals(AlgorithmConstants.SIGALG_SHA512_WITH_RSA) ||
            algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1) ||
            algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1)) {
            return algName;
        } else {
            return "SHA256withRSA";
        }
    }

    protected static String getTestKeySpec(String algName) {
        if (algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410)) {
            return CesecoreConfiguration.getExtraAlgSubAlgName("gost3410", "B");
        } else if (algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145)) {
            return CesecoreConfiguration.getExtraAlgSubAlgName("dstu4145", "233");
        } else if (algName.equals(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA)) {
            return "brainpoolp224r1";
        } else if (algName.equals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA)) {
            return "prime256v1";
        } else if (algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1)) {
            return "2048"; // RSA-PSS required at least 2014 bits
        } else if (algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1)) {
            return "2048"; // RSA-PSS required at least 2014 bits
        } else if (algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA1_WITH_DSA)) {
            return "DSA1024";
        } else {
            return "1024"; // Assume RSA
        }
    }

}
