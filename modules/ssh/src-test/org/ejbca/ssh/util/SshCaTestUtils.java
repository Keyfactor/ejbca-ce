/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.ssh.SshCa;
import org.cesecore.certificates.ca.ssh.SshCaInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyGenParams;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ssh.ca.SshCaImpl;

import static org.junit.Assert.assertNotNull;

/**
 * SSH CA Test utilities.
 *
 * @version $Id$
 */
public abstract class SshCaTestUtils {

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SshCaTestUtils"));

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    public static SshCa addSshCa(final String caName, String keyparams, String signatureAlgorithm)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, AuthorizationDeniedException,
            NoSuchSlotException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidAlgorithmException, OperatorCreationException,
            CertificateException, CAExistsException {
        final String caDn = "CN=" + caName;
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo123");
        cryptoTokenProperties.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.TRUE.toString());
        int cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(internalAdmin, caName, SoftCryptoToken.class.getName(),
                cryptoTokenProperties, null, null);
        if (!cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS)) {
            cryptoTokenManagementSession.createKeyPair(internalAdmin, cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS, KeyGenParams.builder(keyparams).build());
        }
        if (!cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS)) {
            cryptoTokenManagementSession.createKeyPair(internalAdmin, cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS, KeyGenParams.builder(keyparams).build());
        }

        CAToken caToken = CaTestUtils.createCaToken(cryptoTokenId, signatureAlgorithm,
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA);

        final CryptoToken cryptoToken = cryptoTokenManagementProxySession.getCryptoToken(cryptoTokenId);

        SshCaInfo sshCaInfo = new SshCaInfo.SshCAInfoBuilder()
                .setName(caName)
                .setSubjectDn(caDn)
                .setCaToken(caToken)
                .setEncodedValidity("1y")
                .build();

        SshCa sshCa = new SshCaImpl(sshCaInfo);
        sshCa.setCAToken(caToken);

        // A CA certificate
        X509Certificate cacert = CertTools.genSelfCert(caDn, 10L, "1.1.1.1",
                cryptoToken.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                cryptoToken.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), signatureAlgorithm, true);
        assertNotNull("No CA certificate was generated.", cacert);
        List<Certificate> cachain = new ArrayList<>();
        cachain.add(cacert);
        sshCa.setCertificateChain(cachain);
        sshCa.setStatus(CAConstants.CA_ACTIVE);
        caSession.addCA(internalAdmin, sshCa);

        return sshCa;
    }

    /** 
     * @param signKeySpec the specification for the signature key to be generated with alias CAToken.SOFTPRIVATESIGNKEYALIAS, i.e 2048, secp256r1, etc
     * @return a new empty soft auto-activated CryptoToken, without a separate encryption keys to save key gen time, i.e. not suitable for key recovery tests
     * @throws CryptoTokenOfflineException 
     * @throws InvalidAlgorithmParameterException */
    public static CryptoToken getNewCryptoTokenSignOnly(final String signKeySpec) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo1234");
        CryptoToken cryptoToken;
        try {
            cryptoToken = CryptoTokenFactory.createCryptoToken(
                    SoftCryptoToken.class.getName(), cryptoTokenProperties, null, 17, "CryptoToken's name");
        } catch (NoSuchSlotException e) {
            throw new IllegalStateException("Attempted to find a slot for a soft crypto token. This should not happen.", e);
        }
        cryptoToken.generateKeyPair(signKeySpec, CAToken.SOFTPRIVATESIGNKEYALIAS);
        //cryptoToken.generateKeyPair("1024", CAToken.SOFTPRIVATEDECKEYALIAS);
        return cryptoToken;
    }

    /** Creates a standalone SSH CA, only in this java VM, i.e. nothing stored on EJBCA server.
     * Meant for standalone JUnit tests
     * @param cryptoToken a CryptoToken with a signKey already generated with alias CAToken.SOFTPRIVATESIGNKEYALIAS
     * @param caName the name the new CA will be given
     * @param signatureAlgorithm the signature algorithm to use for the CA, must match the key in CAToken.SOFTPRIVATESIGNKEYALIAS
     * @throws CertificateException 
     * @throws OperatorCreationException 
     * @throws InvalidAlgorithmException 
     * @throws CryptoTokenOfflineException 
     * @throws InvalidAlgorithmParameterException 
     */
    public static SshCa createTestCA(CryptoToken cryptoToken, final String caName, final String signatureAlgorithm) 
            throws OperatorCreationException, CertificateException, CryptoTokenOfflineException, InvalidAlgorithmException 
             {
        // Create CAToken
        Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, CAToken.SOFTPRIVATESIGNKEYALIAS);

        CAToken caToken = new CAToken(cryptoToken.getId(), caTokenProperties);
        caToken.setSignatureAlgorithm(signatureAlgorithm);
        caToken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);

        final String caDn = "CN=" + caName;
        SshCaInfo sshCaInfo = new SshCaInfo.SshCAInfoBuilder()
                .setName(caName)
                .setSubjectDn(caDn)
                .setCaToken(caToken)
                .setEncodedValidity("1y")
                .build();

        SshCa sshCa = new SshCaImpl(sshCaInfo);
        sshCa.setCAToken(caToken);

        // A CA certificate
        X509Certificate cacert = CertTools.genSelfCert(caDn, 10L, "1.1.1.1",
                cryptoToken.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                cryptoToken.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), signatureAlgorithm, true);
        assertNotNull("No CA certificate was generated.", cacert);
        List<Certificate> cachain = new ArrayList<>();
        cachain.add(cacert);
        sshCa.setCertificateChain(cachain);
        sshCa.setStatus(CAConstants.CA_ACTIVE);

        return sshCa;
    }

}
