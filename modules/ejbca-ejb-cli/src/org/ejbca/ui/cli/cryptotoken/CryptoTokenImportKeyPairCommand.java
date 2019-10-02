/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.cli.cryptotoken;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenSessionRemote;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * CryptoToken EJB CLI command. See {@link #getDescription()} implementation.
 * 
 * @version $Id$
 *
 */
public class CryptoTokenImportKeyPairCommand extends BaseCryptoTokenCommand {

    private static final Logger log = Logger.getLogger(CryptoTokenImportKeyPairCommand.class);

    private static final String PRIVATEKEYFILEPATH = "--privkey-file";
    private static final String PUBLICKEYFILEPATH = "--pubkey-file";
    private static final String KEYALGORITHM = "--key-algorithm";
    private static final String AUTHENTICATIONCODE = "--auth-code";
    private static final String ALIAS = "--alias";

    {
        registerParameter(new Parameter(PRIVATEKEYFILEPATH, "Private key file path", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Path to the file containing private key."));
        registerParameter(new Parameter(PUBLICKEYFILEPATH, "Public key file path", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Path to the file containing public key."));
        registerParameter(new Parameter(ALIAS, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Alias for the key pair which will be created."));
        registerParameter(new Parameter(KEYALGORITHM, "Key algorithm", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Algorithm the key is generated with, if not provided RSA will be assumed."));
        registerParameter(new Parameter(AUTHENTICATIONCODE, "Authentication code", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
                ParameterMode.PASSWORD, "Authentication code for the crypto token."));
    }

    @Override
    public String getMainCommand() {
        return "importkeypair";
    }

    @Override
    public String getCommandDescription() {
        return "Imports a key pair from file.";
    }

    @Override
    public CommandResult executeCommand(Integer cryptoTokenId, ParameterContainer parameters)
            throws AuthorizationDeniedException, CryptoTokenOfflineException {
        final String alias = parameters.get(ALIAS);
        String keyAlgorithm = parameters.get(KEYALGORITHM);
        if (keyAlgorithm == null) {
            keyAlgorithm = "RSA";
        }
        try {
            final CryptoTokenSessionRemote cryptoTokenSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenSessionRemote.class);

            KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);

            final CryptoToken currentCryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
            final byte[] currentTokendata = currentCryptoToken.getTokenData();

            InputStream targetStream = new ByteArrayInputStream(currentTokendata);
            keystore.load(targetStream, parameters.get(AUTHENTICATIONCODE).toCharArray());

            PrivateKey privateKey = loadPrivateKey(parameters.get(PRIVATEKEYFILEPATH), keyAlgorithm);
            PublicKey publicKey = loadPublicKey(parameters.get(PUBLICKEYFILEPATH), keyAlgorithm);

            final Certificate[] certchain = new Certificate[1];
            certchain[0] = CertTools.genSelfCert("CN=SignatureKeyHolder", 36500, null, privateKey, publicKey,
                    AlgorithmConstants.SIGALG_SHA256_WITH_RSA, true);
            keystore.setKeyEntry(alias, privateKey, null, certchain);

            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            keystore.store(baos, parameters.get(AUTHENTICATIONCODE).toCharArray());

            final Properties properties = currentCryptoToken.getProperties();
            CryptoToken newCryptoToken = new SoftCryptoToken();

            newCryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), properties, baos.toByteArray(), cryptoTokenId,
                    currentCryptoToken.getTokenName());
            cryptoTokenSession.mergeCryptoToken(newCryptoToken);
            return CommandResult.SUCCESS;
        } catch (Exception e) {
            e.printStackTrace();
            getLogger().error("Creating key pair with the alias  " + alias + " failed : " + e);
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    private PrivateKey loadPrivateKey(final String filename, final String algorithm)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKey = getKey(filename);
        privateKey = privateKey.replace("-----BEGIN RSA PRIVATE KEY-----\n", "");
        privateKey = privateKey.replace("-----END RSA PRIVATE KEY-----", "");
        final byte[] keyBytes = Base64.decode(privateKey.getBytes());
        final KeyFactory kf = KeyFactory.getInstance(algorithm);
        final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return kf.generatePrivate(spec);
    }

    private PublicKey loadPublicKey(final String filename, final String algorithm)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKey = getKey(filename);
        publicKey = publicKey.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKey = publicKey.replace("-----END PUBLIC KEY-----", "");
        final byte[] keyBytes = Base64.decode(publicKey.getBytes());
        final KeyFactory kf = KeyFactory.getInstance(algorithm);
        final X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return kf.generatePublic(spec);
    }

    private String getKey(final String filename) throws IOException {
        // Read key from file
        String strKeyPEM = "";
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String line;
        while ((line = br.readLine()) != null) {
            strKeyPEM += line + "\n";
        }
        br.close();
        return strKeyPEM;
    }
}
