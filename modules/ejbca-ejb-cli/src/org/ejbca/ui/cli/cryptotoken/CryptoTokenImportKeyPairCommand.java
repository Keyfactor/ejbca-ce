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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenSessionRemote;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

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
    private static final String KEYSPEC = "--key-spec";
    private static final String AUTHENTICATIONCODE = "--auth-code";
    private static final String ALIAS = "--alias";
    private static final String PRIVKEYPASS = "--privkey-pass";

    private static final String PRIV_KEY_HEADER = "-----BEGIN PRIVATE KEY-----\n";
    private static final String PRIV_KEY_FOOTER = "-----END PRIVATE KEY-----";

    private static final String RSA_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----\n";
    private static final String RSA_KEY_FOOTER = "-----END RSA PRIVATE KEY-----";

    private static final String EC_KEY_HEADER = "-----BEGIN EC PRIVATE KEY-----\n";
    private static final String EC_KEY_FOOTER = "-----END EC PRIVATE KEY-----";
    
    private static final String DSA_KEY_HEADER = "-----BEGIN DSA PRIVATE KEY-----\n";
    private static final String DSA_KEY_FOOTER = "-----END DSA PRIVATE KEY-----";
    
    {
        registerParameter(new Parameter(PRIVATEKEYFILEPATH, "Private key file path", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Path to the file containing private key."));
        registerParameter(new Parameter(PUBLICKEYFILEPATH, "Public key file path", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Path to the file containing public key."));
        registerParameter(new Parameter(ALIAS, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Alias for the key pair which will be created."));
        registerParameter(new Parameter(KEYALGORITHM, "Key algorithm", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Algorithm the key is generated with (RSA, EC, DSA), if not provided RSA will be assumed."));
        registerParameter(new Parameter(KEYSPEC, "Key specification", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Specification used to generated the key, if not provided SHA256 will be assumed. Format could be any of the followings: "
                + "SHA1, SHA256, SHA384, SHA512, SHA3-256, SHA3-384, SHA3-512."));
        registerParameter(new Parameter(AUTHENTICATIONCODE, "Authentication code", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Authentication code for the crypto token."));
        registerParameter(new Parameter(PRIVKEYPASS, "Privatekey password", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Password used to protect private key (if any)."));
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
        String keySpec = parameters.get(KEYSPEC);                
        char[] privateKeyPass = null; 
        
        if (keyAlgorithm == null) {
            keyAlgorithm = "RSA";
        }
        if (keySpec == null) {
            keySpec = "SHA256";
        }
        
        if (parameters.get(PRIVKEYPASS) != null) {
            privateKeyPass = parameters.get(PRIVKEYPASS).toCharArray();
        }
        try {
            final CryptoTokenSessionRemote cryptoTokenSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenSessionRemote.class);
            final CryptoToken currentCryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
            final byte[] currentTokendata = currentCryptoToken.getTokenData();

            final InputStream targetStream = new ByteArrayInputStream(currentTokendata);

            KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            
            String authCode = parameters.get(AUTHENTICATIONCODE);
            if (authCode == null) {
                log.info("Enter authentication code for the crypto token: ");
                // Read the password, but mask it so we don't display it on the console
                authCode = String.valueOf(System.console().readPassword());
            }
            
            keystore.load(targetStream, authCode.toCharArray());

            PrivateKey privateKey = loadPrivateKey(parameters.get(PRIVATEKEYFILEPATH), keyAlgorithm);
            PublicKey publicKey = loadPublicKey(parameters.get(PUBLICKEYFILEPATH), keyAlgorithm);
            
            // Dummy certificate chain to hold keys
            final Certificate[] certchain = new Certificate[1];
            final String signatureAlgorithm = getSignatureAlgorithm(keyAlgorithm + "-" + keySpec);
            
            certchain[0] = CertTools.genSelfCert("CN=SignatureKeyHolder", 36500, null, privateKey, publicKey,
                    signatureAlgorithm, true);
            keystore.setKeyEntry(alias, privateKey, privateKeyPass, certchain);

            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            keystore.store(baos, authCode.toCharArray());

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
        switch (algorithm) {
        case "EC":
            privateKey = privateKey.replace(EC_KEY_HEADER, StringUtils.EMPTY);
            privateKey = privateKey.replace(EC_KEY_FOOTER, StringUtils.EMPTY);
            break;
        case "DSA":
            privateKey = privateKey.replace(DSA_KEY_HEADER, StringUtils.EMPTY);
            privateKey = privateKey.replace(DSA_KEY_FOOTER, StringUtils.EMPTY);
            break;
        default:
            privateKey = privateKey.replace(RSA_KEY_HEADER, StringUtils.EMPTY);
            privateKey = privateKey.replace(RSA_KEY_FOOTER, StringUtils.EMPTY);
            break;
        }
        
        // Sometimes key file contains just these headers
        privateKey = privateKey.replace(PRIV_KEY_HEADER, StringUtils.EMPTY);
        privateKey = privateKey.replace(PRIV_KEY_FOOTER, StringUtils.EMPTY);
        
        final byte[] keyBytes = Base64.decode(privateKey.getBytes());
        final KeyFactory kf = KeyFactory.getInstance(algorithm);
        final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return kf.generatePrivate(spec);
    }

    private PublicKey loadPublicKey(final String filename, final String algorithm)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKey = getKey(filename);
        publicKey = publicKey.replace("-----BEGIN PUBLIC KEY-----\n", StringUtils.EMPTY);
        publicKey = publicKey.replace("-----END PUBLIC KEY-----", StringUtils.EMPTY);
        final byte[] keyBytes = Base64.decode(publicKey.getBytes());
        final KeyFactory kf = KeyFactory.getInstance(algorithm);
        final X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return kf.generatePublic(spec);
    }

    private String getKey(final String filename) throws IOException {
        // Read key from file
        String strKeyPEM = StringUtils.EMPTY;
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String line;
        while ((line = br.readLine()) != null) {
            strKeyPEM += line + "\n";
        }
        br.close();
        return strKeyPEM;
    }
    
    private String getSignatureAlgorithm(final String keyAlgorithm) {
        String signatureAlgorithm = null;
        switch (keyAlgorithm) {
        case "DSA-SHA1":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA1_WITH_DSA;
            break;
        case "RSA-SHA256":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
            break;
        case "RSA-SHA384":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA384_WITH_RSA;
            break;
        case "RSA-SHA512":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA512_WITH_RSA;
            break;
        case "RSA-SHA3-256":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA;
            break;
        case "RSA-SHA3-384":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA;
            break;
        case "RSA-SHA3-512":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA;
            break;
        case "EC-SHA1":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA;
            break;
        case "EC-SHA256":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
            break;
        case "EC-SHA384":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA;
            break;
        case "EC-SHA512":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA;
            break; 
        case "EC-SHA3-256":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA;
            break;
        case "EC-SHA3-384":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA;
            break;
        case "EC-SHA3-512":
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA;
            break;
        default:
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
            break;
        }
        return signatureAlgorithm;
    }
    
}
