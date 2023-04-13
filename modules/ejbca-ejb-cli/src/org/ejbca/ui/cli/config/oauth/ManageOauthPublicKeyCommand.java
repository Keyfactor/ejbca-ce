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
package org.ejbca.ui.cli.config.oauth;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.text.ParseException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.oauth.OAuthPublicKey;
import org.cesecore.config.OAuthConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.util.oauth.OAuthTools;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

/**
 * Adds or removes public keys to/from already existing Trusted OAuth Provider
 *
 */
public class ManageOauthPublicKeyCommand extends BaseOAuthConfigCommand{
    private static final Logger log = Logger.getLogger(ManageOauthPublicKeyCommand.class);

    private static final String LABEL = "--label";
    private static final String ACTION = "--action";
    private static final String KEY_IDENTIFIER = "--keyidentifier";
    private static final String KEY_FILE = "--keyfile";
    private static final String KEY_METHOD = "--keymethod";
    private static final String KEY_URL = "--keyurl";
    private static final String KEY_VALUE = "--key";

    {
        registerParameter(new Parameter(LABEL, "Provider name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider name to add the key to"));
        registerParameter(new Parameter(ACTION, "Action: add or remove", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Action: add or remove"));
        registerParameter(new Parameter(KEY_IDENTIFIER, "Key identifier", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key identifier of the key which is going to be added/removed. When adding JWK keys, it can be omitted."));
        registerParameter(new Parameter(KEY_FILE, "Public key file", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Path to publickey file of public key. Can be in PEM, DER, X.509 certificate or JWK format."));
        registerParameter(new Parameter(KEY_METHOD, "Public Key input method", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Method to provide public key(--keymethod): within file (FILE), configuration url (URL) or as text value (TEXT)"));
        registerParameter(new Parameter(KEY_URL, "Config url", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Public key configuration URL"));
        registerParameter(new Parameter(KEY_VALUE, "Public key", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Public key text value"));
    }

    @Override
    public String getCommandDescription() {
        return "Adds or removes public key of Trusted OAuth Provider with defined label.";
    }

    @Override
    public String getMainCommand() {
            return "oauthproviderkey";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        CommandResult result = null;
        String action = parameters.get(ACTION);
        String label = parameters.get(LABEL);
        String kid = parameters.get(KEY_IDENTIFIER);

        switch (action.toLowerCase()) {
            case "add": {
                result = addKey(label, kid, parameters);
                break;
            }
            case "remove": {
                result = removeKey(label, kid);
                break;
            }
            default: {
                log.info("Invalid action value! Valid values are 'add' or 'remove' ");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        }
        return result;
    }

    private CommandResult addKey(final String label, final String kidParam, final ParameterContainer parameters){
        final OAuthKeyInfo oAuthKeyInfo = getOAuthConfiguration().getOauthKeyByLabel(label);

        if (oAuthKeyInfo == null) {
            log.info("Error: Trusted OAuth Provider with label: " + label + " not found!");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        String keyMethod = parameters.get(KEY_METHOD);
        if (StringUtils.isEmpty(keyMethod)) {
            log.info("Please specify method to provide public key(--keymethod): within file (FILE), configuration url (URL) or as text value (TEXT)");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        switch (keyMethod.toLowerCase()) {
            case "file": {
                String publicKey = parameters.get(KEY_FILE);
                if (!parsePublicKeyFromFile(kidParam, oAuthKeyInfo, publicKey)) {
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
                break;
            }
            case "url": {
                if (!addOauthPublicKeyFromUrl(oAuthKeyInfo, parameters.get(KEY_URL))) {
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
                break;
            }
            case "text": {
                if (!parsePublicKeyFromText(oAuthKeyInfo, kidParam, parameters.get(KEY_VALUE))) {
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
                break;
            }
        }
        if (saveGlobalConfig()) {
            log.info("Public key successfuly added to Trusted OAuth Provider with label " + label + "!");
            return CommandResult.SUCCESS;
        } else {
            log.info("Error: Failed to update configuration due to authorization issue!");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
    }

    private boolean parsePublicKeyFromFile(String kidParam, OAuthKeyInfo oAuthKeyInfo, String publicKey) {
        if (StringUtils.isEmpty(publicKey)) {
            log.info("Error: Public key file is not defined!");
            return false;
        }
        byte[] fileBytes = getFileBytes(publicKey);
        byte[] publicKeyByteArray;
        try {
            publicKeyByteArray = OAuthTools.getBytesFromOauthKey(fileBytes);
        } catch (final CertificateParsingException e) {
            log.info("Could not parse the public key file.", e);
            return false;
        }
        final String kid;
        if (StringUtils.isBlank(kidParam)) {
            kid = OAuthTools.getKeyIdFromJwkKey(fileBytes);
            if (kid == null) {
                log.info("Error: This key format does not include the key identifier. Please specify the key identifier manually with " + KEY_IDENTIFIER);
                return false;
            }
        } else {
            kid = kidParam;
        }

        if (oAuthKeyInfo.getAllKeyIdentifiers()!= null && oAuthKeyInfo.getAllKeyIdentifiers().contains(kid)) {
            log.info("Error: Key with identifier " + kid + " already exists.");
            return false;
        }
        if (isDuplicateKeyId(kid)) {
            return false;
        };
        oAuthKeyInfo.addPublicKey(kid, publicKeyByteArray);
        return true;
    }

    private boolean isDuplicateKeyId(final String kid) {
        OAuthConfiguration oAuthConfiguration = getOAuthConfiguration();
        if (oAuthConfiguration != null && oAuthConfiguration.getOauthKeys() != null && !StringUtils.isEmpty(kid)) {
            for (OAuthKeyInfo info : oAuthConfiguration.getOauthKeys().values()) {
                if (info.getKeyValues() == null) {
                    continue;
                }
                for (OAuthPublicKey key : info.getKeyValues()) {
                    if (kid.equals(key.getKeyIdentifier())) {
                        log.info("The Provider " + info.getLabel() + " already has a Public Key with the Key Identifier " + kid + 
                                ". The Key Identifier should be unique.");
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean addOauthPublicKeyFromUrl(OAuthKeyInfo oAuthKeyInfo, String url) {
        if (StringUtils.isEmpty(url)) {
            log.info("Public key config url is not defined!");
            return false;
        }
        try {
            boolean atLeastOneKeyAdded = false;
            JWKSet jwkSet = JWKSet.load(new URL(url));
            for (JWK jwk : jwkSet.getKeys()) {
                if (oAuthKeyInfo.getAllKeyIdentifiers() != null && oAuthKeyInfo.getAllKeyIdentifiers().contains(jwk.getKeyID())) {
                    log.info("Key with identifier " + jwk.getKeyID() + " already exists.");
                    continue;
                }
                if (jwk.getKeyID() != null && isDuplicateKeyId(jwk.getKeyID())) {
                    continue;
                };
                final PublicKey publicKey = jwk.toRSAKey().toPublicKey();
                final byte[] encoded = publicKey.getEncoded();
                oAuthKeyInfo.addPublicKey(jwk.getKeyID(), encoded);
                atLeastOneKeyAdded = true;
            }
            if (!atLeastOneKeyAdded) {
                return false;
            }
        } catch (MalformedURLException e) {
            log.info("Could not parse public key config url " + url);
            return false;
        } catch (ParseException | IOException | JOSEException e) {
            log.info("Could not load keys using config url " + url);
            return false;
        }
        return true;
    }

    private boolean parsePublicKeyFromText(OAuthKeyInfo oAuthKeyInfo, String kid, String value){
        if (StringUtils.isEmpty(value)) {
            log.info("Public key value is not defined!");
            return false;
        }

        byte[] inputKeyBytes = value.getBytes(StandardCharsets.US_ASCII);
        try {
            inputKeyBytes = com.keyfactor.util.Base64.decode(inputKeyBytes);
        } catch (RuntimeException e) {
            log.info("New key is not in Base64 format. Assuming it is PEM or JWK format.");
        }
        final byte[] parsedPublicKey;
        try {
            parsedPublicKey = OAuthTools.getBytesFromOauthKey(inputKeyBytes);
        } catch (CertificateParsingException e) {
            log.info("Could not parse public key from input string ");
            return false;
        }
        if (StringUtils.isBlank(kid)) {
            kid = OAuthTools.getKeyIdFromJwkKey(inputKeyBytes);
            if (kid == null) {
                log.info("Error: This key format does not include the key identifier. Please specify the key identifier manually with " + KEY_IDENTIFIER);
                return false;
            }
        }
        if (StringUtils.isEmpty(kid)) {
            log.info("Public key identifier is not defined!");
            return false;
        }
        if (oAuthKeyInfo.getAllKeyIdentifiers() != null && oAuthKeyInfo.getAllKeyIdentifiers().contains(kid)) {
            log.info("Key with identifier " + kid + " already exists.");
            return false;
        }
        if (isDuplicateKeyId(kid)) {
            return false;
        };
        oAuthKeyInfo.addPublicKey(kid, parsedPublicKey);
        return true;
    }


    private CommandResult removeKey(String label, String kid){
        final OAuthKeyInfo oAuthKeyInfo = getOAuthConfiguration().getOauthKeyByLabel(label);

        if (oAuthKeyInfo == null) {
            log.info("Trusted OAuth Provider with label: " + label + " not found!");
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        if (oAuthKeyInfo.getAllKeyIdentifiers()== null || !oAuthKeyInfo.getAllKeyIdentifiers().contains(kid)) {
            log.info("Key with identifier " + kid + " does not exist in Trusted OAuth Provider with name " + label + ".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        oAuthKeyInfo.getKeys().remove(kid);

        if (saveGlobalConfig()) {
            log.info("Public key with kid " +kid+ " successfuly removed from Trusted OAuth Provider with label: " + label + "!");
            return CommandResult.SUCCESS;
        } else {
            log.info("Failed to update configuration due to authorization issue!");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
    }
    
    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
