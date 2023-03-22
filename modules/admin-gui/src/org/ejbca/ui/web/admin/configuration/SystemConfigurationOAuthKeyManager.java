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

package org.ejbca.ui.web.admin.configuration;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.oauth.OAuthKeyInfo.OAuthProviderType;
import org.cesecore.authentication.oauth.OAuthKeyManager;
import org.cesecore.authentication.oauth.OAuthPublicKey;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2AuthenticationToken;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.util.OAuthProviderUIHelper;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.keys.KeyTools;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

/**
 * This class is used to manage OAuth Keys in EJBCA's system configuration. It adds some additional
 * functionality to the OAuthKeyManager, such as loading and saving state from the database and editing of
 * new OAuth Keys.
 */
public class SystemConfigurationOAuthKeyManager extends OAuthKeyManager {
    private static final Logger log = Logger.getLogger(SystemConfigurationOAuthKeyManager.class);

    private static final String EDIT_OAUTH_KEY = "editOAuthKey";
    private static final String OAUTH_KEY_SAVED = "saved";
    private static final String HIDDEN_PWD = "**********";

    private final SystemConfigurationHelper systemConfigurationHelper;
    private final OAuthKeyEditor oauthKeyEditor;
    private AuthenticationToken adminToken;
    private OAuthConfiguration oAuthConfiguration;
    private List<Pair<String, Integer>> keyBindings = new ArrayList<>();
    
    private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
    private final GlobalConfigurationSessionLocal globalConfigurationSession = ejbLocalHelper.getGlobalConfigurationSession();

    private enum OAuthKeyEditorMode {
        VIEW,
        ADD,
        EDIT
    }

    public enum PublicKeyUploadInFormOf {
        FILE("File Upload"),
        TEXT("Input text value"),
        URL("Provide key config url");
        private final String label;

        PublicKeyUploadInFormOf(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    public class OAuthKeyEditor {
        private String label;
        private String keyIdentifier;
        private OAuthProviderType type = OAuthProviderType.TYPE_GENERIC;
        private String url;
        private String client;
        private String clientSecret;
        private String realm;
        private String audience;
        private boolean audienceCheckDisabled = false;
        private String scope;
        private UploadedFile publicKeyFile;
        
        // if null, use client secret
        private Integer keyBinding = null;
        private List<OAuthPublicKey> publicKeys;
        private int skewLimit = 60000;
        private OAuthKeyInfo oauthKeyBeingEdited;
        private String defaultKeyLabel;
        private OAuthKeyEditorMode editorMode;
        PublicKeyUploadInFormOf keyInTheFormOf = PublicKeyUploadInFormOf.FILE;
        String publicKeyValue;
        String publicKeyUrl;
        
        // PingID-specific fields
        private String logoutUrl;
        private String tokenUrl;

        public String getKeyIdentifier() {
            return keyIdentifier;
        }

        public OAuthProviderType getType() {
            return type;
        }

        public void setType(OAuthProviderType type) {
            this.type = type;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }
        
        public UploadedFile getPublicKeyFile() {
            return publicKeyFile;
        }

        public int getSkewLimit() {
            return skewLimit;
        }
        
        public String getDefaultKeyLabel() {
            return defaultKeyLabel;
        }
        
        public void setKeyIdentifier(final String keyIdentifier) {
            this.keyIdentifier = keyIdentifier;
        }

        public void setPublicKeyFile(final UploadedFile publicKeyFile) {
            this.publicKeyFile = publicKeyFile;
        }

        public List<OAuthPublicKey> getPublicKeys() {
            if (publicKeys == null) {
                publicKeys = new ArrayList<>();
            }
            return publicKeys;
        }

        public void setPublicKeys(List<OAuthPublicKey> publicKeys) {
            this.publicKeys = publicKeys;
        }

        public void setSkewLimit(final int skewLimit) {
            this.skewLimit = skewLimit;
        }
        
        public void setDefaultKeyLabel(final String defaultKeyLabel) {
            this.defaultKeyLabel = defaultKeyLabel;
        }

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public String getClient() {
            return client;
        }

        public void setClient(String client) {
            this.client = client;
        }
        
        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getRealm() {
            return realm;
        }

        public void setRealm(String realm) {
            this.realm = realm;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public PublicKeyUploadInFormOf getKeyInTheFormOf() {
            return keyInTheFormOf;
        }

        public void setKeyInTheFormOf(PublicKeyUploadInFormOf keyInTheFormOf) {
            this.keyInTheFormOf = keyInTheFormOf;
        }

        public String getPublicKeyValue() {
            return publicKeyValue;
        }

        public void setPublicKeyValue(String publicKeyValue) {
            this.publicKeyValue = publicKeyValue;
        }

        public String getPublicKeyUrl() {
            return publicKeyUrl;
        }

        public void setPublicKeyUrl(String publicKeyUrl) {
            this.publicKeyUrl = publicKeyUrl;
        }

        public OAuthKeyEditorMode getEditorMode() {
            return editorMode;
        }

        public void setEditorMode(OAuthKeyEditorMode editorMode) {
            this.editorMode = editorMode;
        }

        public boolean isViewMode(){
            return this.editorMode.equals(OAuthKeyEditorMode.VIEW);
        }
        public boolean isEditMode(){
            return this.editorMode.equals(OAuthKeyEditorMode.EDIT);
        }
        public boolean isAddMode(){
            return this.editorMode.equals(OAuthKeyEditorMode.ADD);
        }

        public boolean isTypeGeneric() {
            return OAuthProviderType.TYPE_GENERIC.getIndex() == type.getIndex();
        }
        
        public boolean isTypePingId() {
            return OAuthProviderType.TYPE_PINGID.getIndex() == type.getIndex();
        }

        public boolean isTypeKeycloak() {
            return OAuthProviderType.TYPE_KEYCLOAK.getIndex() == type.getIndex();
        }

        public boolean isTypeAzure() {
            return OAuthProviderType.TYPE_AZURE.getIndex() == type.getIndex();
        }

        public boolean isShowUrls() {
            return OAuthProviderType.TYPE_PINGID.getIndex() == type.getIndex() || OAuthProviderType.TYPE_GENERIC.getIndex() == type.getIndex();
        }


        public boolean isFileForm() {
            return this.keyInTheFormOf.equals(PublicKeyUploadInFormOf.FILE);
        }

        public boolean isTextForm() {
            return this.keyInTheFormOf.equals(PublicKeyUploadInFormOf.TEXT);
        }

        public boolean isUrlForm() {
            return this.keyInTheFormOf.equals(PublicKeyUploadInFormOf.URL);
        }

        /**
         * Load an existing OAuth Key into the editor.
         */
        public void loadIntoEditor(final OAuthKeyInfo oauthKey, String defaultKeyLabel) {
            // Only replace the key if a new one was uploaded
            this.publicKeyFile = null;
            if (oauthKey.getKeys() == null) {
                this.publicKeys = new ArrayList<>();
            } else {
                this.publicKeys = new ArrayList<>(oauthKey.getKeys().values());
            }
            this.type = oauthKey.getType();
            this.url = oauthKey.getUrl();
            this.audience = oauthKey.getAudience();
            this.audienceCheckDisabled = oauthKey.isAudienceCheckDisabled();
            this.label = oauthKey.getLabel();
            this.client = oauthKey.getClient();
            this.realm = oauthKey.getRealm();
            this.clientSecret = SystemConfigurationOAuthKeyManager.HIDDEN_PWD;
            this.keyBinding = oauthKey.getKeyBinding();
            this.scope = oauthKey.getScope();
            this.skewLimit = oauthKey.getSkewLimit();
            this.oauthKeyBeingEdited = oauthKey;
            this.defaultKeyLabel = defaultKeyLabel;
            this.keyInTheFormOf = PublicKeyUploadInFormOf.FILE;
            this.publicKeyUrl = oauthKey.getPublicKeyUrl();
            
            this.logoutUrl = oauthKey.getLogoutUrl();
            this.tokenUrl = oauthKey.getTokenUrl();
        }

        /**
         * Reset all input to this OAuth Key editor.
         */
        public void clear() {
            keyIdentifier = null;
            type = OAuthProviderType.TYPE_GENERIC;
            publicKeyFile = null;
            publicKeys = null;
            url = null;
            logoutUrl = null;
            tokenUrl = null;
            keyBinding = null;
            label = null;
            client = null;
            clientSecret = null;
            audience = null;
            audienceCheckDisabled = false;
            realm = null;
            scope = null;
            oauthKeyBeingEdited = null;
            skewLimit = 60000;
            publicKeyValue = null;
            publicKeyUrl = null;
            keyInTheFormOf = PublicKeyUploadInFormOf.FILE;
        }

        /**
         * Returns the OAuth Key currently being edited by this OAuth Key editor.
         * @return the OAuth Key being edited, or null
         */
        public OAuthKeyInfo getOauthKeyBeingEdited() {
            return oauthKeyBeingEdited;
        }

        public void stopEditing() {
            oauthKeyBeingEdited = null;
            clear();
        }

        public String getLogoutUrl() {
            return logoutUrl;
        }

        public String getTokenUrl() {
            return tokenUrl;
        }

        public void setLogoutUrl(String logoutUrl) {
            this.logoutUrl = logoutUrl;
        }

        public void setTokenUrl(String tokenUrl) {
            this.tokenUrl = tokenUrl;
        }

        public final String getAudience() {
            return audience;
        }

        public final void setAudience(String audience) {
            this.audience = audience;
        }

        public Integer getKeyBinding() {
            return keyBinding;
        }

        public void setKeyBinding(Integer keyBinding) {
            this.keyBinding = keyBinding;
        }

        public boolean isAudienceCheckDisabled() {
            return audienceCheckDisabled;
        }

        public void setAudienceCheckDisabled(boolean audienceCheckDisabled) {
            this.audienceCheckDisabled = audienceCheckDisabled;
        }
    }

    public interface SystemConfigurationHelper {
        /**
         * Displays an error message to the user.
         * @param languageKey the language key of the message to show
         */
        public void addErrorMessage(String languageKey);

        /**
         * Displays an error message to the user with a formatted message.
         * @param languageKey the language key of the message to show
         * @param params additional parameters to include in the error message
         */
        public void addErrorMessage(String languageKey, Object... params);

        /**
         * Displays an information message to the user.
         * @param languageKey the language key of the message to show
         */
        public void addInfoMessage(String languageKey);

        /**
         * Saves a list of OAuth Keys to persistent storage.
         * @param oauthKeys the OAuth Keys to save
         */
        public void saveOauthKeys(List<OAuthKeyInfo> oauthKeys);
        
        /**
         * Saves a an OAuth Key as the default one to persistent storage.
         * @param defaultKey the OAuth Key to save as the default key
         */
        public void saveDefaultOauthKey(OAuthKeyInfo defaultKey);
    }

    public SystemConfigurationOAuthKeyManager(final List<OAuthKeyInfo> oAuthKeys, final SystemConfigurationHelper systemConfigurationHelper) {
        super(oAuthKeys);
        this.systemConfigurationHelper = systemConfigurationHelper;
        this.oauthKeyEditor = new OAuthKeyEditor();

        // get the names of all the key bindings
        log.trace("Loading key bindings");
        ejbLocalHelper.getInternalKeyBindingMgmtSession().getAllInternalKeyBindingInfos(AuthenticationKeyBinding.IMPLEMENTATION_ALIAS).stream()
                .sorted((b1, b2) -> b1.getName().compareTo(b2.getName())).forEach(b -> {
                    log.info("Adding key binding:" + b.getName() + ":" + b.getId());
                    keyBindings.add(Pair.of(b.getName(), b.getId()));
                });
    }
    
    public AuthenticationToken getAdminToken() {
        return adminToken;
    }
    
    public void setAdminToken(final AuthenticationToken adminToken) {
        this.adminToken = adminToken;
    }

    public List<PublicKeyUploadInFormOf> getAvailableKeyUploadForms() {
        return Arrays.asList(PublicKeyUploadInFormOf.values());
    }

    private byte[] getUploadedBytes(final UploadedFile upload) {
        if (log.isDebugEnabled()) {
            log.debug("Received uploaded public key file: " + upload.getName());
        }
        try {
            return upload.getBytes();
        } catch (final Exception e) {
            log.info("Failed to add OAuth Key.", e);
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_GENERICADDERROR", e.getLocalizedMessage());
            return null;
        }
    }

    //Adds public key to list of keys
    public String addPublicKey() {
        switch (oauthKeyEditor.getKeyInTheFormOf()) {
            case FILE: {
                return addOauthPublicKeyFromFile();
            }
            case URL: {
                return addOauthPublicKeyFromUrl();
            }
            case TEXT: {
                return addOauthPublicKeyFromTextValue();
            }
        }
        return StringUtils.EMPTY;
    }

    private String addOauthPublicKeyFromTextValue() {
        if (!validateInputNotEmpty(oauthKeyEditor.getPublicKeyValue(), "OAUTHKEYTAB_KEYVALUE_EMPTY")) {
            return StringUtils.EMPTY;
        }
        byte[] inputKeyBytes = oauthKeyEditor.getPublicKeyValue().getBytes(StandardCharsets.US_ASCII);
        try {
            inputKeyBytes = com.keyfactor.util.Base64.decode(inputKeyBytes);
        } catch (RuntimeException e) {
            log.info("New key is not in Base64 format. Assuming it is PEM or JWK format.");
        }
        final byte[] parsedPublicKey;
        try {
            parsedPublicKey = KeyTools.getBytesFromOauthKey(inputKeyBytes);
        } catch (CertificateParsingException e) {
            log.info("Could not parse public key from certificate string " + oauthKeyEditor.getPublicKeyValue());
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_BADKEYSTRING");
            return null;
        }
        final String keyIdentifier = getKeyIdentifierOrExtract(inputKeyBytes);
        if (keyIdentifier == null || validateSameKeyExists(keyIdentifier)) {
            return StringUtils.EMPTY;
        }
        final OAuthPublicKey key = new OAuthPublicKey(parsedPublicKey, keyIdentifier);
        oauthKeyEditor.getPublicKeys().add(key);
        oauthKeyEditor.setKeyIdentifier(null);
        oauthKeyEditor.setPublicKeyValue(null);
        return null;
    }

    private String addOauthPublicKeyFromUrl() {
        if (!validateInputNotEmpty(oauthKeyEditor.getPublicKeyUrl(), "OAUTHKEYTAB_KEYURL_EMPTY"))
            return StringUtils.EMPTY;
        try {
            JWKSet jwkSet = JWKSet.load(new URL(oauthKeyEditor.getPublicKeyUrl()));
            for (JWK jwk : jwkSet.getKeys()) {
                if (validateSameKeyExists(jwk.getKeyID())) {
                    continue;
                }
                final PublicKey publicKey = jwk.toRSAKey().toPublicKey();
                final byte[] encoded = publicKey.getEncoded();
                oauthKeyEditor.getPublicKeys().add(
                        new OAuthPublicKey(encoded, jwk.getKeyID()));
            }
        } catch (MalformedURLException e) {
            log.info("Could not parse public key config url " + oauthKeyEditor.getPublicKeyUrl());
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_BADKEYURL", oauthKeyEditor.getPublicKeyUrl());
            return StringUtils.EMPTY;
        } catch (ParseException | IOException | JOSEException e) {
            log.info("Could not load keys using config url " + oauthKeyEditor.getPublicKeyUrl());
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_FAILEDKEYURL", oauthKeyEditor.getPublicKeyUrl());
            return StringUtils.EMPTY;
        }
        // oauthKeyEditor.setPublicKeyUrl(null);
        return null;
    }

    private String addOauthPublicKeyFromFile() {
        if (oauthKeyEditor.getPublicKeyFile() == null) {
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_UPLOADFAILED");
            return StringUtils.EMPTY;
        }
        final byte[] uploadedFileBytes = getUploadedBytes(oauthKeyEditor.getPublicKeyFile());
        if (uploadedFileBytes == null) {
            // Error already reported
            return StringUtils.EMPTY;
        }
        final byte[] newOauthKeyPublicKey;
        try {
            newOauthKeyPublicKey = KeyTools.getBytesFromOauthKey(uploadedFileBytes);
        } catch (CertificateParsingException exception) {
            log.info("Could not parse the certificate file.", exception);
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_BADKEYFILE", oauthKeyEditor.getPublicKeyFile().getName(), exception.getMessage());
            return StringUtils.EMPTY;
        }
        final String keyIdentifier = getKeyIdentifierOrExtract(uploadedFileBytes);
        if (keyIdentifier == null || validateSameKeyExists(keyIdentifier)) {
            return StringUtils.EMPTY;
        }
        final OAuthPublicKey key = new OAuthPublicKey(newOauthKeyPublicKey, keyIdentifier);
        oauthKeyEditor.getPublicKeys().add(key);
        oauthKeyEditor.setKeyIdentifier(null);
        oauthKeyEditor.setPublicKeyFile(null);
        return null;
    }

    private String getKeyIdentifierOrExtract(byte[] newOauthKeyPublicKey) {
        String keyIdentifier = oauthKeyEditor.getKeyIdentifier();
        if (StringUtils.isBlank(keyIdentifier)) {
            // If the upload was a JWK, we can extract the Key ID from it.
            keyIdentifier = KeyTools.getKeyIdFromJwkKey(newOauthKeyPublicKey);
            if (!validateInputNotEmpty(keyIdentifier, "OAUTHKEYTAB_KEYIDENTIFIER_EMPTY")) {
                return null;
            }
        }
        return keyIdentifier;
    }

    private boolean validateSameKeyExists(String newKeyIdentifier) {
        // Currently edited public keys need to be checked separately since they are not yet part of oAuthConfiguration
        if (oauthKeyEditor != null && oauthKeyEditor.getPublicKeys() != null) {
            for (OAuthPublicKey key : oauthKeyEditor.getPublicKeys()) {
                if (newKeyIdentifier.equals(key.getKeyIdentifier())) {
                    systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_ALREADYEXISTSKEYONTHISPROVIDER", newKeyIdentifier);
                    return true;
                }
            }
        }
        if (oAuthConfiguration == null) {
            oAuthConfiguration = (OAuthConfiguration) globalConfigurationSession.getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
        }
        if (oAuthConfiguration != null && oAuthConfiguration.getOauthKeys() != null && !StringUtils.isEmpty(newKeyIdentifier)) {
            for (OAuthKeyInfo info : oAuthConfiguration.getOauthKeys().values()) {
                if (info.getKeyValues() == null) {
                    continue;
                }
                for (OAuthPublicKey key : info.getKeyValues()) {
                    if (newKeyIdentifier.equals(key.getKeyIdentifier())) {
                        systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_ALREADYEXISTSKEY", info.getLabel(), newKeyIdentifier);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private boolean validateInputNotEmpty(String keyIdentifier, String errorMessage) {
        if (StringUtils.isEmpty(keyIdentifier)) {
            systemConfigurationHelper.addErrorMessage(errorMessage);
            return false;
        }
        return true;
    }

    public String removePublicKey(OAuthPublicKey key){
        /*
         * Check that we don't lock out current administrator by changing the key id of currently used token
         */
        if ( getAdminToken()instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) getAdminToken();
            String str = Base64.toBase64String(CertTools.generateSHA256Fingerprint(key.getPublicKeyBytes()));
            if (str.equals(token.getPublicKeyBase64Fingerprint()) && !key.getKeyIdentifier().equals(oauthKeyEditor.getKeyIdentifier())) {
                systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_EDITKEYIDNOTPOSSIBLE");
                return StringUtils.EMPTY;
            }
        }
        getOauthKeyEditor().getPublicKeys().remove(key);
        return StringUtils.EMPTY;
    }

    /**
     * Adds an OAuth Key with the information stored in the OAuth Key editor.
     */
    public String addOauthKey() {
        if (!validateInputNotEmpty(oauthKeyEditor.getLabel(), "OAUTHKEYTAB_LABEL_EMPTY"))
            return StringUtils.EMPTY;

        if (oauthKeyEditor.getSkewLimit() < 0) {
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_SKEWLIMITNEGATIVE");
            return StringUtils.EMPTY;
        }

        final OAuthKeyInfo newOauthKey = new OAuthKeyInfo(oauthKeyEditor.getLabel(), oauthKeyEditor.getSkewLimit(),
                oauthKeyEditor.getType());
        newOauthKey.setUrl(newOauthKey.fixUrl(oauthKeyEditor.getUrl()));
        newOauthKey.setRealm(oauthKeyEditor.getRealm());
        newOauthKey.setScope(oauthKeyEditor.getScope());
        newOauthKey.setAudience(oauthKeyEditor.getAudience());
        newOauthKey.setAudienceCheckDisabled(oauthKeyEditor.isAudienceCheckDisabled());
        newOauthKey.setClient(oauthKeyEditor.getClient());
        newOauthKey.setTokenUrl(oauthKeyEditor.getTokenUrl());
        newOauthKey.setLogoutUrl(oauthKeyEditor.getLogoutUrl());
        newOauthKey.setClientSecretAndEncrypt(oauthKeyEditor.getClientSecret());
        if (!StringUtils.isEmpty(oauthKeyEditor.getPublicKeyUrl())) {
            newOauthKey.setPublicKeyUrl(oauthKeyEditor.getPublicKeyUrl());
        }
        if (oauthKeyEditor.getKeyBinding() != null) {
            newOauthKey.setKeyBinding(oauthKeyEditor.getKeyBinding());
        }

        if (oauthKeyEditor.getPublicKeys().isEmpty()) {
            newOauthKey.setKeys(null);
        } else {
            final Map<String, OAuthPublicKey> newOauthKeyMap = new LinkedHashMap<>();
            for (OAuthPublicKey key : oauthKeyEditor.getPublicKeys()) {
                newOauthKeyMap.put(key.getKeyIdentifier(), key);
            }
            newOauthKey.setKeys(newOauthKeyMap);
        }

        if (!super.canAdd(newOauthKey)) {
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_ALREADYEXISTS");
            return StringUtils.EMPTY;
        }
        try {
            OAuthProviderUIHelper.validateProvider(oauthKeyEditor);
        } catch(Exception e) {
            systemConfigurationHelper.addErrorMessage(e.getMessage());
            return StringUtils.EMPTY;
        }

        super.addOauthKey(newOauthKey);
        systemConfigurationHelper.saveOauthKeys(super.getAllOauthKeys());
        oauthKeyEditor.clear();
        return OAUTH_KEY_SAVED;
    }

    @Override
    public void removeOauthKey(final OAuthKeyInfo oauthKey) {
        if (getAdminToken() instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauth2token = (OAuth2AuthenticationToken) getAdminToken();
            oauthKeyEditor.loadIntoEditor(oauthKey, oauthKey.getLabel());
            oauthKeyEditor.stopEditing();
            final Collection<OAuthPublicKey> publicKeys = oauthKey.getKeys().values();
            for (OAuthPublicKey key : publicKeys) {
                String oauthKeyToBeRemovedString = Base64.toBase64String(CertTools.generateSHA256Fingerprint(key.getPublicKeyBytes()));
                if (oauth2token.getPublicKeyBase64Fingerprint().equals(oauthKeyToBeRemovedString)) {
                    systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_PUBLICKEYREMOVALNOTPOSSIBLE");
                    return;
                }
            }
        }
        super.removeOauthKey(oauthKey);
        systemConfigurationHelper.saveOauthKeys(super.getAllOauthKeys());
    }

    /**
     * Prepares for an OAuth Key to be edited. This method will load the specified OAuth Key into
     * the OAuth Key editor and set the editor in edit mode.
     * @param oauthKey the OAuth Key to be edited
     * @return the constant string EDIT_OAUTH_KEY
     */
    public String editOauthKey(final OAuthKeyInfo oauthKey, final String defaultKeyIdentifier) {
        oauthKeyEditor.loadIntoEditor(oauthKey, defaultKeyIdentifier);
        oauthKeyEditor.setEditorMode(OAuthKeyEditorMode.EDIT);
        return EDIT_OAUTH_KEY;
    }

    /**
     * Prepares for an OAuth Key to be viewed. This method will load the specified OAuth Key into
     * the OAuth Key editor and set the editor in view mode.
     * @param oauthKey the OAuth Key to be edited
     * @return the constant string EDIT_OAUTH_KEY
     */
    public String viewOauthKey(final OAuthKeyInfo oauthKey, final String defaultKeyIdentifier) {
        oauthKeyEditor.loadIntoEditor(oauthKey, defaultKeyIdentifier);
        oauthKeyEditor.setEditorMode(OAuthKeyEditorMode.VIEW);
        return EDIT_OAUTH_KEY;
    }

    /**
     * Prepares for an OAuth Key to be added. This method will clear OAuth Key in
     * the OAuth Key editor and set the editor in add mode.
     * @return the constant string EDIT_OAUTH_KEY
     */
    public String goToAddOauthKey() {
        oauthKeyEditor.clear();
        oauthKeyEditor.setEditorMode(OAuthKeyEditorMode.ADD);
        return EDIT_OAUTH_KEY;
    }
    public void toggleCurrentAliasEditMode() {
        oauthKeyEditor.setEditorMode(OAuthKeyEditorMode.EDIT);
    }
    /**
     * Retrieves the OAuth Key editor for this OAuth Key manager.
     * @return an editor which can be used to edit OAuth Keys
     */
    public OAuthKeyEditor getOauthKeyEditor() {
        return oauthKeyEditor;
    }

    public List<OAuthProviderType> getAvailableProviderTypes() {
        return Arrays.asList(OAuthProviderType.values());
    }

    /**
     * Save the OAuth Key currently being edited.
     * @return an empty string on failure or the constant string OAUTH_KEY_SAVED on success
     * @throws IllegalStateException if there is no OAuth Key to save
     */
    public String saveOauthKeyBeingEdited() {
        if (oauthKeyEditor.getOauthKeyBeingEdited() == null) {
            throw new IllegalStateException("The OAuth Key being edited has already been saved or was never loaded.");
        }

        if (oauthKeyEditor.getSkewLimit() < 0) {
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_SKEWLIMITNEGATIVE");
            return StringUtils.EMPTY;
        }
        final OAuthKeyInfo oauthKeyToUpdate = oauthKeyEditor.getOauthKeyBeingEdited();

        final String keyLabel = oauthKeyEditor.getLabel();
        if (!oauthKeyToUpdate.getLabel().equals(keyLabel) && !super.canEdit(oauthKeyToUpdate, keyLabel)) {
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_ALREADYEXISTS");
            return StringUtils.EMPTY;
        }
        /* Check if the OAuth key being edited is also set as the default key. Also check whether the key id is being changed. 
         * If both are true, update the default OAuth key entry.
         */
        if (oauthKeyEditor.getDefaultKeyLabel() != null && oauthKeyEditor.getDefaultKeyLabel().equals(oauthKeyEditor.getOauthKeyBeingEdited().getLabel())
                && !oauthKeyEditor.getOauthKeyBeingEdited().getLabel().equals(keyLabel)) {
            // Find the default key among the current OAuth keys
            OAuthKeyInfo defaultKey = null;
            for (OAuthKeyInfo info : getAllOauthKeys()) {
                if (oauthKeyEditor.getDefaultKeyLabel().equals(info.getLabel())) {
                    defaultKey = info;
                }
            }
            if (defaultKey != null) {
                systemConfigurationHelper.saveDefaultOauthKey(defaultKey);
            }
        }
        // If the client secret was not changed from the placeholder value in the UI, set the old value, i.e. no change
        if (oauthKeyEditor.getClientSecret().equals(SystemConfigurationOAuthKeyManager.HIDDEN_PWD)) {
            oauthKeyEditor.setClientSecret(oauthKeyToUpdate.getClientSecretAndDecrypt());
        }
        
        /* Make sure the edited provider does not have any unfilled mandatory fields */
        try {
            OAuthProviderUIHelper.validateProvider(oauthKeyEditor);
        } catch(Exception e) {
            systemConfigurationHelper.addErrorMessage(e.getMessage());
            return StringUtils.EMPTY;
        }

        /* Update the configuration */
        oauthKeyToUpdate.setSkewLimit(oauthKeyEditor.getSkewLimit());
        if (oauthKeyEditor.getPublicKeys().isEmpty()) {
            oauthKeyToUpdate.setKeys(null);
        } else {
            final Map<String, OAuthPublicKey> newOauthKeyMap = new LinkedHashMap<>();
            for (OAuthPublicKey key : oauthKeyEditor.getPublicKeys()) {
                newOauthKeyMap.put(key.getKeyIdentifier(), key);
            }
            oauthKeyToUpdate.setKeys(newOauthKeyMap);
        }
        
        oauthKeyToUpdate.setUrl(oauthKeyToUpdate.fixUrl(oauthKeyEditor.getUrl()));
        oauthKeyToUpdate.setLabel(oauthKeyEditor.getLabel());
        oauthKeyToUpdate.setClient(oauthKeyEditor.getClient());
        oauthKeyToUpdate.setKeyBinding(oauthKeyEditor.getKeyBinding());
        oauthKeyToUpdate.setClientSecretAndEncrypt(oauthKeyEditor.getClientSecret());
        oauthKeyToUpdate.setRealm(oauthKeyEditor.getRealm());
        oauthKeyToUpdate.setScope(oauthKeyEditor.getScope());
        oauthKeyToUpdate.setAudience(oauthKeyEditor.getAudience());
        oauthKeyToUpdate.setAudienceCheckDisabled(oauthKeyEditor.isAudienceCheckDisabled());
        oauthKeyToUpdate.setLogoutUrl(oauthKeyEditor.getLogoutUrl());
        oauthKeyToUpdate.setTokenUrl(oauthKeyEditor.getTokenUrl());
        if (!StringUtils.isEmpty(oauthKeyEditor.getPublicKeyUrl())) {
            oauthKeyToUpdate.setPublicKeyUrl(oauthKeyEditor.getPublicKeyUrl());
        }
        systemConfigurationHelper.saveOauthKeys(super.getAllOauthKeys());
        oauthKeyEditor.stopEditing();
        return OAUTH_KEY_SAVED;
    }

    public List<Pair<String, Integer>> getKeyBindings() {
        return keyBindings;
    }
}
