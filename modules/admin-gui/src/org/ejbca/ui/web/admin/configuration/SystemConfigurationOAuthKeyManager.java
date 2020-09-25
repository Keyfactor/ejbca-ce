/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.admin.configuration;

import java.security.cert.CertificateParsingException;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.oauth.OAuthKeyManager;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2AuthenticationToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;

/**
 * This class is used to manage OAuth Keys in EJBCA's system configuration. It adds some additional
 * functionality to the OAuthKeyManager, such as loading and saving state from the database and editing of
 * new OAuth Keys.
 */
public class SystemConfigurationOAuthKeyManager extends OAuthKeyManager {
    private static final String EDIT_OAUTH_KEY = "editOAuthKey";
    private static final String OAUTH_KEY_SAVED = "saved";
    private static final Logger log = Logger.getLogger(SystemConfigurationOAuthKeyManager.class);
    private final SystemConfigurationHelper systemConfigurationHelper;
    private final OAuthKeyEditor oauthKeyEditor;
    private AuthenticationToken adminToken;

    public class OAuthKeyEditor {
        private String keyIdentifier;
        private UploadedFile publicKeyFile;
        private int skewLimit = 60000;
        private OAuthKeyInfo oauthKeyBeingEdited;
        private String defaultKeyIdentifier;
        
        public String getKeyIdentifier() {
            return keyIdentifier;
        }

        public UploadedFile getPublicKeyFile() {
            return publicKeyFile;
        }

        public int getSkewLimit() {
            return skewLimit;
        }
        
        public String getDefaultKeyIdentifier() {
            return defaultKeyIdentifier;
        }
        
        public void setKeyIdentifier(final String keyIdentifier) {
            this.keyIdentifier = keyIdentifier;
        }

        public void setPublicKeyFile(final UploadedFile publicKeyFile) {
            this.publicKeyFile = publicKeyFile;
        }

        public void setSkewLimit(final int skewLimit) {
            this.skewLimit = skewLimit;
        }
        
        public void setDefaultKeyIdentifier(final String defaultKeyIdentifier) {
            this.defaultKeyIdentifier = defaultKeyIdentifier;
        }
        
        /**
         * Load an existing OAuth Key into the editor.
         */
        public void loadIntoEditor(final OAuthKeyInfo oauthKey, String defaultKeyIdentifier) {
            // Only replace the key if a new one was uploaded
            this.publicKeyFile = null;
            this.keyIdentifier = oauthKey.getKeyIdentifier();
            this.skewLimit = oauthKey.getSkewLimit();
            this.oauthKeyBeingEdited = oauthKey;
            this.defaultKeyIdentifier = defaultKeyIdentifier;
        }

        /**
         * Reset all input to this OAuth Key editor.
         */
        public void clear() {
            keyIdentifier = null;
            publicKeyFile = null;
            skewLimit = 60000;
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
    }
    
    public AuthenticationToken getAdminToken() {
        return adminToken;
    }
    
    public void setAdminToken(final AuthenticationToken adminToken) {
        this.adminToken = adminToken;
    }

    private byte[] getOauthKeyPublicKey(final UploadedFile upload) {
        if (log.isDebugEnabled()) {
            log.debug("Received uploaded public key file: " + upload.getName());
        }
        try {
            byte[] uploadedFileBytes = upload.getBytes();
            return KeyTools.getBytesFromPublicKeyFile(uploadedFileBytes);
        } catch (final CertificateParsingException e) {
            log.info("Could not parse the public key file.", e);
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_BADKEYFILE", upload.getName(), e.getMessage());
            return null;
        } catch (final Exception e) {
            log.info("Failed to add OAuth Key.", e);
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_GENERICADDERROR", e.getLocalizedMessage());
            return null;
        }
    }

    /**
     * Adds an OAuth Key with the information stored in the OAuth Key editor.
     */
    public void addOauthKey() {
        if (oauthKeyEditor.getPublicKeyFile() == null) {
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_UPLOADFAILED");
            return;
        }

        if (oauthKeyEditor.getSkewLimit() < 0) {
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_SKEWLIMITNEGATIVE");
            return;
        }

        final byte[] newOauthKeyPublicKey = getOauthKeyPublicKey(oauthKeyEditor.getPublicKeyFile());
        if (newOauthKeyPublicKey == null) {
            // Error already reported
            return;
        }

        final OAuthKeyInfo newOauthKey = new OAuthKeyInfo(oauthKeyEditor.getKeyIdentifier(), newOauthKeyPublicKey, oauthKeyEditor.getSkewLimit());

        if (!super.canAdd(newOauthKey)) {
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_ALREADYEXISTS");
            return;
        }

        super.addOauthKey(newOauthKey);
        systemConfigurationHelper.saveOauthKeys(super.getAllOauthKeys());
        oauthKeyEditor.clear();
    }

    @Override
    public void removeOauthKey(final OAuthKeyInfo oauthKey) {
        if (getAdminToken() instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauth2token = (OAuth2AuthenticationToken) getAdminToken();
            oauthKeyEditor.loadIntoEditor(oauthKey, oauthKey.getKeyIdentifier());
            String oauthKeyToBeRemovedString = Base64.toBase64String(CertTools.generateSHA256Fingerprint(oauthKeyEditor.oauthKeyBeingEdited.getPublicKeyBytes()));
            oauthKeyEditor.stopEditing();
            if (oauth2token.getPublicKeyBase64Fingerprint().equals(oauthKeyToBeRemovedString)) {
                systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_PUBLICKEYREMOVALNOTPOSSIBLE");
                return;
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
        return EDIT_OAUTH_KEY;
    }

    /**
     * Retrieves the OAuth Key editor for this OAuth Key manager.
     * @return an editor which can be used to edit OAuth Keys
     */
    public OAuthKeyEditor getOauthKeyEditor() {
        return oauthKeyEditor;
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
        if (oauthKeyEditor.getPublicKeyFile() != null) {
            final byte[] keyBytes = getOauthKeyPublicKey(oauthKeyEditor.getPublicKeyFile());
            if (keyBytes == null) {
                // Error already reported
                return StringUtils.EMPTY;
            }
        }
        if (oauthKeyEditor.getSkewLimit() < 0) {
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_SKEWLIMITNEGATIVE");
            return StringUtils.EMPTY;
        }
        final OAuthKeyInfo oauthKeyToUpdate = oauthKeyEditor.getOauthKeyBeingEdited();
        
        /*
         * Check that we don't lock out current administrator by changing the key id of currently used token
         */
        if ((getAdminToken() != null) && getAdminToken()instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken adminToken = (OAuth2AuthenticationToken) getAdminToken();
            String str = Base64.toBase64String(CertTools.generateSHA256Fingerprint(oauthKeyToUpdate.getPublicKeyBytes()));
            if (str.equals(adminToken.getPublicKeyBase64Fingerprint()) && !oauthKeyToUpdate.getKeyIdentifier().equals(oauthKeyEditor.getKeyIdentifier())) {
                systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_EDITKEYIDNOTPOSSIBLE");
                return StringUtils.EMPTY;
            }
        }
        final String keyIdentifier = oauthKeyEditor.getKeyIdentifier();
        if (!super.canEdit(oauthKeyToUpdate, keyIdentifier)) {
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_ALREADYEXISTS");
            return StringUtils.EMPTY;
        }
        /* Check if the OAuth key being edited is also set as the default key. Also check whether the key id is being changed. 
         * If both are true, update the default OAuth key entry.
         */
        if (oauthKeyEditor.getDefaultKeyIdentifier() != null && oauthKeyEditor.getDefaultKeyIdentifier().equals(oauthKeyEditor.getOauthKeyBeingEdited().getKeyIdentifier())
                && !oauthKeyEditor.getOauthKeyBeingEdited().getKeyIdentifier().equals(keyIdentifier)) {
            // Find the default key among the current OAuth keys
            OAuthKeyInfo defaultKey = null;
            for (OAuthKeyInfo info : getAllOauthKeys()) {
                if (oauthKeyEditor.getDefaultKeyIdentifier().equals(info.getKeyIdentifier())) {
                    defaultKey = info;
                }
            }
            if (defaultKey != null) {
                systemConfigurationHelper.saveDefaultOauthKey(defaultKey);
            }
        }

        /* Update the configuration */
        final byte[] keyBytes = oauthKeyEditor.getPublicKeyFile() != null ? getOauthKeyPublicKey(oauthKeyEditor.getPublicKeyFile())
                : oauthKeyEditor.getOauthKeyBeingEdited().getPublicKeyBytes();
        final int skewLimit = oauthKeyEditor.getSkewLimit();
        oauthKeyToUpdate.setPublicKeyBytes(keyBytes);
        oauthKeyToUpdate.setSkewLimit(skewLimit);
        oauthKeyToUpdate.setKeyIdentifier(keyIdentifier);
        systemConfigurationHelper.saveOauthKeys(super.getAllOauthKeys());
        oauthKeyEditor.stopEditing();
        return OAUTH_KEY_SAVED;
    }
}
