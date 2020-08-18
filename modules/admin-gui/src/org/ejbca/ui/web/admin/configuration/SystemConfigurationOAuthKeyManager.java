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
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.oauth.OAuthKeyManager;
import org.cesecore.keys.util.KeyTools;

/**
 * This class is used to manage OAuth Keys in EJBCA's system configuration. It adds some additional
 * functionality to the OAuthKeyManager, such as loading and saving state from the database, editing of
 * new OAuth Keys, checking whether a CT log is in use before removing it and language awareness.
 * 
 * @version $Id$
 */
public class SystemConfigurationOAuthKeyManager extends OAuthKeyManager {
    private static final String EDIT_OAUTH_KEY = "editOAuthKey";
    private static final String OAUTH_KEY_SAVED = "saved";
    private static final Logger log = Logger.getLogger(SystemConfigurationOAuthKeyManager.class);
    private final SystemConfigurationHelper systemConfigurationHelper;
    private final OAuthKeyEditor oauthKeyEditor;

    public class OAuthKeyEditor {
        private String keyIdentifier;
        private UploadedFile publicKeyFile;
        private int skewLimit = 5000;
        private OAuthKeyInfo oauthKeyBeingEdited;

        public String getOauthKeyIdentifier() {
            return keyIdentifier;
        }

        public UploadedFile getPublicKeyFile() {
            return publicKeyFile;
        }
        
        public int getSkewLimit() {
            return skewLimit;
        }

        public void setOauthKeyIdentifier(final String issuer) {
            this.keyIdentifier = issuer;
        }

        public void setPublicKeyFile(final UploadedFile publicKeyFile) {
            this.publicKeyFile = publicKeyFile;
        }
        
        public void setSkewLimit(final int skewLimit) {
            this.skewLimit = skewLimit;
        }

        /**
         * Load an existing CT log into the editor.
         */
        public void loadIntoEditor(final OAuthKeyInfo oauthKey) {
            // Only replace the key if a new one was uploaded
            this.publicKeyFile = null;
            this.keyIdentifier = oauthKey.getKeyIdentifier();
            this.skewLimit = oauthKey.getSkewLimit();
            this.oauthKeyBeingEdited = oauthKey;
        }

        /**
         * Reset all input to this CT log editor.
         */
        public void clear() {
            keyIdentifier = null;
            publicKeyFile = null;
        }

        /**
         * Returns the CT log currently being edited by this CT log editor.
         * @return the CT log being edited, or null
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
         * @param oAuthKeys the OAuth Keys to save
         */
        public void saveOAuthKeys(List<OAuthKeyInfo> oAuthKeys);
    }

    public SystemConfigurationOAuthKeyManager(final List<OAuthKeyInfo> oAuthKeys, final SystemConfigurationHelper systemConfigurationHelper) {
        super(oAuthKeys);
        this.systemConfigurationHelper = systemConfigurationHelper;
        this.oauthKeyEditor = new OAuthKeyEditor();
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
            log.info("Failed to add CT Log.", e);
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_GENERICADDERROR", e.getLocalizedMessage());
            return null;
        }
    }

    /**
     * Adds a CT log with the information stored in the CT log editor.
     */
    public void addOauthKey() {
        if (oauthKeyEditor.getPublicKeyFile() == null) {
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_UPLOADFAILED");
            return;
        }

        final byte[] newOAuthKeyPublicKey = getOauthKeyPublicKey(oauthKeyEditor.getPublicKeyFile());
        if (newOAuthKeyPublicKey == null) {
            // Error already reported
            return;
        }

        final OAuthKeyInfo newOAuthKey = new OAuthKeyInfo(oauthKeyEditor.getOauthKeyIdentifier(), newOAuthKeyPublicKey, oauthKeyEditor.getSkewLimit());

        if (!super.canAdd(newOAuthKey)) {
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_ALREADYEXISTS", newOAuthKey.toString());
            return;
        }

        super.addOauthKey(newOAuthKey);
        systemConfigurationHelper.saveOAuthKeys(super.getAllOauthKeys());
        oauthKeyEditor.clear();
    }

    @Override
    public void removeOauthKey(final OAuthKeyInfo oauthKey) {
        super.removeOauthKey(oauthKey);
        systemConfigurationHelper.saveOAuthKeys(super.getAllOauthKeys());
    }

    /**
     * Prepares for a CT log to be edited. This method will load the specified CT log into
     * the CT log editor and set the editor in edit mode.
     * @param oauthKey the CT log to be edited
     * @return the constant string EDIT_OAUTH_KEY
     */
    public String editOauthKey(final OAuthKeyInfo oauthKey) {
        oauthKeyEditor.loadIntoEditor(oauthKey);
        return EDIT_OAUTH_KEY;
    }

    /**
     * Retrieves the CT log editor for this CT log manager.
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

        /* Validate data entry by the user */
        if (oauthKeyEditor.getPublicKeyFile() != null) {
            final byte[] keyBytes = getOauthKeyPublicKey(oauthKeyEditor.getPublicKeyFile());
            if (keyBytes == null) {
                // Error already reported
                return StringUtils.EMPTY;
            }
        }
        if (oauthKeyEditor.getSkewLimit() <= 0) {
            systemConfigurationHelper.addErrorMessage("OAUTHKEYTAB_SKEWLIMITNEGATIVE");
            return StringUtils.EMPTY;
        }

        /* Update the configuration */
        final OAuthKeyInfo oauthKeyToUpdate = oauthKeyEditor.getOauthKeyBeingEdited();
        final String keyIdentifier = oauthKeyEditor.getOauthKeyIdentifier();
        final byte[] keyBytes = oauthKeyEditor.getPublicKeyFile() != null ? getOauthKeyPublicKey(oauthKeyEditor.getPublicKeyFile())
                : oauthKeyEditor.getOauthKeyBeingEdited().getPublicKeyBytes();
        final int skewLimit = oauthKeyEditor.getSkewLimit();
        oauthKeyToUpdate.setOauthPublicKey(keyBytes);
        oauthKeyToUpdate.setSkewLimit(skewLimit);
        oauthKeyToUpdate.setKeyIdentifier(keyIdentifier);
        systemConfigurationHelper.saveOAuthKeys(super.getAllOauthKeys());
        oauthKeyEditor.stopEditing();
        return OAUTH_KEY_SAVED;
    }
}
