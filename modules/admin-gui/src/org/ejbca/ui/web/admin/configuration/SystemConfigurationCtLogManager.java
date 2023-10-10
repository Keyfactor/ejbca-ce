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

import java.security.cert.CertificateParsingException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.servlet.http.Part;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.CtLogManager;

import com.keyfactor.util.keys.KeyTools;

/**
 * This class is used to manage CT logs in EJBCA's system configuration. It adds some additional
 * functionality to the CtLogManager, such as loading and saving state from the database, editing of
 * new CT logs, checking whether a CT log is in use before removing it and language awareness.
 *
 */
public class SystemConfigurationCtLogManager extends CtLogManager {
    private static final String EDIT_CT_LOG = "editCTLog";
    private static final String CT_LOG_SAVED = "saved";
    private static final Logger log = Logger.getLogger(SystemConfigurationCtLogManager.class);
    private final SystemConfigurationHelper systemConfigurationHelper;
    private final CtLogEditor ctLogEditor;

    public class CtLogEditor {
        private String url;
        private Part publicKeyFile;
        private String label;
        private int timeout = 5000;
        private CTLogInfo ctLogBeingEdited;
        private boolean isAcceptingByExpirationYear;
        private boolean useIntervalAcception;
        private String expirationYearRequired;
        private LocalDate intervalStart;
        private LocalDate intervalEnd;

        public String getCtLogUrl() {
            if (StringUtils.isEmpty(url)) {
                return null;
            }
            return CTLogInfo.fixUrl(url);
        }

        public Part getPublicKeyFile() {
            return publicKeyFile;
        }

        public String getCtLogLabel() {
            return label;
        }

        public int getCtLogTimeout() {
            return timeout;
        }

        public void setCtLogUrl(final String url) {
            this.url = url;
        }

        public void setPublicKeyFile(final Part publicKeyFile) {
            this.publicKeyFile = publicKeyFile;
        }

        public void setCtLogLabel(final String label) {
            this.label = label;
        }

        public void setCtLogTimeout(final int timeout) {
            this.timeout = timeout;
        }

        public boolean hasValidUrl() {
            return url.contains("://");
        }

        /**
         * Set a boolean indicating whether the log being edited only accepts certificates with
         * a certain year of expiry, e.g. all certificates expiring in 2019.
         * @param isAcceptingByExpirationYear true if the log is discriminating based on year of expiry
         */
        public void setIsAcceptingByExpirationYear(final boolean isAcceptingByExpirationYear) {
            this.isAcceptingByExpirationYear = isAcceptingByExpirationYear;
        }

        public boolean getIsAcceptingByExpirationYear() {
            return isAcceptingByExpirationYear;
        }

        public boolean isUseIntervalAcception() {
            return useIntervalAcception;
        }

        public void setUseIntervalAcception(boolean useIntervalAcception) {
            this.useIntervalAcception = useIntervalAcception;
        }

        public void setExpirationYearRequired(final String expirationYearRequired) {
            this.expirationYearRequired = expirationYearRequired;
        }

        public String getExpirationYearRequired() {
            return expirationYearRequired;
        }

        public LocalDate getIntervalStart() {
            return intervalStart;
        }
        public Date getIntervalStartAsDate() {
            return Date.from(intervalStart.atStartOfDay(ZoneOffset.UTC).toInstant());
        }

        public void setIntervalStart(LocalDate intervalStart) {
            this.intervalStart = intervalStart;
        }

        public LocalDate getIntervalEnd() {
            return intervalEnd;
        }
        

        public Date getIntervalEndAsDate() {
            return Date.from(intervalEnd.atStartOfDay(ZoneOffset.UTC).toInstant());
        }

        public void setIntervalEnd(LocalDate intervalEnd) {
            this.intervalEnd = intervalEnd;
        }

        /**
         * Load an existing CT log into the editor.
         */
        public void loadIntoEditor(final CTLogInfo ctLog) {
            this.label = ctLog.getLabel();
            // Only replace the key if a new one was uploaded
            this.publicKeyFile = null;
            this.timeout = ctLog.getTimeout();
            this.url = ctLog.getUrl();
            this.ctLogBeingEdited = ctLog;
            this.isAcceptingByExpirationYear = ctLog.getExpirationYearRequired() != null || ctLog.getIntervalStart() != null;
            this.expirationYearRequired = ctLog.getExpirationYearRequired() == null ?
                    String.valueOf(Calendar.getInstance().get(Calendar.YEAR)) : String.valueOf(ctLog.getExpirationYearRequired());
            this.useIntervalAcception = ctLog.getIntervalStart() != null;
            this.intervalEnd = (ctLog.getIntervalEnd() != null ? LocalDate.ofInstant(ctLog.getIntervalEnd().toInstant(), ZoneOffset.UTC)
                    : null);
            this.intervalStart = (ctLog.getIntervalStart() != null ? LocalDate.ofInstant(ctLog.getIntervalStart().toInstant(), ZoneOffset.UTC)
                    : null);
        }

        /**
         * Reset all input to this CT log editor.
         */
        public void clear() {
            url = null;
            publicKeyFile = null;
            label = null;
            timeout = 5000;
        }

        /**
         * Returns the CT log currently being edited by this CT log editor.
         * @return the CT log being edited, or null
         */
        public CTLogInfo getCtLogBeingEdited() {
            return ctLogBeingEdited;
        }

        public void stopEditing() {
            ctLogBeingEdited = null;
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
         * Saves a list of CT logs to persistent storage.
         * @param ctLogs the CT logs to save
         */
        public void saveCtLogs(List<CTLogInfo> ctLogs);

        /**
         * Get a list with names of certificate profiles which references a particular CT log.
         * @param ctLog a CT log which should be checked
         * @return a list of profile names, referencing the CT log given as input or empty if the CT log is not in use
         */
        public List<String> getCertificateProfileNamesByCtLog(CTLogInfo ctLog);
    }

    public SystemConfigurationCtLogManager(final List<CTLogInfo> ctLogs, final SystemConfigurationHelper systemConfigurationHelper) {
        super(ctLogs);
        this.systemConfigurationHelper = systemConfigurationHelper;
        this.ctLogEditor = new CtLogEditor();
    }

    private byte[] getCtLogPublicKey(final Part upload) {
        if (log.isDebugEnabled()) {
            log.debug("Received uploaded public key file: " + upload.getName());
        }
        try {
            byte[] uploadedFileBytes = IOUtils.toByteArray(upload.getInputStream(), upload.getSize());    
            return KeyTools.getBytesFromCtLogKey(uploadedFileBytes);
        } catch (final CertificateParsingException e) {
            log.info("Could not parse the public key file.", e);
            systemConfigurationHelper.addErrorMessage("CTLOGTAB_BADKEYFILE", upload.getName(), e.getMessage());
            return null;
        } catch (final Exception e) {
            log.info("Failed to add CT Log.", e);
            systemConfigurationHelper.addErrorMessage("CTLOGTAB_GENERICADDERROR", e.getLocalizedMessage());
            return null;
        }
    }

    /**
     * Adds a CT log with the information stored in the CT log editor.
     */
    public void addCtLog() {
        if (ctLogEditor.getCtLogUrl() == null || !ctLogEditor.getCtLogUrl().contains("://")) {
            systemConfigurationHelper.addErrorMessage("CTLOGTAB_MISSINGPROTOCOL");
            return;
        }
        if (ctLogEditor.getPublicKeyFile() == null) {
            systemConfigurationHelper.addErrorMessage("CTLOGTAB_UPLOADFAILED");
            return;
        }
        if (ctLogEditor.getCtLogTimeout() <= 0) {
            systemConfigurationHelper.addErrorMessage("CTLOGTAB_TIMEOUTNEGATIVE");
            return;
        }

        final byte[] newCtLogPublicKey = getCtLogPublicKey(ctLogEditor.getPublicKeyFile());
        if (newCtLogPublicKey == null) {
            // Error already reported
            return;
        }

        final CTLogInfo newCtLog = new CTLogInfo(ctLogEditor.getCtLogUrl(), newCtLogPublicKey, ctLogEditor.getCtLogLabel(),
                ctLogEditor.getCtLogTimeout());

        if (!super.canAdd(newCtLog)) {
            systemConfigurationHelper.addErrorMessage("CTLOGTAB_ALREADYEXISTS", newCtLog.toString());
            return;
        }

        super.addCtLog(newCtLog);
        systemConfigurationHelper.saveCtLogs(super.getAllCtLogs());
        ctLogEditor.clear();
    }

    @Override
    public void removeCtLog(final CTLogInfo ctLog) {
        final List<String> usedByProfiles = systemConfigurationHelper.getCertificateProfileNamesByCtLog(ctLog);
        if (!usedByProfiles.isEmpty()) {
            systemConfigurationHelper.addErrorMessage("CTLOGTAB_INUSEBYPROFILES", StringUtils.join(usedByProfiles, ", "));
            return;
        }
        super.removeCtLog(ctLog);
        systemConfigurationHelper.saveCtLogs(super.getAllCtLogs());
    }

    @Override
    public void moveUp(final CTLogInfo ctLog) {
        super.moveUp(ctLog);
        systemConfigurationHelper.saveCtLogs(super.getAllCtLogs());
    }

    @Override
    public void moveDown(final CTLogInfo ctLog) {
        super.moveDown(ctLog);
        systemConfigurationHelper.saveCtLogs(super.getAllCtLogs());
    }

    /**
     * Prepares for a CT log to be edited. This method will load the specified CT log into
     * the CT log editor and set the editor in edit mode.
     * @param ctLog the CT log to be edited
     * @return the constant string EDIT_CT_LOG
     */
    public String editCtLog(final CTLogInfo ctLog) {
        ctLogEditor.loadIntoEditor(ctLog);
        return EDIT_CT_LOG;
    }

    /**
     * Retrieves the CT log editor for this CT log manager.
     * @return an editor which can be used to edit CT logs
     */
    public CtLogEditor getCtLogEditor() {
        return ctLogEditor;
    }

    /**
     * Save the CT log currently being edited.
     * @return an empty string on failure or the constant string CT_LOG_SAVED on success
     * @throws IllegalStateException if there is no CT log to save
     */
    public String saveCtLogBeingEdited() {
        if (ctLogEditor.getCtLogBeingEdited() == null) {
            throw new IllegalStateException("The CT log being edited has already been saved or was never loaded.");
        }

        /* Validate data entry by the user */
        if (!ctLogEditor.hasValidUrl()) {
            systemConfigurationHelper.addErrorMessage("CTLOGTAB_MISSINGPROTOCOL");
            return StringUtils.EMPTY;
        }
        if (ctLogEditor.getCtLogTimeout() <= 0) {
            systemConfigurationHelper.addErrorMessage("CTLOGTAB_TIMEOUTNEGATIVE");
            return StringUtils.EMPTY;
        }
        if (ctLogEditor.getPublicKeyFile() != null) {
            final byte[] keyBytes = getCtLogPublicKey(ctLogEditor.getPublicKeyFile());
            if (keyBytes == null) {
                // Error already reported
                return StringUtils.EMPTY;
            }
        }
        if (ctLogEditor.getIsAcceptingByExpirationYear()) {

            if (!ctLogEditor.isUseIntervalAcception() &&
                    (StringUtils.isEmpty(ctLogEditor.getExpirationYearRequired())
                            || !StringUtils.isNumeric(ctLogEditor.getExpirationYearRequired()))) {
                systemConfigurationHelper.addErrorMessage("CTLOGCONFIGURATION_INVALID_YEAR");
                return StringUtils.EMPTY;
            }
            if (ctLogEditor.isUseIntervalAcception()) {
                if (ctLogEditor.getIntervalEnd() == null || ctLogEditor.getIntervalStart() == null){
                    systemConfigurationHelper.addErrorMessage("CTLOGCONFIGURATION_INTERVAL_REQUIRED");
                    return StringUtils.EMPTY;
                }
                if (ctLogEditor.getIntervalStart().isAfter(ctLogEditor.getIntervalEnd())){
                    systemConfigurationHelper.addErrorMessage("CTLOGCONFIGURATION_INTERVAL_ERROR");
                    return StringUtils.EMPTY;
                }
            }
        }

        /* Ensure the new log configuration is not conflicting with another log */
        final CTLogInfo ctLogToUpdate = ctLogEditor.getCtLogBeingEdited();
        for (final CTLogInfo existing : super.getAllCtLogs()) {
            final boolean isSameLog = existing.getLogId() == ctLogToUpdate.getLogId();
            final boolean urlExistsInCtLogGroup = StringUtils.equals(existing.getUrl(), ctLogEditor.getCtLogUrl())
                    && StringUtils.equals(existing.getLabel(), ctLogEditor.getCtLogLabel());
            if (!isSameLog && urlExistsInCtLogGroup) {
                systemConfigurationHelper.addErrorMessage("CTLOGTAB_ALREADYEXISTS", existing.getUrl());
                return StringUtils.EMPTY;
            }
        }

        /* Update the configuration */
        final String url = ctLogEditor.getCtLogUrl();
        final byte[] keyBytes = ctLogEditor.getPublicKeyFile() != null ? getCtLogPublicKey(ctLogEditor.getPublicKeyFile())
                : ctLogEditor.getCtLogBeingEdited().getPublicKeyBytes();
        final int timeout = ctLogEditor.getCtLogTimeout();
        final String label = ctLogEditor.getCtLogLabel();
        ctLogToUpdate.setLogPublicKey(keyBytes);
        ctLogToUpdate.setTimeout(timeout);
        ctLogToUpdate.setUrl(url);
        ctLogToUpdate.setLabel(label);
        ctLogToUpdate.setExpirationYearRequired(ctLogEditor.getIsAcceptingByExpirationYear() && !ctLogEditor.isUseIntervalAcception()
                ? Integer.valueOf(ctLogEditor.getExpirationYearRequired()) : null);
        ctLogToUpdate.setIntervalStart(ctLogEditor.isUseIntervalAcception() && ctLogEditor.getIsAcceptingByExpirationYear()
                ? ctLogEditor.getIntervalStartAsDate() : null);
        ctLogToUpdate.setIntervalEnd(ctLogEditor.isUseIntervalAcception() && ctLogEditor.getIsAcceptingByExpirationYear()
                ? ctLogEditor.getIntervalEndAsDate() : null);
        systemConfigurationHelper.saveCtLogs(super.getAllCtLogs());
        ctLogEditor.stopEditing();
        return CT_LOG_SAVED;
    }

    @Override
    public void renameLabel(final String oldLabel, final String newLabel) {
        super.renameLabel(oldLabel, newLabel);
        systemConfigurationHelper.saveCtLogs(super.getAllCtLogs());
    }

    public List<String> getAvailableLabels(CTLogInfo ctLog) {
        final List<String> labels = super.getLabels();
        // Remove labels already containing a CT log with the same URL
        for (int i = labels.size() - 1; i >= 0; i--) {
            final String label = labels.get(i);
            if (StringUtils.equals(label, ctLog.getLabel())) {
                // Always add the CT log label of the log itself
                continue;
            }
            final List<CTLogInfo> logGroupMembers = super.getCtLogsByLabel(label);
            if (logGroupHasAnotherCtLogWithSameUrl(logGroupMembers, ctLog)) {
                labels.remove(i);
            }
        }
        return labels;
    }

    private boolean logGroupHasAnotherCtLogWithSameUrl(final List<CTLogInfo> logGroupMembers, final CTLogInfo ctLog) {
        for (final CTLogInfo logGroupMember : logGroupMembers) {
            if (logGroupMember.getLogId() != ctLog.getLogId() && StringUtils.equals(logGroupMember.getUrl(), ctLog.getUrl())) {
                return true;
            }
        }
        return false;
    }

}
