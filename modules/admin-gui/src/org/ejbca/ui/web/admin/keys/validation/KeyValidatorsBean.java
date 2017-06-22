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

package org.ejbca.ui.web.admin.keys.validation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.keys.validation.BaseKeyValidator;
import org.cesecore.keys.validation.CouldNotRemoveKeyValidatorException;
import org.cesecore.keys.validation.KeyValidatorDoesntExistsException;
import org.cesecore.keys.validation.KeyValidatorExistsException;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.keys.validation.RsaKeyValidator;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.StringTools;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Managed bean for key edit validators page (editkeyvalidators.xhtml).
 *
 * @version $Id$
 */
public class KeyValidatorsBean extends BaseManagedBean {

    private static final long serialVersionUID = 1969611638716145216L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(KeyValidatorsBean.class);

    /** Selected key validator id. */
    private Integer selectedKeyValidatorId = null;

    /** Selected key validator name. */
    private String keyValidatorName = StringUtils.EMPTY;

    private boolean renameInProgress = false;
    private boolean deleteInProgress = false;
    private boolean addFromTemplateInProgress = false;

    /** View only flag for view action. */
    private boolean viewOnly = true;

    /** Backing object for key validator list. */
    private ListDataModel<KeyValidatorItem> keyValidatorItems = null;

    @EJB
    private CaSessionLocal caSession;

    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;

    @EJB
    private KeyValidatorSessionLocal keyValidatorSession;

    /**
     * Gets the selected key validator id.
     * @return the id.
     */
    public Integer getSelectedKeyValidatorId() {
        return selectedKeyValidatorId;
    }

    /**
     * Sets the selected key validator id.
     * @param id the id
     */
    public void setSelectedKeyValidatorId(final Integer id) {
        selectedKeyValidatorId = id;
    }

    /**
     * Gets the selected key validator name.
     * @return the name
     */
    public String getSelectedKeyValidatorName() {
        final Integer id = getSelectedKeyValidatorId();
        if (id != null) {
            return keyValidatorSession.getKeyValidatorName(id.intValue());
        }
        return null;
    }

    /**
     * Force a shorter scope (than session scoped) for the ListDataModel by always resetting it before it is rendered
     * @return
     */
    public String getResetKeyValidatorsTrigger() {
        keyValidatorItems = null;
        return StringUtils.EMPTY;
    }

    /**
     * Internal class for key validator items rendered as table.
     * @version $Id$
     *
     */
    public class KeyValidatorItem {

        private final int id;
        private final String name;
        private final String classpath;

        /**
         * Creates a new instance.
         * @param id the id
         * @param name the name
         * @param classpath the class path (optional)
         */
        public KeyValidatorItem(final int id, final String name, final String classpath) {
            this.id = id;
            this.classpath = classpath;
            this.name = name + " (" + classpath.substring(classpath.lastIndexOf('.') + 1) + ")";
        }

        public int getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public String getClasspath() {
            return classpath;
        }
    }

    /**
     * Gets the available key validators.
     * @return
     */
    public ListDataModel<KeyValidatorItem> getAvailableKeyValidators() {
        if (keyValidatorItems == null) {
            final List<KeyValidatorItem> items = new ArrayList<KeyValidatorItem>();
            final Map<Integer, BaseKeyValidator> keyValidators = keyValidatorSession.getAllKeyValidators();
            BaseKeyValidator keyValidator;
            String accessRule;
            String className;
            for (Integer id : keyValidators.keySet()) {
                keyValidator = keyValidators.get(id);
                accessRule = StandardRules.KEYVALIDATORACCESS.resource() + keyValidator.getName();
                if (isAuthorizedTo(accessRule)) {
                    className = StringUtils.isNotBlank(keyValidator.getClasspath()) ? keyValidator.getClasspath() : keyValidator.getClass().getName();
                    className = className.substring(className.lastIndexOf('.') + 1);
                    items.add(new KeyValidatorItem(id, keyValidator.getName(), className));
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("User with token " + getAdmin().getUniqueId() + " is not authorized to access rule "
                                + StandardRules.KEYVALIDATORACCESS.resource() + keyValidator.getName() + ".");
                    }
                }
            }
            keyValidatorItems = new ListDataModel<KeyValidatorItem>(items);
        }
        return keyValidatorItems;
    }

    /**
     * Checks if the administrator is authorized to view.
     * @return true if authorized.
     */
    public boolean isAuthorizedToView() {
        return isAuthorizedTo(StandardRules.KEYVALIDATORVIEW.resource());
    }

    /**
     * Checks if the administrator is authorized to edit.
     * @return true if authorized.
     */
    public boolean isAuthorizedToEdit() {
        return isAuthorizedTo(StandardRules.KEYVALIDATOREDIT.resource());
    }

    /**
     * Gets the view only flag.
     * @return true if view only.
     */
    public boolean getViewOnly() {
        return viewOnly;
    }

    /**
     * Edit action.
     * @return the navigation outcome defined in faces-config.xml.
     */
    public String actionEdit() {
        selectCurrentRowData();
        viewOnly = false;
        return "edit";
    }

    /**
     * View action.
     * @return the navigation outcome defined in faces-config.xml.
     */
    public String actionView() {
        selectCurrentRowData();
        viewOnly = true;
        return "view";
    }

    /**
     * Add action. Adds a new key validator.
     */
    public void actionAdd() {
        final String name = getKeyValidatorName();
        if (StringUtils.isNotBlank(name)) {
            try {
                keyValidatorSession.addKeyValidator(getAdmin(), name, new RsaKeyValidator());
                getEjbcaWebBean().getInformationMemory().keyValidatorsEdited();
                actionCancel();
            } catch (KeyValidatorExistsException e) {
                addErrorMessage("KEYVALIDATORALREADY", name);
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
        keyValidatorItems = null;
    }

    /**
     * Selection changed event.
     */
    private void selectCurrentRowData() {
        final KeyValidatorItem item = (KeyValidatorItem) getAvailableKeyValidators().getRowData();
        setSelectedKeyValidatorId(item.getId());
    }

    /**
     * Checks if a rename, delete or addFromTemplate action is in Progress.
     * @return true if action is in progress.
     */
    public boolean isOperationInProgress() {
        return isRenameInProgress() || isDeleteInProgress() || isAddFromTemplateInProgress();
    }

    /**
     * Checks if a addFromTemplate action is in Progress.
     * @return true if action is in progress.
     */
    public boolean isAddFromTemplateInProgress() {
        return addFromTemplateInProgress;
    }

    /**
     * AddFromTemplate action. 
     */
    public void actionAddFromTemplate() {
        selectCurrentRowData();
        addFromTemplateInProgress = true;
    }

    /**
     * AddFromTemplate confirm action. 
     */
    public void actionAddFromTemplateConfirm() {
        final String name = getKeyValidatorName();
        if (name.length() > 0) {
            try {
                keyValidatorSession.cloneKeyValidator(getAdmin(), getSelectedKeyValidatorName(), name);
                getEjbcaWebBean().getInformationMemory().keyValidatorsEdited();
                setKeyValidatorName(StringUtils.EMPTY);
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            } catch (KeyValidatorExistsException e) {
                addErrorMessage("KEYVALIDATORALREADY", name);
            } catch (KeyValidatorDoesntExistsException e) {
                // NOPMD: ignore do nothing
            }
        }
        actionCancel();
    }

    /**
     * Checks if a delete action is in Progress.
     * @return true if action is in progress.
     */
    public boolean isDeleteInProgress() {
        return deleteInProgress;
    }

    /**
     * Delete action.
     */
    public void actionDelete() {
        selectCurrentRowData();
        deleteInProgress = true;
    }

    /**
     * Delete confirm action.
     */
    public void actionDeleteConfirm() throws AuthorizationDeniedException, CouldNotRemoveKeyValidatorException {
        try {
            keyValidatorSession.removeKeyValidator(getAdmin(), getSelectedKeyValidatorName());
            keyValidatorSession.flushKeyValidatorCache();
            getEjbcaWebBean().getInformationMemory().keyValidatorsEdited();
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage("Not authorized to remove key validator.");
        } catch (KeyValidatorDoesntExistsException e) {
            // NOPMD: ignore do nothing
        } catch (CouldNotRemoveKeyValidatorException e) {
            addErrorMessage("COULDNTDELETEKEYVALIDATOR");
        }
        actionCancel();
    }

    /**
     * Checks if a rename action is in Progress.
     * @return true if action is in progress.
     */
    public boolean isRenameInProgress() {
        return renameInProgress;
    }

    /**
     * Rename action.
     */
    public void actionRename() {
        selectCurrentRowData();
        renameInProgress = true;
    }

    /**
     * Rename confirm action.
     */
    public void actionRenameConfirm() throws AuthorizationDeniedException {
        final String name = getKeyValidatorName();
        if (name.length() > 0) {
            try {
                keyValidatorSession.renameKeyValidator(getAdmin(), getSelectedKeyValidatorName(), name);
                getEjbcaWebBean().getInformationMemory().keyValidatorsEdited();
                setKeyValidatorName(StringUtils.EMPTY);
            } catch (KeyValidatorDoesntExistsException e) {
                addErrorMessage("KEYVALIDATORDOESNOTEXIST", name);
            } catch (KeyValidatorExistsException e) {
                addErrorMessage("KEYVALIDATORALREADY", name);
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage("Not authorized to rename key validator.");
            }
        }
        actionCancel();
    }

    /**
     * Cancel action.
     */
    public void actionCancel() {
        addFromTemplateInProgress = false;
        deleteInProgress = false;
        renameInProgress = false;
        keyValidatorItems = null;
        selectedKeyValidatorId = null;
        keyValidatorName = null;
    }
    
    /**
     * Gets the selected key validator name.
     * @return the name.
     */
    public String getKeyValidatorName() {
        return keyValidatorName;
    }

    /**
     * Sets the selected key validator name.
     * @param name the name
     */
    public void setKeyValidatorName(String name) {
        name = name.trim();
        if (StringTools.checkFieldForLegalChars(name)) {
            addErrorMessage("ONLYCHARACTERS");
        } else {
            this.keyValidatorName = name;
        }
    }

    //----------------------------------------------
    //                Import key validators
    //----------------------------------------------

    private UploadedFile part;

    /**
     * Gets the upload file for import.
     * @return the file
     */
    public UploadedFile getUploadFile() {
        return part;
    }

    /**
     * Sets the upload file for import.
     * @param uploadFile the file
     */
    public void setUploadFile(UploadedFile part) {
        this.part = part;
    }

    /**
     * ImportKeyValidators action.
     */
    public void actionImportKeyValidators() {
        if (log.isDebugEnabled()) {
            log.debug("Importing list of key validators in file " + part);
        }
        if (part == null) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "File upload failed.", null));
            return;
        }
        try {
            importKeyValidatorsFromZip(getUploadFile().getBytes());
            keyValidatorItems = null;
        } catch (IOException | AuthorizationDeniedException | NumberFormatException | KeyValidatorExistsException e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
        }
    }

    /**
     * Imports a list of key validators, stored in separate XML files in the ZIP container.
     * @param Part the mime part.
     * @throws KeyValidatorExistsException if a key validator already exists.
     * @throws AuthorizationDeniedException if not authorized
     * @throws NumberFormatException if the key validator id cannot be parsed.
     * @throws IOException if the stream cannot be read.
     */
    public void importKeyValidatorsFromZip(final byte[] filebuffer)
            throws KeyValidatorExistsException, AuthorizationDeniedException, NumberFormatException, IOException {
        if (log.isDebugEnabled()) {
            log.debug("Importing list of key validators in file " + part);
        }
        //        final byte[] filebuffer = IOUtils.toByteArray(part.getInputStream());
        if (filebuffer.length == 0) {
            throw new IllegalArgumentException("No input file");
        }
        String importedFiles = "";
        String ignoredFiles = "";
        int nrOfFiles = 0;
        final ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(filebuffer));
        ZipEntry ze = zis.getNextEntry();
        if (ze == null) {
            String msg = part.getName() + " is not a zip file.";
            log.info(msg);
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
            return;
        }
        do {
            nrOfFiles++;
            String filename = ze.getName();
            if (log.isDebugEnabled()) {
                log.debug("Importing file: " + filename);
            }
            if (ignoreFile(filename)) {
                ignoredFiles += filename + ", ";
                continue;
            }

            try {
                filename = URLDecoder.decode(filename, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException("UTF-8 was not a known character encoding", e);
            }
            int index1 = filename.indexOf("_");
            int index2 = filename.lastIndexOf("-");
            int index3 = filename.lastIndexOf(".xml");
            String nameToImport = filename.substring(index1 + 1, index2);
            int idToImport = 0;
            try {
                idToImport = Integer.parseInt(filename.substring(index2 + 1, index3));
            } catch (NumberFormatException e) {
                if (log.isDebugEnabled()) {
                    log.debug("NumberFormatException parsing key validator id: " + e.getMessage());
                }
                ignoredFiles += filename + ", ";
                continue;
            }
            if (log.isDebugEnabled()) {
                log.debug("Extracted key validator name '" + nameToImport + "' and ID '" + idToImport + "'");
            }
            if (ignoreKeyValidator(filename, nameToImport, idToImport)) {
                ignoredFiles += filename + ", ";
                continue;
            }

            if (keyValidatorSession.getKeyValidator(idToImport) != null) {
                log.warn("Key valildator id '" + idToImport + "' already exist in database. Adding with a new key validator id instead.");
                idToImport = -1; // means we should create a new id when adding the key validator.
            }

            final byte[] filebytes = new byte[102400];
            int i = 0;
            while ((zis.available() == 1) && (i < filebytes.length)) {
                filebytes[i++] = (byte) zis.read();
            }

            final BaseKeyValidator baseKeyValidator = getKeyValidatorFromByteArray(nameToImport, filebytes);
            if (baseKeyValidator == null) {
                String msg = "Faulty XML file '" + filename + "'. Failed to read key validator.";
                log.info(msg + " Ignoring file.");
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
                continue;
            }

            if (idToImport == -1) {
                keyValidatorSession.addKeyValidator(getAdmin(), nameToImport, baseKeyValidator);
            } else {
                keyValidatorSession.addKeyValidator(getAdmin(), idToImport, nameToImport, baseKeyValidator);
            }
            getEjbcaWebBean().getInformationMemory().keyValidatorsEdited();
            importedFiles += filename + ", ";
            log.info("Added key validator: " + nameToImport);
        } while ((ze = zis.getNextEntry()) != null);
        zis.closeEntry();
        zis.close();

        String msg = part.getName() + " contained " + nrOfFiles + " files. ";
        log.info(msg);
        FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_INFO, msg, null));

        if (StringUtils.isNotEmpty(importedFiles)) {
            importedFiles = importedFiles.substring(0, importedFiles.length() - 2);
        }
        msg = "Imported key validator from files: " + importedFiles;
        if (log.isDebugEnabled()) {
            log.debug(msg);
        }
        FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_INFO, msg, null));

        if (StringUtils.isNotEmpty(ignoredFiles)) {
            ignoredFiles = ignoredFiles.substring(0, ignoredFiles.length() - 2);
        }
        msg = "Ignored files: " + ignoredFiles;
        if (log.isDebugEnabled()) {
            log.debug(msg);
        }
        FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_INFO, msg, null));
    }

    /**
     * Gets a key validator by the XML file stored in the byte[].    
     * @param name the name of the key validator
     * @param bytes the XML file as bytes
     * @return the concrete key validator implementation.
     * @throws AuthorizationDeniedException if not authorized
     */
    private BaseKeyValidator getKeyValidatorFromByteArray(final String name, final byte[] bytes) throws AuthorizationDeniedException {
        final ByteArrayInputStream is = new ByteArrayInputStream(bytes);
        BaseKeyValidator baseKeyValidator = null;
        try {
            final SecureXMLDecoder decoder = new SecureXMLDecoder(is);
            Object data = null;
            try {
                data = decoder.readObject();
                baseKeyValidator = (BaseKeyValidator) keyValidatorSession.createKeyValidatorInstanceByData((Map<?, ?>) data);
            } catch (IOException e) {
                log.info("Error parsing keyvalidator data: " + e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("Full stack trace: ", e);
                }
                return null;
            } finally {
                decoder.close();
            }

            // Make sure certificate profiles exists.
            final List<Integer> certificateProfileIds = baseKeyValidator.getCertificateProfileIds();
            final ArrayList<Integer> certificateProfilesToRemove = new ArrayList<Integer>();
            for (Integer certificateProfileId : certificateProfileIds) {
                if (null == certificateProfileSession.getCertificateProfile(certificateProfileId)) {
                    certificateProfilesToRemove.add(certificateProfileId);
                }
            }
            for (Integer toRemove : certificateProfilesToRemove) {
                log.warn("Warning: certificate profile with id " + toRemove + " was not found and will not be used in key validator '" + name + "'.");
                certificateProfileIds.remove(toRemove);
            }
            if (certificateProfileIds.size() == 0) {
                log.warn("Warning: No certificate profiles left in key validator '" + name + "'.");
                certificateProfileIds.add(Integer.valueOf(CertificateProfile.ANYCA));
            }
            baseKeyValidator.setCertificateProfileIds(certificateProfileIds);
        } finally {
            try {
                is.close();
            } catch (IOException e) {
                throw new IllegalStateException("Unknown IOException was caught when closing stream", e);
            }
        }
        return baseKeyValidator;
    }

    /** 
     * Check ignore file.
     * @return true if the file shall be ignored from a key validator import, false if it should be imported. 
     */
    private boolean ignoreFile(final String filename) {
        if (filename.lastIndexOf(".xml") != (filename.length() - 4)) {
            log.info(filename + " is not an XML file. IGNORED");
            return true;
        }

        if (filename.indexOf("_") < 0 || filename.lastIndexOf("-") < 0 || (filename.indexOf("keyvalidator_") < 0)) {
            log.info(filename + " is not in the expected format. " + "The file name should look like: keyvalidator_<name>-<id>.xml. IGNORED");
            return true;
        }
        return false;
    }

    /** 
     * Check ignore key validator.
     * @return true if the key validator should be ignored from a import because it already exists, false if it should be imported. 
     */
    private boolean ignoreKeyValidator(final String filename, final String name, final int id) {
        if (keyValidatorSession.getKeyValidator(name) != null) {
            log.info("Key validator '" + name + "' already exist in database. IGNORED");
            return true;
        }
        return false;
    }
}
