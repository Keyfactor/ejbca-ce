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
package org.ejbca.ui.web.admin.endentityprofiles;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Part;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;

/**
 * JSF MBean backing edit end entity profiles page.
 *
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class EndEntityProfilesMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EndEntityProfilesMBean.class);

    public static final String PARAMETER_PROFILE_SAVED = "profileSaved";
    /**
     * Maximum size of the profiles ZIP file upload.
     * <p>
     * Usually profiles aren't larger than a few kilobytes, but with printing templates
     * (rarely used) they could be larger. The application server usually has it's
     * own limitation as well.
     */
    private static final int MAX_PROFILEZIP_FILESIZE = 50*1024*1024;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;

    private EjbcaWebBean ejbcaWebBean = getEjbcaWebBean();

    @PostConstruct
    private void postConstruct() {
        final HttpServletRequest req = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        try {
            ejbcaWebBean.initialize(req, AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        profileSaved = "true".equals(FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get(PARAMETER_PROFILE_SAVED));
    }

    public void preRenderView() {
        if (profileSaved) {
            addInfoMessage("ENDENTITYPROFILESAVED");
        }
    }

    private Integer selectedEndEntityProfileId = null;
    private boolean deleteInProgress = false;
    private boolean profileSaved;

    private String endEntityProfileName;
    private Part uploadFile;
    private List<SelectItem> endEntityProfileItems = null; 

    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    public void setEndEntityProfileName(final String endEntityProfileName) {
        this.endEntityProfileName = StringUtils.trim(endEntityProfileName);
    }

    public boolean isAuthorizedToEdit() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES);
    }
    
    public boolean isAuthorizedToView() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES);
    }
    
    public boolean isEmptyProfile() {
        return selectedEndEntityProfileId != null && selectedEndEntityProfileId.equals(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
    }
    
    public List<SelectItem> getEndEntityProfileItems() {
        if (endEntityProfileItems == null) {
            endEntityProfileItems = new ArrayList<>();
            final TreeMap<String,String> profiles = getEjbcaWebBean().getAuthorizedEndEntityProfileNames(AccessRulesConstants.VIEW_END_ENTITY);
            final List<Integer> withMissingCAs = endEntityProfileSession.getAuthorizedEndEntityProfileIdsWithMissingCAs(getAdmin());
            for(Entry<String, String> entry : profiles.entrySet()) {
                final String profileName = entry.getKey();
                final String profileId = entry.getValue();
                final boolean missingCa = withMissingCAs.contains(Integer.valueOf(profileId));
                final String displayName = profileName + (missingCa ? " "+getEjbcaWebBean().getText("MISSINGCAIDS") : "");
                endEntityProfileItems.add(new SelectItem(Integer.valueOf(profileId), displayName));
            }
        }
         return endEntityProfileItems;
    } 

    private boolean validateEndEntityProfileName() {
        if (StringUtils.isBlank(endEntityProfileName)) {
            addErrorMessage("EEPROFILENAMEREQUIRED");
            return false;
        } else if (!StringTools.checkFieldForLegalChars(endEntityProfileName)) {
            addErrorMessage("ONLYCHARACTERS");
            return false;
        }
        return true;
    }

    public void actionAdd() {
        clearMessages();
        if (validateEndEntityProfileName()) {
            try {
                final EndEntityProfile endEntityProfile = new EndEntityProfile();
                endEntityProfile.setAvailableCAs(getEjbcaWebBean().getAuthorizedCAIds());
                endEntityProfileSession.addEndEntityProfile(getAdmin(), endEntityProfileName, endEntityProfile);
                endEntityProfileName = null;
                endEntityProfileItems = null;
            } catch (EndEntityProfileExistsException e) {
                addErrorMessage("EEPROFILEALREADYEXISTS");
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
    }
    
    public Integer getSelectedEndEntityProfileId() {
        return selectedEndEntityProfileId;
    }

    public void setSelectedEndEntityProfileId(final Integer selectedEndEntityProfileId) {
        this.selectedEndEntityProfileId = selectedEndEntityProfileId;
    }

    public void actionDelete() {
        if (selectedProfileExists()) {
            clearMessages();
            deleteInProgress = true;
        }
    }

    public boolean isDeleteInProgress() {
        return deleteInProgress;
    }
    
    private boolean selectedProfileExists() {
        if (selectedEndEntityProfileId != null) {
            return endEntityProfileSession.getEndEntityProfile(selectedEndEntityProfileId) != null;
        } else {
            return false;
        }
    }

    public String getSelectedEndEntityProfileName() {
        if (selectedEndEntityProfileId != null) {
            return endEntityProfileSession.getEndEntityProfileName(selectedEndEntityProfileId);
        }
        return null;
    }

    public void actionDeleteConfirm() {
        clearMessages();
        try {
            endEntityProfileSession.removeEndEntityProfile(getAdmin(), getSelectedEndEntityProfileName());
            reset();
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage("Not authorized to remove end entity profile.");
        }
        nonAjaxPostRedirectGet(null);
    }

    public void reset() {
        deleteInProgress = false;
        endEntityProfileItems = null;
        selectedEndEntityProfileId = null;
        endEntityProfileName = null;
        profileSaved = false;
    }

    @Override
    public void clearMessages() {
        super.clearMessages();
        profileSaved = false;
    }

    public void actionCancel() {
        deleteInProgress = false;
    }

    public void actionRename() {
        clearMessages();
        if (!selectedProfileExists() || !validateEndEntityProfileName()) {
            // Do nothing
        } else if (isEmptyProfile()) {
            addErrorMessage("YOUCANTEDITEMPTYPROFILE");
        } else {
            try {
                endEntityProfileSession.renameEndEntityProfile(getAdmin(), getSelectedEndEntityProfileName(), endEntityProfileName);
                reset();
            } catch (EndEntityProfileExistsException e) {
                addErrorMessage("EEPROFILEALREADYEXISTS");
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage("Not authorized to rename end entity profile.");
            }
        }
    }

    public boolean isOperationInProgress() {
        return isDeleteInProgress();
    }

    public String getInputName() {
        return ejbcaWebBean.getText("FORMAT_ID_STR");
    }

    public void actionImportProfiles() throws IOException, NumberFormatException, AuthorizationDeniedException, EndEntityProfileExistsException, EndEntityProfileNotFoundException {
        clearMessages();
        if (uploadFile == null) {
            addNonTranslatedErrorMessage("File upload failed.");
            return;
        }
        if (uploadFile.getSize() > MAX_PROFILEZIP_FILESIZE) {
            addErrorMessage("File is too large. Maximum size is " + (MAX_PROFILEZIP_FILESIZE/1024/1024) + " MB, but server configuration may impose further limitations.");
            return;
        }
        final byte[] fileBytes = IOUtils.toByteArray(getUploadFile().getInputStream(), uploadFile.getSize());
        importProfilesFromZip(fileBytes);
        endEntityProfileItems = null;
    }
    
    public void importProfilesFromZip(final byte[] filebuffer) throws AuthorizationDeniedException, NumberFormatException, IOException,
            EndEntityProfileExistsException, EndEntityProfileNotFoundException {
        if (filebuffer.length == 0) {
            throw new IllegalArgumentException("No input file");
        }
        String importedFiles = "";
        String ignoredFiles = "";
        int nrOfFiles = 0;
        ZipInputStream zipInputstream = new ZipInputStream(new ByteArrayInputStream(filebuffer));
        ZipEntry zipEntry = zipInputstream.getNextEntry();
        if (zipEntry == null) {
            // Print import message if the file header corresponds to an empty zip archive
            if (Arrays.equals(Arrays.copyOfRange(filebuffer, 0, 4), new byte[] { 80, 75, 5, 6 })) {
                printImportMessage(nrOfFiles, importedFiles, ignoredFiles);
            } else {
                String msg = uploadFile.getName() + " is not a zip file.";
                log.info(msg);
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
            }
            return;
        }
        do {
            nrOfFiles++;
            String filename = zipEntry.getName();
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
            String profilename = filename.substring(index1 + 1, index2);
            int profileid = 0;
            try {
                profileid = Integer.parseInt(filename.substring(index2 + 1, index3));
            } catch (NumberFormatException e) {
                if (log.isDebugEnabled()) {
                    log.debug("NumberFormatException parsing end entity profile id: " + e.getMessage());
                }
                ignoredFiles += filename + ", ";
                continue;
            }
            if (log.isDebugEnabled()) {
                log.debug("Extracted profile name '" + profilename + "' and profile ID '" + profileid + "'");
            }
            if (ignoreProfile(profilename)) {
                ignoredFiles += filename + ", ";
                continue;
            }
            if (endEntityProfileSession.getEndEntityProfile(profileid) != null) {
                log.warn("Endentity profile id '" + profileid + "' already exist in database. Adding with a new profile id instead.");
                profileid = -1; // create a new id when adding the profile
            }
            byte[] filebytes = new byte[102400];
            int i = 0;
            while ((zipInputstream.available() == 1) && (i < filebytes.length)) {
                filebytes[i++] = (byte) zipInputstream.read();
            }
            final EndEntityProfile eeProfile = getEndEntityProfileFromByteArray(filebytes);
            if (eeProfile == null) {
                String msg = "Faulty XML file '" + filename + "'. Failed to read end entity Profile.";
                log.info(msg + " Ignoring file.");
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
                continue;
            }
            if (profileid == -1) {
                endEntityProfileSession.addEndEntityProfile(getAdmin(), profilename, eeProfile);
            } else {
                endEntityProfileSession.addEndEntityProfile(getAdmin(), profileid, profilename, eeProfile);                
            }
            importedFiles += filename + ", ";
            log.info("Added End entity profile: " + profilename);
        } while ((zipEntry = zipInputstream.getNextEntry()) != null);
        zipInputstream.closeEntry();
        zipInputstream.close();
        printImportMessage(nrOfFiles, importedFiles, ignoredFiles);
    }

    private EndEntityProfile getEndEntityProfileFromByteArray(final byte[] profileBytes) {
        ByteArrayInputStream is = new ByteArrayInputStream(profileBytes);
        EndEntityProfile profile = new EndEntityProfile();
        try {
            final SecureXMLDecoder decoder = new SecureXMLDecoder(is);
            // Add end entity profile
            Object data = null;
            try {
                data = decoder.readObject();
            } catch (IOException e) {
                log.info("Error parsing end entity profile data: " + e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("Full stack trace: ", e);
                }
                return null;
            } finally {
                decoder.close();
            }
            profile.loadData(data);
           } finally {
            try {
                is.close();
            } catch (IOException e) {
                throw new IllegalStateException("Unknown IOException was caught when closing stream", e);
            }
        }
        return profile;
    }

    /** @return true if the file shall be ignored from an End Entity Profile import, false if it should be imported */
    private boolean ignoreFile(final String filename) {
        if (!filename.endsWith(".xml")) {
            log.info(filename + " is not an XML file. IGNORED");
            return true;
        }
        if (filename.indexOf("_") < 0 || filename.lastIndexOf("-") < 0 || (filename.indexOf("entityprofile_") < 0)) {
            log.info(filename + " is not in the expected format. "
                    + "The file name should look like: entityprofile_<profile name>-<profile id>.xml. IGNORED");
            return true;
        }
        return false;
    }

    /** @return true if the profile should be ignored from a End Entity Profile import because it already exists, false if it should be imported 
     * @throws EndEntityProfileNotFoundException */
    private boolean ignoreProfile(final String profilename) throws EndEntityProfileNotFoundException {
        // Check if the profiles already exist
        if (endEntityProfileSession.getEndEntityProfile(profilename) != null) {
            log.info("End entity profile '" + profilename + "' already exist in database. IGNORED");
            return true;
        }
       return false;
    }

    private void printImportMessage(final int nrOfFiles, String importedFiles, String ignoredFiles) {
        String msg = "Number of files included in " + uploadFile.getName() + ": " + nrOfFiles;
        log.info(msg);
        addNonTranslatedInfoMessage(msg);
        if (StringUtils.isNotEmpty(importedFiles)) {
            importedFiles = importedFiles.substring(0, importedFiles.length() - 2);
        }
        msg = "Imported End Entity Profiles from files: " + importedFiles;
        if (log.isDebugEnabled()) {
            log.debug(msg);
        }
        addNonTranslatedInfoMessage(msg);
        if (StringUtils.isNotEmpty(ignoredFiles)) {
            ignoredFiles = ignoredFiles.substring(0, ignoredFiles.length() - 2);
        }
        msg = "Ignored files: " + ignoredFiles;
        if (log.isDebugEnabled()) {
            log.debug(msg);
        }
        addNonTranslatedInfoMessage(msg);
    }

    public void setUploadFile(final Part uploadFile) {
        this.uploadFile = uploadFile;
    }

    public Part getUploadFile() {
        return uploadFile;
    }
    
    public String actionEdit() {
        clearMessages();
        if (isEmptyProfile()) {
            addErrorMessage("YOUCANTEDITEMPTYPROFILE");
            return "";
        } else if (selectedProfileExists()) {
            redirect("endentityprofilepage.xhtml", EndEntityProfileMBean.PARAMETER_PROFILE_ID, selectedEndEntityProfileId);
            return "";
        } else {
            return "";
        }
    }

    public void actionCloneProfile() {
        clearMessages();
        if (validateEndEntityProfileName()) {
            try {
                endEntityProfileSession.cloneEndEntityProfile(getAdmin(), getSelectedEndEntityProfileName(), endEntityProfileName);
                reset();
            } catch (EndEntityProfileExistsException e) {
                addErrorMessage("EEPROFILEALREADYEXISTS");
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
    }
}
