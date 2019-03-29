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
import java.util.List;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.util.FileTools;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.ejbca.util.HttpTools;

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
    /**
     * Maximum size of a profile XML file in a ZIP upload.
     */
    private static final int MAX_PROFILE_XML_SIZE = 2*1024*1024;

    /**
     * Matches XML filenames in uploaded ZIP files.
     * The accepted format is: entityprofile_<profile name>-<profile id>.xml
     * The files may also be stored inside a directory
     */
    private static final Pattern xmlFilenamePattern = Pattern.compile("(?:.*/)entityprofile_(.*)-(.*)\\.xml"); // (?:.*/) matches a directory, without capturing it into a match group
    private static final int XML_FILENAME_NAME_INDEX = 1;
    private static final int XML_FILENAME_ID_INDEX = 2;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;

    private EjbcaWebBean ejbcaWebBean = getEjbcaWebBean();

    private Integer selectedEndEntityProfileId = null;
    private boolean deleteInProgress = false;
    private boolean profileSaved;
    private String endEntityProfileName;
    private Part uploadFile;
    private String uploadFilename;
    private List<SelectItem> endEntityProfileItems = null; 


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
            final TreeMap<String,String> profiles = ejbcaWebBean.getAuthorizedEndEntityProfileNames(AccessRulesConstants.VIEW_END_ENTITY);
            final List<Integer> withMissingCAs = endEntityProfileSession.getAuthorizedEndEntityProfileIdsWithMissingCAs(getAdmin());
            for(Entry<String, String> entry : profiles.entrySet()) {
                final String profileName = entry.getKey();
                final Integer profileId = Integer.valueOf(entry.getValue());
                final boolean missingCa = withMissingCAs.contains(profileId);
                final String displayName = profileName + (missingCa ? " "+ejbcaWebBean.getText("MISSINGCAIDS") : "");
                endEntityProfileItems.add(new SelectItem(profileId, displayName));
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
        } else if ("EMPTY".equals(endEntityProfileName)) {
            addErrorMessage("EEPROFILENAMEFORBIDDEN");
            return false;
        }
        return true;
    }

    public void actionAdd() {
        clearMessages();
        if (validateEndEntityProfileName()) {
            try {
                final EndEntityProfile endEntityProfile = new EndEntityProfile();
                endEntityProfile.setAvailableCAs(caSession.getAuthorizedCaIds(getAdmin()));
                endEntityProfileSession.addEndEntityProfile(getAdmin(), endEntityProfileName, endEntityProfile);
                endEntityProfileName = null;
                endEntityProfileItems = null;
            } catch (EndEntityProfileExistsException e) {
                addErrorMessage("EEPROFILEALREADYEXISTS");
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e);
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
        if (!selectedProfileExists()) {
            addErrorMessage("EEPROFILENOTSELECTED");
        } else if (isEmptyProfile()) {
            addErrorMessage("YOUCANTEDITEMPTYPROFILE");
        } else {
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
    
    public void actionExportProfile() {
        clearMessages();
        redirect(getEjbcaWebBean().getBaseUrl() + getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath() + "/profilesexport", "profileType",
                "eep", "profileId", getSelectedEndEntityProfileId().toString());
    }

    public void actionExportProfiles() {
        clearMessages();
        redirect(getEjbcaWebBean().getBaseUrl() + getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath() + "/profilesexport", "profileType",
                "eep");
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
        if (validateRenameOrClone()) {
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

    private boolean validateRenameOrClone() {
        boolean ok = true;
        if (!selectedProfileExists()) {
            addErrorMessage("EEPROFILENOTSELECTED");
            ok = false;
        } else if (isEmptyProfile()) {
            addErrorMessage("YOUCANTEDITEMPTYPROFILE");
            ok = false;
        }
        // validateEndEntityProfileName adds error messages
        return validateEndEntityProfileName() && ok;
    }

    public void actionImportProfiles() throws IOException, AuthorizationDeniedException, EndEntityProfileExistsException {
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

    /** Holds profile information decoded from a filename. Used in this class only, so no getters/setters */
    private static class DecodedFilename {
        public String profileName;
        public int profileId;
    }

    public void importProfilesFromZip(final byte[] zipFileBytes) throws AuthorizationDeniedException, IOException, EndEntityProfileExistsException {
        if (zipFileBytes.length == 0) {
            throw new IllegalArgumentException("No input file");
        }
        final List<String> importedFiles = new ArrayList<>();
        final List<String> ignoredFiles = new ArrayList<>();
        int nrOfFiles = 0;
        final ZipInputStream zipInputStream = new ZipInputStream(new ByteArrayInputStream(zipFileBytes));
        ZipEntry zipEntry = zipInputStream.getNextEntry();
        if (zipEntry == null) {
            // Print import message if the file header corresponds to an empty zip archive
            if (FileTools.isEmptyZipFile(zipFileBytes)) {
                printImportMessage(nrOfFiles, importedFiles, ignoredFiles);
            } else {
                String msg = uploadFilename + " is not a zip file.";
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
            final DecodedFilename decodedFilename = decodeFilename(filename);
            if (decodedFilename == null) {
                ignoredFiles.add(filename);
                continue;
            }
            final String profileName = decodedFilename.profileName;
            int profileId = decodedFilename.profileId;
            if (log.isDebugEnabled()) {
                log.debug("Extracted profile name '" + profileName + "' and profile ID '" + profileId + "'");
            }
            if (ignoreProfile(profileName)) {
                ignoredFiles.add(filename);
                continue;
            }
            if (endEntityProfileSession.getEndEntityProfile(profileId) != null) {
                log.warn("End Entity Profile ID '" + profileId + "' already exist in database. Adding with a new profile ID instead.");
                profileId = -1; // create a new id when adding the profile
            }
            final byte[] filebytes = IOUtils.readFully(zipInputStream, Math.min((int) zipEntry.getSize(), MAX_PROFILE_XML_SIZE));
            final EndEntityProfile eeProfile = getEndEntityProfileFromByteArray(filebytes);
            if (eeProfile == null) {
                final String msg = "Faulty XML file '" + filename + "'. Failed to read end entity Profile.";
                log.info(msg + " Ignoring file.");
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
                continue;
            }
            if (profileId == -1) {
                endEntityProfileSession.addEndEntityProfile(getAdmin(), profileName, eeProfile);
            } else {
                endEntityProfileSession.addEndEntityProfile(getAdmin(), profileId, profileName, eeProfile);                
            }
            importedFiles.add(filename);
            log.info("Added End entity profile: " + profileName);
        } while ((zipEntry = zipInputStream.getNextEntry()) != null);
        zipInputStream.closeEntry();
        zipInputStream.close();
        printImportMessage(nrOfFiles, importedFiles, ignoredFiles);
    }

    private EndEntityProfile getEndEntityProfileFromByteArray(final byte[] profileBytes) {
        final ByteArrayInputStream is = new ByteArrayInputStream(profileBytes);
        final EndEntityProfile profile = new EndEntityProfile();
        try {
            final SecureXMLDecoder decoder = new SecureXMLDecoder(is);
            // Add end entity profile
            final Object data;
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

    /**
     * Checks if a file should be imported, and if so, returns the decoded filename component (profile name and ID).
     * @return Decoded filename components, or null if the file should be ignored.
     */
    private DecodedFilename decodeFilename(final String filename) {
        if (!filename.endsWith(".xml")) {
            log.info(filename + " is not an XML file. IGNORED");
            return null;
        }
        final Matcher matcher = xmlFilenamePattern.matcher(filename);
        if (!matcher.matches()) {
            log.info(filename + " is not in the expected format. "
                    + "The file name should look like: entityprofile_<profile name>-<profile id>.xml. IGNORED");
            return null;
        }
        final DecodedFilename ret = new DecodedFilename();
        try {
            ret.profileName = URLDecoder.decode(matcher.group(XML_FILENAME_NAME_INDEX), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 was not a known character encoding", e);
        }
        try {
            ret.profileId = Integer.parseInt(matcher.group(XML_FILENAME_ID_INDEX));
        } catch (NumberFormatException e) {
            log.info(filename + " contains an invvalid entity profile id: " + e.getMessage());
            return null;
        }
        return ret;
    }

    /** @return true if the profile should be ignored from a End Entity Profile import because it already exists, false if it should be imported */
    private boolean ignoreProfile(final String profilename) {
        // Check if the profiles already exist
        if (endEntityProfileSession.getEndEntityProfile(profilename) != null) {
            log.info("End entity profile '" + profilename + "' already exist in database. IGNORED");
            return true;
        }
       return false;
    }

    private void printImportMessage(final int nrOfFiles, final List<String> importedFiles, final List<String> ignoredFiles) {
        final String msg = "Number of files included in " + uploadFilename + ": " + nrOfFiles;
        log.info(msg);
        addNonTranslatedInfoMessage(msg);
        if (!importedFiles.isEmpty()) {
            addNonTranslatedInfoMessage("Imported End Entity Profiles from files: " + StringUtils.join(importedFiles, ", "));
        }
        if (!ignoredFiles.isEmpty()) {
            addNonTranslatedInfoMessage("Ignored files: " + StringUtils.join(ignoredFiles, ", "));
        }
        if (importedFiles.isEmpty()) {
            addErrorMessage("No End Entity Profiles were imported.");
        }
    }

    public void setUploadFile(final Part uploadFile) {
        this.uploadFile = uploadFile;
        uploadFilename = uploadFile != null ? HttpTools.getUploadFilename(uploadFile) : null;
    }

    public Part getUploadFile() {
        return uploadFile;
    }

    public void actionEdit() {
        clearMessages();
        if (!selectedProfileExists()) {
            addErrorMessage("EEPROFILENOTSELECTED");
        } else if (isEmptyProfile()) {
            addErrorMessage("YOUCANTEDITEMPTYPROFILE");
        } else {
            redirect("endentityprofilepage.xhtml", EndEntityProfileMBean.PARAMETER_PROFILE_ID, selectedEndEntityProfileId);
        }
    }

    public void actionCloneProfile() {
        clearMessages();
        if (validateRenameOrClone()) {
            try {
                endEntityProfileSession.cloneEndEntityProfile(getAdmin(), getSelectedEndEntityProfileName(), endEntityProfileName);
                reset();
            } catch (EndEntityProfileExistsException e) {
                addErrorMessage("EEPROFILEALREADYEXISTS");
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e);
            }
        }
    }
}
