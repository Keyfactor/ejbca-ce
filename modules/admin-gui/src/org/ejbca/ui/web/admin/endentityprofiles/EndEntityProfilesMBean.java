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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.faces.view.ViewScoped;
import javax.inject.Named;
import javax.servlet.http.Part;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.util.SecureXMLDecoder;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.ejbca.util.HttpTools;

import com.keyfactor.util.FileTools;
import com.keyfactor.util.StreamSizeLimitExceededException;
import com.keyfactor.util.StringTools;

/**
 * JSF MBean backing edit end entity profiles page.
 *
 */
@Named
@ViewScoped
public class EndEntityProfilesMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EndEntityProfilesMBean.class);

    public static final String PARAMETER_PROFILE_SAVED = "profileSaved";
    private static final String PROFILE_ALREADY_EXISTS = "EEPROFILEALREADYEXISTS";
    private static final String PROFILE_NOT_SELECTED = "EEPROFILENOTSELECTED";
    private static final String YOU_CANT_EDIT_EMPTY_PROFILE = "YOUCANTEDITEMPTYPROFILE";

    /**
     * Maximum size of the profiles ZIP file upload.
     * <p>
     * Usually profiles aren't larger than a few kilobytes, but with printing templates
     * (rarely used) they could be larger. The application server usually has it's
     * own limitation as well.
     */
    private static final int MAX_PROFILEZIP_FILESIZE = 50 * 1024 * 1024;
    /**
     * Maximum size of a profile XML file in a ZIP upload.
     */
    private static final int MAX_PROFILE_XML_SIZE = 2 * 1024 * 1024;

    /**
     * Matches XML filenames in uploaded ZIP files.
     * The accepted format is: entityprofile_<profile name>-<profile id>.xml
     * The files may also be stored inside a directory
     */
    private static final Pattern xmlFilenamePattern = Pattern.compile("(?:.*/)?entityprofile_(.*)-(.*)\\.xml"); // (?:.*/) matches a directory, without capturing it into a match group
    private static final int XML_FILENAME_NAME_INDEX = 1;
    private static final int XML_FILENAME_ID_INDEX = 2;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private RoleDataSessionLocal roleDataSession;

    private EjbcaWebBean ejbcaWebBean = getEjbcaWebBean();

    private Integer selectedEndEntityProfileId = null;
    private boolean deleteInProgress = false;
    private String endEntityProfileName;
    private Part uploadFile;
    private boolean profileSaved;
    private String uploadFilename;
    private List<SelectItem> endEntityProfileItems = null;

    public EndEntityProfilesMBean() {
        super(AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES);
    }
    
    @PostConstruct
    private void postConstruct() { 
        profileSaved = null != FacesContext.getCurrentInstance()
            .getExternalContext()
            .getRequestParameterMap()
            .get(PARAMETER_PROFILE_SAVED);
    }

    public void preRenderView() {
        if (profileSaved) {
            final String nameOfSavedEndEntityProfile = FacesContext.getCurrentInstance()
                    .getExternalContext()
                    .getRequestParameterMap()
                    .get(PARAMETER_PROFILE_SAVED);
            addInfoMessage("ENDENTITYPROFILESAVED", nameOfSavedEndEntityProfile);
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

    private boolean isEmptyProfile() {
        return selectedEndEntityProfileId != null && selectedEndEntityProfileId.equals(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
    }

    public List<SelectItem> getEndEntityProfileItems() {
        if (endEntityProfileItems == null) {
            endEntityProfileItems = new ArrayList<>();
            final TreeMap<String, String> profiles = ejbcaWebBean.getAuthorizedEndEntityProfileNames(AccessRulesConstants.VIEW_END_ENTITY);
            final List<Integer> withMissingCAs = endEntityProfileSession.getAuthorizedEndEntityProfileIdsWithMissingCAs(getAdmin());
            for (Entry<String, String> entry : profiles.entrySet()) {
                final String profileName = entry.getKey();
                final Integer profileId = Integer.valueOf(entry.getValue());
                final boolean missingCa = withMissingCAs.contains(profileId);
                final String displayName = profileName + (missingCa ? " " + ejbcaWebBean.getText("MISSINGCAIDS") : "");
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
                addErrorMessage(PROFILE_ALREADY_EXISTS);
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
            addErrorMessage(PROFILE_NOT_SELECTED);
        } else if (isEmptyProfile()) {
            addErrorMessage(YOU_CANT_EDIT_EMPTY_PROFILE);
        } else if (!canRemoveEndEntityProfile(getSelectedEndEntityProfileName())) {
            addErrorMessage("COULDNTDELETEEEPROFILE");
        } else {
            clearMessages();
            deleteInProgress = true;
        }
    }

    public boolean isDeleteInProgress() {
        return deleteInProgress;
    }

    private boolean selectedProfileExists() {
        return selectedEndEntityProfileId != null && endEntityProfileSession.getEndEntityProfile(selectedEndEntityProfileId) != null;
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

    /**
     * Tries to remove an End Entity Profile. Prints messages
     * containing information about what is preventing the removal.
     *
     * @param name the name of the profile to be removed
     * @return true if profile can be removed safely
     */
    private boolean canRemoveEndEntityProfile(String name) {
        boolean ret = true;
        int profileId;
        try {
            profileId = endEntityProfileSession.getEndEntityProfileId(name);
        } catch (EndEntityProfileNotFoundException e) {
            addNonTranslatedErrorMessage("EEPROFILEDOESNOTEXIST");
            return false;
        }
        final List<UserData> users = endEntityAccessSession.findByEndEntityProfileId(profileId);
        // Only return the users the admin is authorized to view to prevent information leaks
        final List<String> authorizedUsers = new ArrayList<>();
        for (UserData user : users) {
            if (caSession.authorizedToCANoLogging(getAdmin(), user.getCaId())
                    && authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_VIEWENDENTITY)) {
                authorizedUsers.add(user.getUsername());
            }
        }
        // Only return the End Entities that the admin is authorized to (empty string if none)
        if (authorizedUsers.size() > 100) {
            ret = false;
            addErrorMessage("EEPROFILEUSEDINENDENTITIESEXCESSIVE");
        } else if (!authorizedUsers.isEmpty()) {
            ret = false;
            addErrorMessage("EESUSINGPROFILE");
            addNonTranslatedErrorMessage(StringUtils.join(authorizedUsers, ", "));
        }
        final List<String> rolesUsingProfile = getRulesWithEndEntityProfile(profileId);
        if (!rolesUsingProfile.isEmpty()) {
            ret = false;
            // Only return the used administrator roles if the admin is authorized to view them to prevent information leaks
            if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.VIEWROLES.resource())) {
                addErrorMessage("ADMINROLESUSINGPROFILE");
                addErrorMessage(StringUtils.join(rolesUsingProfile, ", "));
            }
        }
        // Remove profile if it's not in use
        return ret;
    }

    /** @return a list of role names where the End Entity Profile's ID is explicitly defined in the role's access rules */
    private List<String> getRulesWithEndEntityProfile(final int profileId) {
        if (log.isTraceEnabled()) {
            log.trace(">getRulesWithEndEntityProfile(" + profileId + ")");
        }
        final List<String> rolenames = new ArrayList<>();
        final Pattern idInRulename = Pattern.compile("^" + AccessRulesConstants.ENDENTITYPROFILEPREFIX + "(-?[0-9]+)/.*$");
        for (final Role role : roleDataSession.getAllRoles()) {
            for (final String explicitResource : role.getAccessRules().keySet()) {
                final Matcher matcher = idInRulename.matcher(explicitResource);
                if (matcher.find() && String.valueOf(profileId).equals(matcher.group(1))) {
                    rolenames.add(role.getRoleNameFull());
                    break;
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("End entity profile with id " + profileId + " is present in roles: " + StringUtils.join(rolenames, ", "));
        }
        if (log.isTraceEnabled()) {
            log.trace("<getRulesWithEndEntityProfile(" + profileId + ")");
        }
        return rolenames;
    }

    public void actionExportProfile() {
        clearMessages();
        if (getSelectedEndEntityProfileId() != null) {
            redirect(getEjbcaWebBean().getBaseUrl() + getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath() + "/profilesexport", "profileType",
                    "eep", "profileId", getSelectedEndEntityProfileId().toString());
        } else {
            addErrorMessage(PROFILE_NOT_SELECTED);
        }

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
                addErrorMessage(PROFILE_ALREADY_EXISTS);
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage("Not authorized to rename end entity profile.");
            }
        }
    }

    private boolean validateRenameOrClone() {
        boolean ok = true;
        if (!selectedProfileExists()) {
            addErrorMessage(PROFILE_NOT_SELECTED);
            ok = false;
        } else if (isEmptyProfile()) {
            addErrorMessage(YOU_CANT_EDIT_EMPTY_PROFILE);
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
            addErrorMessage("File is too large. Maximum size is " + (MAX_PROFILEZIP_FILESIZE / 1024 / 1024) + " MB, but server configuration may impose further limitations.");
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
        final Map<String, Set<Integer>> ignoredCAsByProfile = new HashMap<>();
        int nrOfFiles = 0;
        final ZipInputStream zipInputStream = new ZipInputStream(new ByteArrayInputStream(zipFileBytes));
        ZipEntry zipEntry = zipInputStream.getNextEntry();
        if (zipEntry == null) {
            // Print import message if the file header corresponds to an empty zip archive
            if (FileTools.isEmptyZipFile(zipFileBytes)) {
                printImportMessage(nrOfFiles, importedFiles, ignoredFiles, ignoredCAsByProfile);
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
            byte[] filebytes;
            try {
                filebytes = FileTools.readStreamToByteArray(zipInputStream, (int) zipEntry.getSize(), MAX_PROFILE_XML_SIZE);
            } catch (StreamSizeLimitExceededException e) {
                final String msg = "XML file '" + filename + "' is too large.";
                log.info(msg + " Ignoring file.");
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
                continue;
            }
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
                final Set<Integer> removedCAs = removeNonExistentCAsAndReturnRemovedCAs(eeProfile);
                if (!removedCAs.isEmpty()) {
                    ignoredCAsByProfile.put(profileName, removedCAs);
                }
                endEntityProfileSession.addEndEntityProfile(getAdmin(), profileId, profileName, eeProfile);
            }
            importedFiles.add(filename);
            log.info("Added End entity profile: " + profileName);
        } while ((zipEntry = zipInputStream.getNextEntry()) != null);
        zipInputStream.closeEntry();
        zipInputStream.close();
        printImportMessage(nrOfFiles, importedFiles, ignoredFiles, ignoredCAsByProfile);
    }

    private String createMessageForIgnoredCA(String endEntityProfileName, Set<Integer> removedCAs) {
        String caNames = removedCAs.stream()
            .map(String::valueOf)
            .reduce("", (acc, id) -> acc.equals("") ? acc + id : acc + ", " + id);
        return "Non existent CAs (with id " + caNames + ") removed from End Entity Profile " + endEntityProfileName + ". ";
    }

    private Set<Integer> removeNonExistentCAsAndReturnRemovedCAs(EndEntityProfile profile) {
        List<Integer> allCas = caSession.getAllCaIds();
        Set<Integer> removedCas = new HashSet<>();
        List<Integer> existentCAs = new ArrayList<>();
        profile.getAvailableCAs().forEach(id -> {
            if (allCas.contains(id)) {
                existentCAs.add(id);
            } else {
                removedCas.add(id);
            }
        });
        profile.setAvailableCAs(existentCAs);
        return removedCas;
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

    private void printImportMessage(final int nrOfFiles, final List<String> importedFiles, final List<String> ignoredFiles, final Map<String, Set<Integer>> ignoredCAsByProfile) {
        final String msg = "Number of files included in " + uploadFilename + ": " + nrOfFiles;
        log.info(msg);
        addNonTranslatedInfoMessage(msg);
        if (!importedFiles.isEmpty()) {
            addNonTranslatedInfoMessage("Imported End Entity Profiles from files: " + StringUtils.join(importedFiles, ", "));
        }
        if (!ignoredFiles.isEmpty()) {
            addNonTranslatedInfoMessage("Ignored files: " + StringUtils.join(ignoredFiles, ", "));
        }
        if (!ignoredCAsByProfile.isEmpty()) {
            ignoredCAsByProfile.forEach((profileName, caIds) -> addNonTranslatedInfoMessage(createMessageForIgnoredCA(profileName, caIds)));
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
            addErrorMessage(PROFILE_NOT_SELECTED);
        } else if (isEmptyProfile()) {
            addErrorMessage(YOU_CANT_EDIT_EMPTY_PROFILE);
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
                addErrorMessage(PROFILE_ALREADY_EXISTS);
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e);
            }
        }
    }
}
