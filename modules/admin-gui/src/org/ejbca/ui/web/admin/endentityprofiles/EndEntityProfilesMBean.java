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
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.TreeMap;
import javax.annotation.PostConstruct;
import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;

/**
 * 
 * JSF MBean backing edit end entity profiles page.
 *
 * @version $Id$
 */
@ManagedBean
@SessionScoped
public class EndEntityProfilesMBean extends BaseManagedBean implements Serializable {
    
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EndEntityProfilesMBean.class);
    
    private final EjbLocalHelper ejbLocalhelper = new EjbLocalHelper();
    private final AuthorizationSessionLocal authorizationSession = ejbLocalhelper.getAuthorizationSession();
    
    private EjbcaWebBean ejbcaWebBean = getEjbcaWebBean();
    private CAInterfaceBean caBean = new CAInterfaceBean();
    private RAInterfaceBean raBean = new RAInterfaceBean();
    private HardTokenInterfaceBean tokenBean = new HardTokenInterfaceBean();
       
    @PostConstruct
    private void postConstruct() throws Exception {
        final HttpServletRequest req = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        ejbcaWebBean.initialize(req, AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES);
        caBean.initialize(ejbcaWebBean);
        raBean.initialize(req, ejbcaWebBean);
        tokenBean.initialize(req, ejbcaWebBean);
    }
    
    private Integer selectedEndEntityProfileId = null;
    
    private boolean renameInProgress = false;
    private boolean deleteInProgress = false;
    private boolean viewOnly = true;
    
    private String endEntityProfileName;
    private String profile;
    
    private UploadedFile uploadFile;
    
    private List<SelectItem> endEntityProfileItems = null; 
    
    private class EndEntityProfileItem {
        private Integer id;
        private String name;
        
        private EndEntityProfileItem(final Integer id, final String name) {
            this.id = id;
            this.name = name;
        }
        
        private Integer getId() {
            return id;
        }

        private String getName() {
            return name;
        }
     }
    
    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    public void setEndEntityProfileName(String endEntityProfileName) {
        endEntityProfileName = endEntityProfileName.trim();
        if (StringTools.checkFieldForLegalChars(endEntityProfileName)) {
            addErrorMessage("ONLYCHARACTERS");
        } else {
            this.endEntityProfileName = endEntityProfileName;
        }
    }
            
    public boolean isAuthorizedToEdit() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES);
    }
    
    public boolean isAuthorizedToView() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES);
    }
    
    public boolean isViewOnly() {
        return viewOnly;
    }
    
    public boolean isEmptyProfile() {
        return selectedEndEntityProfileId.equals(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
    }
    
    public String getProfile() { 
        return profile;
    }
    
    public void setProfile(String profile) {
        this.profile = profile; 
    }
    
    public List<SelectItem> getEndEntityProfileItems() {
        if (endEntityProfileItems == null) {
            endEntityProfileItems = new ArrayList<>();
            final List<EndEntityProfileItem> items = new ArrayList<>();
            TreeMap<String,String> profiles = getEjbcaWebBean().getAuthorizedEndEntityProfileNames(AccessRulesConstants.VIEW_END_ENTITY);
            List<String> withMissingCAs = raBean.getAuthorizedEndEntityProfileIdsWithMissingCAs();
            for(Entry<String, String> entry : profiles.entrySet()) {
                String profileName = entry.getKey();
                String profileId = entry.getValue();
                final boolean missingCa = withMissingCAs.contains(profileId);
                String displayName = profileName + (missingCa ? " "+getEjbcaWebBean().getText("MISSINGCAIDS") : "");
                items.add(new EndEntityProfileItem(new Integer(profileId), displayName));
            }
            for (EndEntityProfileItem item : items){
                endEntityProfileItems.add(new SelectItem(item.getId(), item.getName() ));
            }
        }
         return endEntityProfileItems;
    } 
    
    public void actionAdd() {
        endEntityProfileName = getEndEntityProfileName();
        if (endEntityProfileName != null && endEntityProfileName.length() > 0) {
            try {
                final EndEntityProfile endEntityProfile = new EndEntityProfile();
                endEntityProfile.setAvailableCAs(getEjbcaWebBean().getAuthorizedCAIds());
                getEjbcaWebBean().getEjb().getEndEntityProfileSession().addEndEntityProfile(getAdmin(), endEntityProfileName, endEntityProfile);
                setEndEntityProfileName("");
            } catch (EndEntityProfileExistsException e) {
                addErrorMessage("ENDENTITYPROFILEALREADY");
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
        endEntityProfileItems = null;
    }
    
    public Integer getSelectedEndEntityProfileId() {
        return selectedEndEntityProfileId;
    }

    public void setSelectedEndEntityProfileId(final Integer selectedEndEntityProfileId) {
        this.selectedEndEntityProfileId = selectedEndEntityProfileId;
    }

    public void actionDelete() {
        if (selectedProfileExists()) {
            deleteInProgress = true;
        }
    }
        
    public boolean isDeleteInProgress() {
        return deleteInProgress;
    }
    
    private boolean selectedProfileExists() {
        if(selectedEndEntityProfileId != null) {
            return getEjbcaWebBean().getEjb().getEndEntityProfileSession().getEndEntityProfile(selectedEndEntityProfileId) != null;
        } else {
            return false;
        }
    }
    
    public String getSelectedEndEntityProfileName() {
        final Integer profileId = getSelectedEndEntityProfileId();
        if (profileId != null) {
            return getEjbcaWebBean().getEjb().getEndEntityProfileSession().getEndEntityProfileName(profileId.intValue());
        }
        return null;
    }
    
    public void actionDeleteConfirm() {
        try {
            getEjbcaWebBean().getEjb().getEndEntityProfileSession().removeEndEntityProfile(getAdmin(), getSelectedEndEntityProfileName());
            getEjbcaWebBean().getEjb().getCertificateProfileSession().flushProfileCache();
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage("Not authorized to remove end entity profile.");
        }
        actionCancel();
        super.nonAjaxPostRedirectGet(null);
    }
        
    public void actionCancel() {
        deleteInProgress = false;
        renameInProgress = false;
        endEntityProfileItems = null;
        selectedEndEntityProfileId = null;
        endEntityProfileName = null;
    }
        
    public boolean isRenameInProgress() {
        return renameInProgress;
    }

    public void actionRename() {
        if (selectedProfileExists()) {
            renameInProgress = true;
        }
    }

    public void actionRenameConfirm() {
        if (selectedProfileExists()) {
            final String endEntityProfileName = getEndEntityProfileName();
            if (endEntityProfileName.length() > 0) {
                if(isEmptyProfile()) {
                    addErrorMessage("YOUCANTEDITEMPTYPROFILE");
                } else {
                    try {
                        getEjbcaWebBean().getEjb().getEndEntityProfileSession().renameEndEntityProfile(getAdmin(), getSelectedEndEntityProfileName(), endEntityProfileName);
                        setEndEntityProfileName("");
                    } catch (EndEntityProfileExistsException e) {
                        addErrorMessage("ENDENTITYPROFILEALREADY");
                    } catch (AuthorizationDeniedException e) {
                        addNonTranslatedErrorMessage("Not authorized to rename end entity profile.");
                    }
                }
            }
            actionCancel();
        }
    }
    
    public boolean isOperationInProgress() {
        return isRenameInProgress() || isDeleteInProgress();
    }
    
    public String editProfile() {
        return "edit";
    }
    
    public String viewProfile() {
        return "view";
    }
    
    public String saveProfile() {
        return "done";
    }
    public String leaveProfile() {
        return "done";
    }
    public String getInputName() {
        return ejbcaWebBean.getText("FORMAT_ID_STR");
    }
    
    public void actionImportProfiles() throws IOException, FileUploadException, NumberFormatException, AuthorizationDeniedException, EndEntityProfileExistsException, EndEntityProfileNotFoundException {
        if (uploadFile == null) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "File upload failed.", null));
            return;
        }
        importProfilesFromZip(getUploadFile().getBytes());
        endEntityProfileItems = null;
    }
    
    public void importProfilesFromZip(byte[] filebuffer) throws AuthorizationDeniedException,
    NumberFormatException, IOException, EndEntityProfileExistsException, EndEntityProfileNotFoundException {
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
            if (ignoreProfile(filename, profilename, profileid)) {
                ignoredFiles += filename + ", ";
                continue;
            }
            if (getEjbcaWebBean().getEjb().getEndEntityProfileSession().getEndEntityProfile(profileid) != null) {
                log.warn("Endentity profile id '" + profileid + "' already exist in database. Adding with a new profile id instead.");
                profileid = -1; // create a new id when adding the profile
            }
            byte[] filebytes = new byte[102400];
            int i = 0;
            while ((zipInputstream.available() == 1) && (i < filebytes.length)) {
                filebytes[i++] = (byte) zipInputstream.read();
            }
            final EndEntityProfile eeProfile = getEndEntityProfileFromByteArray(profilename, filebytes);
            if (eeProfile == null) {
                String msg = "Faulty XML file '" + filename + "'. Failed to read end entity Profile.";
                log.info(msg + " Ignoring file.");
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
                continue;
            }
            if (profileid == -1) {
                getEjbcaWebBean().getEjb().getEndEntityProfileSession().addEndEntityProfile(getAdmin(), profilename, eeProfile);
            } else {
                getEjbcaWebBean().getEjb().getEndEntityProfileSession().addEndEntityProfile(getAdmin(), profileid, profilename, eeProfile);                
            }
            importedFiles += filename + ", ";
            log.info("Added End entity profile: " + profilename);
        } while ((zipEntry = zipInputstream.getNextEntry()) != null);
        zipInputstream.closeEntry();
        zipInputstream.close();
        printImportMessage(nrOfFiles, importedFiles, ignoredFiles);
    }

    private EndEntityProfile getEndEntityProfileFromByteArray(String profilename, byte[] profileBytes) {
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
    private boolean ignoreFile(String filename) {
        if (filename.lastIndexOf(".xml") != (filename.length() - 4)) {
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
    private boolean ignoreProfile(String filename, String profilename, int profileid) throws EndEntityProfileNotFoundException {
        // Check if the profiles already exist
        if (ejbcaWebBean.getEjb().getEndEntityProfileSession().getEndEntityProfile(profilename) != null) {
            log.info("End entity profile '" + profilename + "' already exist in database. IGNORED");
            return true;
        }
       return false;
    }
        
    private void printImportMessage(int nrOfFiles, String importedFiles, String ignoredFiles) {
        String msg = "Number of files included in " + uploadFile.getName() + ": " + nrOfFiles;
        log.info(msg);
        FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_INFO, msg, null));
        if (StringUtils.isNotEmpty(importedFiles)) {
            importedFiles = importedFiles.substring(0, importedFiles.length() - 2);
        }
        msg = "Imported End Entity Profiles from files: " + importedFiles;
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

    public void setUploadFile(UploadedFile uploadFile) {
        this.uploadFile = uploadFile;
    }
    
    public UploadedFile getUploadFile() {
        return uploadFile;
    }
    
    public String actionEdit() {
        if (isEmptyProfile()) {
            addErrorMessage("YOUCANTEDITEMPTYPROFILE");
            return "";
        } else if (selectedProfileExists()) {
            viewOnly = false;
            return "edit"; 
        } else {
            return "";
        }
    }

    /*public String actionView() {
        selectCurrentRowData();
        if (selectedProfileExists()) {
            viewOnly = true;
            return "view"; // Outcome is defined in faces-config.xml
        } else {
            return "";
        }
    }*/
    
    public void actionCloneProfile() {
        final String endEntityProfileName = getEndEntityProfileName();
        if (endEntityProfileName.length() > 0) {
            try {
                getEjbcaWebBean().getEjb().getEndEntityProfileSession().cloneEndEntityProfile(getAdmin(), getSelectedEndEntityProfileName(), endEntityProfileName);
            } catch (EndEntityProfileExistsException e) {
                addErrorMessage("ENDENTITYPROFILEALREADY");
                
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage()); 
            }
            setEndEntityProfileName("");
        }
        actionCancel();
    }
}
