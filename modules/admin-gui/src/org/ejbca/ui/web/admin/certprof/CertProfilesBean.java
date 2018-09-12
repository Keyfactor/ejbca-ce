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
package org.ejbca.ui.web.admin.certprof;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.annotation.PostConstruct;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JSF MBean backing the certificate profiles pages.
 *  
 * @version $Id$
 */
// Declarations in faces-config.xml
//@javax.faces.bean.RequestScoped
//@javax.faces.bean.ManagedBean(name="certProfilesBean")
public class CertProfilesBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CertProfilesBean.class);

    // This restriction in certificate profile naming can be removed when the current running version no longer has
    // to be able to run side by side (share the db) with an EJBCA 6.1.x or earlier
    @Deprecated
    private static final String LEGACY_FIXED_MARKER = "(FIXED)";

    public class CertificateProfileItem {
        private final int id;
        private final String name;
        private final boolean fixed;
        private final boolean missingCa;

        public CertificateProfileItem(final int id, final String name, final boolean fixed, final boolean missingCa) {
            this.id = id;
            this.name = name;
            this.fixed = fixed;
            this.missingCa = missingCa;
        }

        public int getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public boolean isFixed() {
            return fixed;
        }

        public boolean isMissingCa() {
            return missingCa;
        }
    }

    private Integer selectedCertProfileId = null;
    private boolean renameInProgress = false;
    private boolean deleteInProgress = false;
    private boolean addFromTemplateInProgress = false;
    private String certProfileName = "";
    private boolean viewOnly = true;
    private ListDataModel<CertificateProfileItem> certificateProfileItems = null;


    // Authentication check and audit log page access request
    @PostConstruct
    public void initialize() throws Exception {
        final HttpServletRequest request = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
        getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CERTIFICATEPROFILEVIEW.resource());
    }
    
    public Integer getSelectedCertProfileId() {
        return selectedCertProfileId;
    }

    public void setSelectedCertProfileId(final Integer selectedCertProfileId) {
        this.selectedCertProfileId = selectedCertProfileId;
    }

    public String getSelectedCertProfileName() {
        final Integer profileId = getSelectedCertProfileId();
        if (profileId != null) {
            return getEjbcaWebBean().getEjb().getCertificateProfileSession().getCertificateProfileName(profileId.intValue());
        }
        return null;
    }

    // Force a shorter scope (than session scoped) for the ListDataModel by always resetting it before it is rendered
    public String getResetCertificateProfilesTrigger() {
        certificateProfileItems = null;
        return "";
    }


    public ListDataModel<CertificateProfileItem> getCertificateProfiles() {
        if (certificateProfileItems == null) {
            final List<CertificateProfileItem> items = new ArrayList<>();
            final CertificateProfileSessionLocal certificateProfileSession = getEjbcaWebBean().getEjb().getCertificateProfileSession();
            final List<Integer> authorizedProfileIds = new ArrayList<>();

            //Always include
            authorizedProfileIds.addAll(certificateProfileSession.getAuthorizedCertificateProfileIds(getAdmin(),
                    CertificateConstants.CERTTYPE_ENDENTITY));
            if (isAuthorizedTo(StandardRules.ROLE_ROOT.resource())) {
                //Only root users may use CA profiles
                authorizedProfileIds.addAll(certificateProfileSession.getAuthorizedCertificateProfileIds(getAdmin(),
                        CertificateConstants.CERTTYPE_ROOTCA));
                authorizedProfileIds.addAll(certificateProfileSession.getAuthorizedCertificateProfileIds(getAdmin(),
                        CertificateConstants.CERTTYPE_SUBCA));
            }
            boolean usingHardwareTokens = getEjbcaWebBean().getGlobalConfiguration().getIssueHardwareTokens();
            if (usingHardwareTokens) {
                authorizedProfileIds.addAll(certificateProfileSession.getAuthorizedCertificateProfileIds(getAdmin(),
                        CertificateConstants.CERTTYPE_HARDTOKEN));
            }
            final List<Integer> profileIdsWithMissingCA = certificateProfileSession.getAuthorizedCertificateProfileWithMissingCAs(getAdmin());
            final Map<Integer, String> idToNameMap = certificateProfileSession.getCertificateProfileIdToNameMap();
            final Set<Integer> existing = new HashSet<>();
            for(Integer profileId : authorizedProfileIds) {
                final boolean missingCa = profileIdsWithMissingCA.contains(profileId);
                final boolean fixed = isCertProfileFixed(profileId);
                final String name = idToNameMap.get(profileId);
                if (existing.add(profileId)) { // Don't add twice!
                    items.add(new CertificateProfileItem(profileId, name, fixed, missingCa));
                }
            }
            // Sort list by name
            Collections.sort(items, new Comparator<CertificateProfileItem>() {
                @Override
                public int compare(final CertificateProfileItem a, final CertificateProfileItem b) {
                    if(isCertProfileFixed(a.getId()) && !isCertProfileFixed(b.getId())) {
                        return -1;
                    } else if(!isCertProfileFixed(a.getId()) && isCertProfileFixed(b.getId())) {
                        return 1;
                    } else {
                    return a.getName().compareToIgnoreCase(b.getName());
                    }
                }
            });
            certificateProfileItems = new ListDataModel<>(items);
        }
        return certificateProfileItems;
    }

    /** @return true if the specified certificate profile id is fixed */
    private boolean isCertProfileFixed(final int profileId) {
        if (profileId <= CertificateProfileConstants.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
            return true;
        } else {
            return false;
        }
    }

    public boolean isAuthorizedToEdit() {
        return isAuthorizedTo(StandardRules.CERTIFICATEPROFILEEDIT.resource());
    }

    public boolean isAuthorizedToOnlyView() {
        return isAuthorizedTo(StandardRules.CERTIFICATEPROFILEVIEW.resource()) && !isAuthorizedToEdit();
    }

    public String actionEdit() {
        selectCurrentRowData();
        if (selectedProfileExists()) {
            viewOnly = false;
            return "edit"; // Outcome is defined in faces-config.xml
        } else {
            return "";
        }
    }

    public String actionView() {
        selectCurrentRowData();
        if (selectedProfileExists()) {
            viewOnly = true;
            return "view"; // Outcome is defined in faces-config.xml
        } else {
            return "";
        }
    }
    
    public boolean getViewOnly() {
        return viewOnly;
    }

    private void selectCurrentRowData() {
        final CertificateProfileItem certificateProfileItem = getCertificateProfiles().getRowData();
        selectedCertProfileId = certificateProfileItem.getId();
    }

    public boolean isOperationInProgress() {
        return isRenameInProgress() || isDeleteInProgress() || isAddFromTemplateInProgress();
    }

    public void actionAdd() {
        final String certProfileName = getCertProfileName();
        if (certProfileName.endsWith(LEGACY_FIXED_MARKER)) {
            addErrorMessage("YOUCANTEDITFIXEDCERTPROFS");
        } else if (certProfileName.length() > 0) {
            try {
                final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
                certificateProfile.setAvailableCAs(getEjbcaWebBean().getAuthorizedCAIds());
                getEjbcaWebBean().getEjb().getCertificateProfileSession().addCertificateProfile(getAdmin(), certProfileName, certificateProfile);
                setCertProfileName("");
            } catch (CertificateProfileExistsException e) {
                addErrorMessage("CERTIFICATEPROFILEALREADY");
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
        certificateProfileItems = null;
    }

    public boolean isAddFromTemplateInProgress() {
        return addFromTemplateInProgress;
    }

    public void actionAddFromTemplate() {
        selectCurrentRowData();
        if (selectedProfileExists()) {
            addFromTemplateInProgress = true;
        }
    }

    public void actionAddFromTemplateConfirm() {
        final String certProfileName = getCertProfileName();
        if (certProfileName.endsWith(LEGACY_FIXED_MARKER)) {
            addErrorMessage("YOUCANTEDITFIXEDCERTPROFS");
        } else if (certProfileName.length() > 0) {
            try {
                final List<Integer> authorizedCaIds;
                if (isCertProfileFixed(getSelectedCertProfileId()) && !isAuthorizedTo(StandardRules.ROLE_ROOT.resource())) {
                    // Expand ANYCA to the current admin's list of authorized CA Ids
                    authorizedCaIds = getEjbcaWebBean().getEjb().getCaSession().getAuthorizedCaIds(getAdmin());
                } else {
                    // Use null as authorizedCaIds, so we will copy the profile exactly as the template(, including ANY CA for SuperAdmin)
                    authorizedCaIds = null;
                }
                getEjbcaWebBean().getEjb().getCertificateProfileSession()
                        .cloneCertificateProfile(getAdmin(), getSelectedCertProfileName(), certProfileName, authorizedCaIds);
                setCertProfileName("");
            } catch (CertificateProfileExistsException e) {
                addErrorMessage("CERTIFICATEPROFILEALREADY");
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            } catch (CertificateProfileDoesNotExistException e) {
                // NOPMD: ignore do nothing
            }
            
        }
        actionCancel();
    }

    public boolean isDeleteInProgress() {
        return deleteInProgress;
    }

    public void actionDelete() {
        selectCurrentRowData();
        if (selectedProfileExists()) {
            deleteInProgress = true;
        }
    }

    public void actionDeleteConfirm() {
        if (canDeleteCertProfile()) {
            try {
                getEjbcaWebBean().getEjb().getCertificateProfileSession().removeCertificateProfile(getAdmin(), getSelectedCertProfileName());
                getEjbcaWebBean().getEjb().getCertificateProfileSession().flushProfileCache();
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage("Not authorized to remove certificate profile.");
            }
        } else {
            addErrorMessage("COULDNTDELETECERTPROF");
        }
        actionCancel();
    }

    public boolean isRenameInProgress() {
        return renameInProgress;
    }

    public void actionRename() {
        selectCurrentRowData();
        if (selectedProfileExists()) {
            renameInProgress = true;
        }
    }

    public void actionRenameConfirm() {
        final String certProfileName = getCertProfileName();
        if (certProfileName.endsWith(LEGACY_FIXED_MARKER)) {
            addErrorMessage("YOUCANTEDITFIXEDCERTPROFS");
        } else if (certProfileName.length() > 0) {
            try {
                getEjbcaWebBean().getEjb().getCertificateProfileSession()
                        .renameCertificateProfile(getAdmin(), getSelectedCertProfileName(), certProfileName);
                setCertProfileName("");
            } catch (CertificateProfileExistsException e) {
                addErrorMessage("CERTIFICATEPROFILEALREADY");
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage("Not authorized to rename certificate profile.");
            }
        }
        actionCancel();
    }

    public void actionCancel() {
        addFromTemplateInProgress = false;
        deleteInProgress = false;
        renameInProgress = false;
        certificateProfileItems = null;
        selectedCertProfileId = null;
        certProfileName = null;
    }
    
    /** @return true if there exists a certificate profile with the selected id */
    private boolean selectedProfileExists() {
        return getEjbcaWebBean().getEjb().getCertificateProfileSession().getCertificateProfile(selectedCertProfileId) != null;
    }

    private boolean canDeleteCertProfile() {
        boolean ret = true;
        final int certificateProfileId = getSelectedCertProfileId().intValue();
        final CertificateProfile certProfile = getEjbcaWebBean().getEjb().getCertificateProfileSession().getCertificateProfile(certificateProfileId);
        final int certProfileType = certProfile.getType();
        // Count number of EEs that reference this CP
        if (certProfileType == CertificateConstants.CERTTYPE_ENDENTITY) {
            final long numberOfEndEntitiesReferencingCP = getEjbcaWebBean().getEjb().getEndEntityAccessSession().countByCertificateProfileId(certificateProfileId);
            if (numberOfEndEntitiesReferencingCP > 1000) {
                ret = false;
                addErrorMessage("CERTPROFILEUSEDINENDENTITIES");
                addErrorMessage("CERTPROFILEUSEDINENDENTITIESEXCESSIVE");
            } else if (numberOfEndEntitiesReferencingCP > 0) {
                ret = false;
                addErrorMessage("CERTPROFILEUSEDINENDENTITIES");
                final List<String> eeNames = getEjbcaWebBean().getEjb().getEndEntityAccessSession()
                        .findByCertificateProfileId(certificateProfileId);
                addNonTranslatedErrorMessage(getEjbcaWebBean().getText("DISPLAYINGFIRSTTENRESULTS") + numberOfEndEntitiesReferencingCP + " "
                        + getAsCommaSeparatedString(eeNames));
            }
        }
        // Check if certificate profile is in use by any service
        final List<String> servicesReferencingCP = getEjbcaWebBean().getEjb().getServiceSession()
                .getServicesUsingCertificateProfile(certificateProfileId);
        if (!servicesReferencingCP.isEmpty()) {
            ret = false;
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("CERTPROFILEUSEDINSERVICES") + " "
                    + getAsCommaSeparatedString(servicesReferencingCP));
        }
        // Check if certificate profile is in use by any end entity profile
        if (certProfileType == CertificateConstants.CERTTYPE_ENDENTITY || certProfileType == CertificateConstants.CERTTYPE_SUBCA) {
            final List<String> endEntityProfilesReferencingCP = getEjbcaWebBean().getEjb().getEndEntityProfileSession()
                    .getEndEntityProfilesUsingCertificateProfile(certificateProfileId);
            if (!endEntityProfilesReferencingCP.isEmpty()) {
                ret = false;
                addNonTranslatedErrorMessage(getEjbcaWebBean().getText("CERTPROFILEUSEDINENDENTITYPROFILES") + " "
                        + getAsCommaSeparatedString(endEntityProfilesReferencingCP));
            }
        }
        // Check if certificate profile is in use by any hard token profile
        if (certProfileType == CertificateConstants.CERTTYPE_ENDENTITY) {
            final List<String> hardTokenProfilesReferencingCP = getEjbcaWebBean().getEjb().getHardTokenSession()
                    .getHardTokenProfileUsingCertificateProfile(certificateProfileId);
            if (!hardTokenProfilesReferencingCP.isEmpty()) {
                ret = false;
                addNonTranslatedErrorMessage(getEjbcaWebBean().getText("CERTPROFILEUSEDINHARDTOKENPROFILES") + " "
                        + getAsCommaSeparatedString(hardTokenProfilesReferencingCP));
            }
        }
        if (certProfileType != CertificateConstants.CERTTYPE_ENDENTITY) {
            // Check if certificate profile is in use by any CA
            final List<String> casReferencingCP = getEjbcaWebBean().getEjb().getCaAdminSession().getCAsUsingCertificateProfile(certificateProfileId);
            if (!casReferencingCP.isEmpty()) {
                ret = false;
                addNonTranslatedErrorMessage(getEjbcaWebBean().getText("CERTPROFILEUSEDINCAS") + " " + getAsCommaSeparatedString(casReferencingCP));
            }
        }
        return ret;
    }

    private String getAsCommaSeparatedString(final List<String> list) {
        final StringBuilder sb = new StringBuilder();
        for (final String entry : list) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(entry);
        }
        return sb.toString();
    }

    public String getCertProfileName() {
        return certProfileName;
    }

    public void setCertProfileName(String certProfileName) {
        certProfileName = certProfileName.trim();
        if (StringTools.checkFieldForLegalChars(certProfileName)) {
            addErrorMessage("ONLYCHARACTERS");
        } else {
            this.certProfileName = certProfileName;
        }
    }

    //----------------------------------------------
    //                Import profiles
    //----------------------------------------------
    private UploadedFile uploadFile;

    public UploadedFile getUploadFile() {
        return uploadFile;
    }

    public void setUploadFile(UploadedFile uploadFile) {
        this.uploadFile = uploadFile;
    }

    public void actionImportProfiles() {

        if (uploadFile == null) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "File upload failed.", null));
            return;
        }
        try {
            importProfilesFromZip(getUploadFile().getBytes());
            certificateProfileItems = null;
        } catch (IOException e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
        } catch (AuthorizationDeniedException e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
        } catch (NumberFormatException e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
        } catch (CertificateProfileExistsException e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
        }

    }

    public void importProfilesFromZip(byte[] filebuffer) throws CertificateProfileExistsException, AuthorizationDeniedException,
            NumberFormatException, IOException {

        if (filebuffer.length == 0) {
            throw new IllegalArgumentException("No input file");
        }

        String importedFiles = "";
        String ignoredFiles = "";
        int nrOfFiles = 0;

        ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(filebuffer));
        ZipEntry ze = zis.getNextEntry();
        if (ze == null) {
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
            String profilename = filename.substring(index1 + 1, index2);
            int profileid = 0;
            try {
                profileid = Integer.parseInt(filename.substring(index2 + 1, index3));
            } catch (NumberFormatException e) {
                if (log.isDebugEnabled()) {
                    log.debug("NumberFormatException parsing certificate profile id: " + e.getMessage());
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

            if (getEjbcaWebBean().getEjb().getCertificateProfileSession().getCertificateProfile(profileid) != null) {
                log.warn("Certificate profile id '" + profileid + "' already exist in database. Adding with a new profile id instead.");
                profileid = -1; // means we should create a new id when adding the cert profile
            }

            byte[] filebytes = new byte[102400];
            int i = 0;
            while ((zis.available() == 1) && (i < filebytes.length)) {
                filebytes[i++] = (byte) zis.read();
            }

            final CertificateProfile certificateProfile = getCertProfileFromByteArray(profilename, filebytes);
            if (certificateProfile == null) {
                String msg = "Faulty XML file '" + filename + "'. Failed to read Certificate Profile.";
                log.info(msg + " Ignoring file.");
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
                continue;
            }
            
            if (profileid == -1) {
                getEjbcaWebBean().getEjb().getCertificateProfileSession().addCertificateProfile(getAdmin(), profilename, certificateProfile);
            } else {
                getEjbcaWebBean().getEjb().getCertificateProfileSession().addCertificateProfile(getAdmin(), profileid, profilename, certificateProfile);                
            }
            importedFiles += filename + ", ";
            log.info("Added Certificate profile: " + profilename);
        } while ((ze = zis.getNextEntry()) != null);
        zis.closeEntry();
        zis.close();
        
        printImportMessage(nrOfFiles, importedFiles, ignoredFiles);
    }

    /**
     * Logs and creates FacesMessage with information about number of files, imported files
     * and ignored files when importing Certificate Profiles.
     * 
     * @param nrOfFiles the number of files the uploaded archive contained
     * @param importedFiles the files in the archive that were imported
     * @param ignoredFiles the files in the archive that were ignored
     */
    private void printImportMessage(int nrOfFiles, String importedFiles, String ignoredFiles) {
        String msg = uploadFile.getName() + " contained " + nrOfFiles + " files. ";
        log.info(msg);
        FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_INFO, msg, null));

        if (StringUtils.isNotEmpty(importedFiles)) {
            importedFiles = importedFiles.substring(0, importedFiles.length() - 2);
        }
        msg = "Imported Certificate Profiles from files: " + importedFiles;
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

    private CertificateProfile getCertProfileFromByteArray(String profilename, byte[] profileBytes) {
        ByteArrayInputStream is = new ByteArrayInputStream(profileBytes);
        CertificateProfile cprofile = new CertificateProfile();
        try {
            final SecureXMLDecoder decoder = new SecureXMLDecoder(is);
            // Add certificate profile
            Object data = null;
            try {
                data = decoder.readObject();
            } catch (IOException e) {
                log.info("Error parsing certificate profile data: " + e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("Full stack trace: ", e);
                }
                return null;
            } finally {
                decoder.close();
            }
            cprofile.loadData(data);

            // Make sure CAs in profile exist
            List<Integer> cas = cprofile.getAvailableCAs();
            ArrayList<Integer> casToRemove = new ArrayList<>();
            for (Integer currentCA : cas) {
                // If the CA is not ANYCA and the CA does not exist, remove it from the profile before import
                if (currentCA != CertificateProfile.ANYCA) {
                    if(!getEjbcaWebBean().getEjb().getCaSession().existsCa(currentCA)) {
                        casToRemove.add(currentCA);
                    }
                }
            }
            for (Integer toRemove : casToRemove) {
                log.warn("Warning: CA with id " + toRemove + " was not found and will not be used in certificate profile '" + profilename + "'.");
                cas.remove(toRemove);
            }
            if (cas.size() == 0) {
                log.warn("Error: No CAs left in certificate profile '" + profilename + "' and no CA specified on command line. Using ANYCA.");
                cas.add(Integer.valueOf(CertificateProfile.ANYCA));

            }
            cprofile.setAvailableCAs(cas);
            // Remove and warn about unknown publishers
            List<Integer> publishers = cprofile.getPublisherList();
            ArrayList<Integer> allToRemove = new ArrayList<>();
            for (Integer publisher : publishers) {
                BasePublisher pub = null;
                try {
                    pub = getEjbcaWebBean().getEjb().getPublisherSession().getPublisher(publisher);
                } catch (Exception e) {
                    log.warn("Warning: There was an error loading publisher with id " + publisher + ". Use debug logging to see stack trace: "
                            + e.getMessage());
                    if (log.isDebugEnabled()) {
                        log.debug("Full stack trace: ", e);
                    }
                }
                if (pub == null) {
                    allToRemove.add(publisher);
                }
            }
            for (Integer toRemove : allToRemove) {
                log.warn("Warning: Publisher with id " + toRemove + " was not found and will not be used in certificate profile '" + profilename
                        + "'.");
                publishers.remove(toRemove);
            }
            cprofile.setPublisherList(publishers);

        } finally {
            try {
                is.close();
            } catch (IOException e) {
                throw new IllegalStateException("Unknown IOException was caught when closing stream", e);
            }
        }
        return cprofile;
    }

    /** @return trueif the file shall be ignored from a Certificate Profile import, false if it should be imported */
    private boolean ignoreFile(String filename) {
        if (filename.lastIndexOf(".xml") != (filename.length() - 4)) {
            log.info(filename + " is not an XML file. IGNORED");
            return true;
        }

        if (filename.indexOf("_") < 0 || filename.lastIndexOf("-") < 0 || (filename.indexOf("certprofile_") < 0)) {
            log.info(filename + " is not in the expected format. "
                    + "The file name should look like: certprofile_<profile name>-<profile id>.xml. IGNORED");
            return true;
        }
        return false;
    }

    /** @return true if the profile should be ignored from a Certificate Profile import because it already exists, false if it should be imported */
    private boolean ignoreProfile(String filename, String profilename, int profileid) {
        // We don't add the fixed profiles, EJBCA handles those automagically
        if (CertificateProfileConstants.isFixedCertificateProfile(profileid)) {
            log.info(filename + " contains a fixed profile. IGNORED");
            return true;
        }
        // Check if the profiles already exist
        if (getEjbcaWebBean().getEjb().getCertificateProfileSession().getCertificateProfileId(profilename) != CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
            log.info("Certificate profile '" + profilename + "' already exist in database. IGNORED");
            return true;
        }
        return false;
    }
}
