/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.regex.Pattern;

import javax.faces.model.ListDataModel;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
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
    //private static final Logger log = Logger.getLogger(CertProfilesBean.class);
    
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
        public int getId() { return id; }
        public String getName() { return name; }
        public boolean isFixed() { return fixed; }
        public boolean isMissingCa() { return missingCa; }
    }
    
    private Integer selectedCertProfileId = null;
    private boolean renameInProgress = false;
    private boolean deleteInProgress = false;
    private boolean addFromTemplateInProgress = false;
    private String certProfileName = "";

    public Integer getSelectedCertProfileId() { return selectedCertProfileId; }
    public void setSelectedCertProfileId(final Integer selectedCertProfileId) { this.selectedCertProfileId = selectedCertProfileId; }

    public String getSelectedCertProfileName() {
        final Integer profileId = getSelectedCertProfileId();
        if (profileId!=null) {
            return getEjbcaWebBean().getEjb().getCertificateProfileSession().getCertificateProfileName(profileId.intValue());
        }
        return null;
    }
    
    // Force a shorter scope (than session scoped) for the ListDataModel by always resetting it before it is rendered
    public String getResetCertificateProfilesTrigger() {
        certificateProfileItems = null;
        return "";
    }
    
    private ListDataModel certificateProfileItems = null;
    public ListDataModel/*<CertificateProfileItem>*/ getCertificateProfiles() {
        if (certificateProfileItems==null) {
            final List<CertificateProfileItem> items = new ArrayList<CertificateProfileItem>();
            final TreeMap<String, Integer> profileNameToIdMap = getEjbcaWebBean().getInformationMemory().getEditCertificateProfileNames();
            final List<Integer> profileIdsWithMissingCA = getEjbcaWebBean().getInformationMemory().getEditCertificateProfilesWithMissingCAs();
            for (final Entry<String,Integer> entry : profileNameToIdMap.entrySet()) {
                final Integer profileId = entry.getValue();
                final boolean missingCa = profileIdsWithMissingCA.contains(profileId);
                final boolean fixed = isCertProfileFixed(profileId);
                final String name = getEjbcaWebBean().getEjb().getCertificateProfileSession().getCertificateProfileName(profileId);
                items.add(new CertificateProfileItem(profileId, name, fixed, missingCa));
            }
            certificateProfileItems = new ListDataModel(items);
        }
        return certificateProfileItems;
    }

    /** @return true if the specified certificate profile id is fixed */
    private boolean isCertProfileFixed(final int profileId) {
        final TreeMap<String, Integer> profileNameToIdMap = getEjbcaWebBean().getInformationMemory().getEditCertificateProfileNames();
        for (final Entry<String,Integer> entry : profileNameToIdMap.entrySet()) {
            if (entry.getValue().intValue() == profileId) {
                if (entry.getKey().endsWith(LEGACY_FIXED_MARKER)) {
                    return true;
                }
                break;
            }
        }
        return false;
    }

    public boolean isAuthorizedToEdit() {
        return getEjbcaWebBean().getEjb().getAccessControlSession().isAuthorizedNoLogging(getAdmin(), StandardRules.EDITCERTIFICATEPROFILE.resource());
    }
    
    public String actionEdit() {
        selectCurrentRowData();
        return "edit";   // Outcome is defined in faces-config.xml
    }
    
    private void selectCurrentRowData() {
        final CertificateProfileItem certificateProfileItem = (CertificateProfileItem) getCertificateProfiles().getRowData();
        selectedCertProfileId = certificateProfileItem.getId();
    }

    public boolean isOperationInProgress() { return isRenameInProgress() || isDeleteInProgress() || isAddFromTemplateInProgress(); }
    
    public void actionAdd() {
        final String certProfileName = getCertProfileName();
        if (certProfileName.endsWith(LEGACY_FIXED_MARKER)) {
            addErrorMessage("YOUCANTEDITFIXEDCERTPROFS");
        } else if (certProfileName.length()>0) {
            try {
                final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
                certificateProfile.setAvailableCAs(getEjbcaWebBean().getInformationMemory().getAuthorizedCAIds());
                getEjbcaWebBean().getEjb().getCertificateProfileSession().addCertificateProfile(getAdmin(), certProfileName, certificateProfile);
                getEjbcaWebBean().getInformationMemory().certificateProfilesEdited();
                setCertProfileName("");
            } catch(CertificateProfileExistsException e){
                addErrorMessage("CERTIFICATEPROFILEALREADY");
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
        certificateProfileItems = null;
    }

    public boolean isAddFromTemplateInProgress() { return addFromTemplateInProgress; }

    public void actionAddFromTemplate() {
        selectCurrentRowData();
        addFromTemplateInProgress = true;
    }
    
    public void actionAddFromTemplateConfirm() {
        final String certProfileName = getCertProfileName();
        if (certProfileName.endsWith(LEGACY_FIXED_MARKER)) {
            addErrorMessage("YOUCANTEDITFIXEDCERTPROFS");
        } else if (certProfileName.length()>0) {
            try {
                // Use null as authorizedCaIds, so we will copy the profile exactly as the template, including available CAs
                getEjbcaWebBean().getEjb().getCertificateProfileSession().cloneCertificateProfile(getAdmin(), getSelectedCertProfileName(), certProfileName, null);
                getEjbcaWebBean().getInformationMemory().certificateProfilesEdited();
                setCertProfileName("");
            } catch(CertificateProfileExistsException e) {
                addErrorMessage("CERTIFICATEPROFILEALREADY");
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            } catch (CertificateProfileDoesNotExistException e) {
                // NOPMD: ignore do nothing
            }
        }
        addFromTemplateInProgress = false;
        certificateProfileItems = null;
    }
    
    public void actionAddFromTemplateCancel() {
        addFromTemplateInProgress = false;
        certificateProfileItems = null;
    }
    
    public boolean isDeleteInProgress() { return deleteInProgress; }

    public void actionDelete() {
        selectCurrentRowData();
        deleteInProgress = true;
    }
    
    public void actionDeleteConfirm() {
        if (canDeleteCertProfile()) {
            try {
                getEjbcaWebBean().getEjb().getCertificateProfileSession().removeCertificateProfile(getAdmin(), getSelectedCertProfileName());
                getEjbcaWebBean().getInformationMemory().certificateProfilesEdited();
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage("Not authorized to remove certificate profile.");
            }
        } else {
            addErrorMessage("COULDNTDELETECERTPROF");
        }
        deleteInProgress = false;
        certificateProfileItems = null;
    }
    
    public void actionDeleteCancel() {
        deleteInProgress = false;
        certificateProfileItems = null;
    }
    
    public boolean isRenameInProgress() { return renameInProgress; }

    public void actionRename() {
        selectCurrentRowData();
        renameInProgress = true;
    }

    public void actionRenameConfirm() {
        final String certProfileName = getCertProfileName();
        if (certProfileName.endsWith(LEGACY_FIXED_MARKER)) {
            addErrorMessage("YOUCANTEDITFIXEDCERTPROFS");
        } else if (certProfileName.length()>0) {
            try {
                getEjbcaWebBean().getEjb().getCertificateProfileSession().renameCertificateProfile(getAdmin(), getSelectedCertProfileName(), certProfileName);
                getEjbcaWebBean().getInformationMemory().certificateProfilesEdited();
                setCertProfileName("");
            } catch(CertificateProfileExistsException e) {
                addErrorMessage("CERTIFICATEPROFILEALREADY");
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage("Not authorized to rename certificate profile.");
            }
        }
        renameInProgress = false;
        certificateProfileItems = null;
    }

    public void actionRenameCancel() {
        renameInProgress = false;
        certificateProfileItems = null;
    }

    /*
    @Deprecated // Bridge new and old so we can migrate step by step
    private CAInterfaceBean getCaInterfaceBean() {
        final ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();
        final HttpSession httpSession = ((HttpSession)externalContext.getSession(false));
        return (CAInterfaceBean) httpSession.getAttribute("cabean");
    }
    */

    private boolean canDeleteCertProfile() {
        boolean ret = true;
        final int certificateProfileId = getSelectedCertProfileId().intValue();
        final CertificateProfile certProfile = getEjbcaWebBean().getEjb().getCertificateProfileSession().getCertificateProfile(certificateProfileId);
        final int certProfileType = certProfile.getType();
        // Count number of EEs that reference this CP
        if (certProfileType==CertificateConstants.CERTTYPE_ENDENTITY) {
            final long numberOfEndEntitiesReferencingCP = getEjbcaWebBean().getEjb().
                    getEndEntityManagementSession().countEndEntitiesUsingCertificateProfile(certificateProfileId);
            if (numberOfEndEntitiesReferencingCP>1000) {
                ret = false;
                addErrorMessage("CERTPROFILEUSEDINENDENTITIES");
                addErrorMessage("CERTPROFILEUSEDINENDENTITIESEXCESSIVE");
            } else if (numberOfEndEntitiesReferencingCP>0) {
                ret = false;
                addErrorMessage("CERTPROFILEUSEDINENDENTITIES");
                final List<String> eeNames = getEjbcaWebBean().getEjb().
                        getEndEntityManagementSession().findByCertificateProfileId(certificateProfileId);
                addNonTranslatedErrorMessage(getEjbcaWebBean().getText("DISPLAYINGFIRSTTENRESULTS") + numberOfEndEntitiesReferencingCP +
                        " " + getAsCommaSeparatedString(eeNames));
            }
        }
        // Check if certificate profile is in use by any service
        final List<String> servicesReferencingCP = getEjbcaWebBean().getEjb().
                getServiceSession().getServicesUsingCertificateProfile(certificateProfileId);
        if (!servicesReferencingCP.isEmpty()) {
            ret = false;
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("CERTPROFILEUSEDINSERVICES") + 
                    " " + getAsCommaSeparatedString(servicesReferencingCP));
        }
        // Check if certificate profile is in use by any end entity profile
        if (certProfileType==CertificateConstants.CERTTYPE_ENDENTITY || certProfileType==CertificateConstants.CERTTYPE_SUBCA) {
            final List<String> endEntityProfilesReferencingCP = getEjbcaWebBean().getEjb().
                    getEndEntityProfileSession().getEndEntityProfilesUsingCertificateProfile(certificateProfileId);
            if (!endEntityProfilesReferencingCP.isEmpty()) {
                ret = false;
                addNonTranslatedErrorMessage(getEjbcaWebBean().getText("CERTPROFILEUSEDINENDENTITYPROFILES") + 
                        " " + getAsCommaSeparatedString(endEntityProfilesReferencingCP));
            }
        }
        // Check if certificate profile is in use by any hard token profile
        if (certProfileType==CertificateConstants.CERTTYPE_ENDENTITY) {
            final List<String> hardTokenProfilesReferencingCP = getEjbcaWebBean().getEjb().
                    getHardTokenSession().getHardTokenProfileUsingCertificateProfile(certificateProfileId);
            if (!hardTokenProfilesReferencingCP.isEmpty()) {
                ret = false;
                addNonTranslatedErrorMessage(getEjbcaWebBean().getText("CERTPROFILEUSEDINHARDTOKENPROFILES") + 
                        " " + getAsCommaSeparatedString(hardTokenProfilesReferencingCP));
            }
        }
        if (certProfileType!=CertificateConstants.CERTTYPE_ENDENTITY) {
            // Check if certificate profile is in use by any CA
            final List<String> casReferencingCP = getEjbcaWebBean().getEjb().
                    getCaAdminSession().getCAsUsingCertificateProfile(certificateProfileId);
            if (!casReferencingCP.isEmpty()) {
                ret = false;
                addNonTranslatedErrorMessage(getEjbcaWebBean().getText("CERTPROFILEUSEDINCAS") + 
                        " " + getAsCommaSeparatedString(casReferencingCP));
            }
        }
        return ret;
    }

    private String getAsCommaSeparatedString(final List<String> list) {
        final StringBuilder sb = new StringBuilder();
        for (final String entry : list) {
            if (sb.length()>0) {
                sb.append(", ");
            }
            sb.append(entry);
        }
        return sb.toString();
    }

    public String getCertProfileName() { return certProfileName; }
    public void setCertProfileName(String certProfileName) {
        certProfileName = certProfileName.trim();
        if (checkFieldForLegalChars(certProfileName)) {
            addErrorMessage("ONLYCHARACTERS");
        } else {
            this.certProfileName = certProfileName;
        }
    }

    private boolean checkFieldForLegalChars(final String fieldValue) {
        final String blackList = "/[^\\u0041-\\u005a\\u0061-\\u007a\\u00a1-\\ud7ff\\ue000-\\uffff_ 0-9@\\.\\*\\,\\-:\\/\\?\\'\\=\\(\\)\\|.]/g";
        return Pattern.matches(blackList, fieldValue);
    }
}
