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
package org.ejbca.ra;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.KeyToValueHolder;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ra.RaEndEntityDetails.Callbacks;

/**
 * Backing bean for end entity details view.
 *  
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaEndEntityBean implements Serializable {

    private static final long serialVersionUID = 1L;

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSessionBean;

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    private String username = null;
    private RaEndEntityDetails raEndEntityDetails = null;
    private Map<Integer, String> eepIdToNameMap = null;
    private Map<Integer, String> cpIdToNameMap = null;
    private Map<Integer,String> caIdToNameMap = new HashMap<>();
    private boolean editEditEndEntityMode = false;
    private List<RaCertificateDetails> issuedCerts = null;
    private SelectItem[] selectableStatuses = null;
    private SelectItem[] selectableTokenTypes = null;
    private int selectedStatus = -1;
    private int selectedTokenType = -1;
    private String enrollmentCode = "";
    private String enrollmentCodeConfirm = "";
    private boolean clearCsrChecked = false;
    
    
    private final Callbacks raEndEntityDetailsCallbacks = new RaEndEntityDetails.Callbacks() {
        @Override
        public RaLocaleBean getRaLocaleBean() {
            return raLocaleBean;
        }

        @Override
        public EndEntityProfile getEndEntityProfile(int eepId) {
            IdNameHashMap<EndEntityProfile> map = raMasterApiProxyBean.getAuthorizedEndEntityProfiles(raAuthenticationBean.getAuthenticationToken(), AccessRulesConstants.VIEW_END_ENTITY);
            KeyToValueHolder<EndEntityProfile> tuple = map.get(eepId);
            return tuple==null ? null : tuple.getValue();
        }
    };

    @PostConstruct
    public void postConstruct() {
        username = ((HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest()).getParameter("ee");
        // Check if edit mode is set as a parameter
        String editParameter = ((HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest()).getParameter("edit");
        if (editParameter != null && editParameter.equals("true")) {
            editEditEndEntity();
        } else {
            reload();
        }
    }

    private void reload() {
        if (username!=null) {
            final EndEntityInformation endEntityInformation = raMasterApiProxyBean.searchUser(raAuthenticationBean.getAuthenticationToken(), username);
            if (endEntityInformation!=null) {
                cpIdToNameMap = raMasterApiProxyBean.getAuthorizedCertificateProfileIdsToNameMap(raAuthenticationBean.getAuthenticationToken());
                eepIdToNameMap = raMasterApiProxyBean.getAuthorizedEndEntityProfileIdsToNameMap(raAuthenticationBean.getAuthenticationToken());
                final List<CAInfo> caInfos = new ArrayList<>(raMasterApiProxyBean.getAuthorizedCas(raAuthenticationBean.getAuthenticationToken()));
                for (final CAInfo caInfo : caInfos) {
                    caIdToNameMap.put(caInfo.getCAId(), caInfo.getName());
                }
                raEndEntityDetails = new RaEndEntityDetails(endEntityInformation, raEndEntityDetailsCallbacks, cpIdToNameMap, eepIdToNameMap, caIdToNameMap);
                selectedTokenType = endEntityInformation.getTokenType();
            }
        }
        issuedCerts = null;
        selectableStatuses = null;
        selectableTokenTypes = null;
        selectedStatus = -1;
        clearCsrChecked = false;
    }

    public String getUsername() { return username; }
    public RaEndEntityDetails getEndEntity() { return raEndEntityDetails; }

    /**
     * @return true if edit mode is enabled
     */
    public boolean isEditEditEndEntityMode() {
        return editEditEndEntityMode;
    }

    /**
     * Enables edit mode (given that the API version allows it) and reloads
     */
    public void editEditEndEntity() {
        editEditEndEntityMode = isApiEditCompatible();
        reload();
    }

    /**
     * Cancels edit mode and reloads
     */
    public void editEditEndEntityCancel() {
        editEditEndEntityMode = false;
        reload();
    }

    /**
     * Edits the current End Entity, cancels edit mode and reloads
     */
    public void editEditEndEntitySave() {
        boolean changed = false;
        int selectedStatus = getSelectedStatus();
        int selectedTokenType = getSelectedTokenType();
        EndEntityInformation endEntityInformation = new EndEntityInformation(
                raEndEntityDetails.getEndEntityInformation());
        if (selectedStatus > 0 && selectedStatus != endEntityInformation.getStatus()) {
            // A new status was selected, verify the enrollment codes
            if (verifyEnrollmentCodes()) {
                // Change the End Entity's status and set the new password
                endEntityInformation.setStatus(selectedStatus);
                endEntityInformation.setPassword(enrollmentCode);
                endEntityInformation.setTokenType(getNewTokenTypeValue(selectedTokenType, endEntityInformation));
                changed = true;
            }
        } else if (!StringUtils.isEmpty(enrollmentCode)
                || !StringUtils.isEmpty(enrollmentCodeConfirm)) {
            // Not a new status, but the enrollment codes were not empty
            if (verifyEnrollmentCodes()) {
                // Enrollment codes were valid, set new password but leave status unchanged
                endEntityInformation.setPassword(enrollmentCode);
                endEntityInformation.setTokenType(getNewTokenTypeValue(selectedTokenType, endEntityInformation));
                changed = true;
            }
        } else {
            int newTokenType = getNewTokenTypeValue(selectedTokenType, endEntityInformation);
            if (newTokenType != endEntityInformation.getTokenType()) {
                endEntityInformation.setTokenType(newTokenType);
                changed = true;
            }
        }
        if (clearCsrChecked) {
            if (endEntityInformation.getExtendedInformation() != null) {
                endEntityInformation.getExtendedInformation().setCertificateRequest(null);
            }            
            changed = true;
        }
        if (changed) {
            // Edit the End Entity if changes were made
            try {
                boolean result = raMasterApiProxyBean.editUser(raAuthenticationBean.getAuthenticationToken(), endEntityInformation, false);
                if (result) {
                    raLocaleBean.addMessageError("editendentity_success");
                } else {
                    raLocaleBean.addMessageError("editendentity_failure");
                }
            } catch (WaitingForApprovalException e) {
                raLocaleBean.addMessageError("editendentity_approval_sent");
            } catch (ApprovalException e) {
                raLocaleBean.addMessageError("editendentity_approval_exists");
            } catch (AuthorizationDeniedException e) {
                raLocaleBean.addMessageError("editendentity_unauthorized");
            } catch (EndEntityProfileValidationException
                    | CADoesntExistsException
                    | CertificateSerialNumberException
                    | IllegalNameException
                    | NoSuchEndEntityException
                    | CustomFieldException e) {
                raLocaleBean.addMessageError("editendentity_failure");
            }
        }
        editEditEndEntityCancel();
    }

    /**
     * @return the new tokenType value to be saved/used
     */
    private int getNewTokenTypeValue(final int selectedTokenType, final EndEntityInformation endEntityInformation) {
        if (selectedTokenType == -1) {
            return endEntityInformation.getTokenType();
        }
        return selectedTokenType;
    }

    /**
     * @return true if enrollment code and confirm enrollment code are valid
     */
    private boolean verifyEnrollmentCodes() {
        if (blankEnrollmentCodes()) {
            raLocaleBean.addMessageError("editendentity_password_blank");
            return false;
        }
        if (!enrollmentCode.equals(enrollmentCodeConfirm)) {
            raLocaleBean.addMessageError("editendentity_password_nomatch");
            return false;
        }
        return true;
    }

    /**
     * @return true if enrollment code or confirm enrollment code is blank
     */
    private boolean blankEnrollmentCodes() {
        return StringUtils.isBlank(enrollmentCode) || StringUtils.isBlank(enrollmentCodeConfirm);
    }

    /**
     * @return the status currently selected in edit mode
     */
    public int getSelectedStatus() {
        if (selectedStatus == -1) {
            getSelectableStatuses();
        }
        return selectedStatus;
    }

    /**
     * Sets the selected status to a new status
     * 
     * @param selectedStatus the new status
     */
    public void setSelectedStatus(int selectedStatus) {
        this.selectedStatus = selectedStatus;
    }
    
    /**
     * @return the tokenType currently selected in edit mode
     */
    public int getSelectedTokenType() {
        if (selectedTokenType == -1) {
            getSelectableTokenTypes();
        }
        return selectedTokenType;
    }

    /**
     * Sets the selected tokenType to a new tokenType
     * 
     * @param selectedTokenType the new tokenType
     */
    public void setSelectedTokenType(int selectedTokenType) {
        this.selectedTokenType = selectedTokenType;
    }

    /**
     * Sets the enrollment code field
     * 
     * @param enrollmentCode the new enrollment code
     */
    public void setEnrollmentCode(String enrollmentCode) {
        this.enrollmentCode = enrollmentCode;
    }

    /**
     * @return the enrollment code
     */
    public String getEnrollmentCode() {
        return enrollmentCode;
    }

    /**
     * Sets the enrollment code (confirm) field
     * 
     * @param enrollmentCode the new enrollment code (confirm)
     */
    public void setEnrollmentCodeConfirm(String enrollmentCodeConfirm) {
        this.enrollmentCodeConfirm = enrollmentCodeConfirm;
    }

    /**
     * @return the enrollment code (confirm)
     */
    public String getEnrollmentCodeConfirm() {
        return enrollmentCodeConfirm;
    }

    /**
     * Generates an array of selectable statuses if not already cached and sets
     * the current selected status to "Unchanged"
     * 
     * @return an array of selectable statuses
     */
    public SelectItem[] getSelectableStatuses() {
        if (editEditEndEntityMode && selectableStatuses == null) {
            selectableStatuses = new SelectItem[] {
                    new SelectItem(0,
                            raLocaleBean.getMessage("component_eedetails_status_unchanged")),
                    new SelectItem(EndEntityConstants.STATUS_NEW,
                            raLocaleBean.getMessage("component_eedetails_status_new")),
                    new SelectItem(EndEntityConstants.STATUS_GENERATED,
                            raLocaleBean.getMessage("component_eedetails_status_generated"))
            };
            selectedStatus = (int)selectableStatuses[0].getValue();
        }
        return selectableStatuses;
    }
    
    /**
     * Generates an array of selectable tokenTypes if not already cached
     * 
     * @return an array of selectable tokenTypes
     */
    public SelectItem[] getSelectableTokenTypes() {
        if (editEditEndEntityMode && selectableTokenTypes == null) {
            selectableTokenTypes = new SelectItem[] {
                    new SelectItem(EndEntityConstants.TOKEN_USERGEN,
                            raLocaleBean.getMessage("component_eedetails_tokentype_usergen")),
                    new SelectItem(EndEntityConstants.TOKEN_SOFT_JKS,
                            raLocaleBean.getMessage("component_eedetails_tokentype_jks")),
                    new SelectItem(EndEntityConstants.TOKEN_SOFT_P12,
                            raLocaleBean.getMessage("component_eedetails_tokentype_pkcs12")),
                    new SelectItem(EndEntityConstants.TOKEN_SOFT_PEM,
                            raLocaleBean.getMessage("component_eedetails_tokentype_pem"))
            };
            selectedTokenType = (int)selectableTokenTypes[0].getValue();
        }
        return selectableTokenTypes;
    }

    /**
     * @return a list of the End Entity's certificates
     */
    public List<RaCertificateDetails> getIssuedCerts() {
        if (issuedCerts == null) {
            issuedCerts = RaEndEntityTools.searchCertsByUsernameSorted(
                    raMasterApiProxyBean, raAuthenticationBean.getAuthenticationToken(),
                    username, raLocaleBean);
        }
        return issuedCerts;
    }

    /**
     * @return true if the API is compatible with End Entity editing 
     */
    public boolean isApiEditCompatible() {
        return raMasterApiProxyBean.getApiVersion() >= 2;
    }
    
    /**
     * @return whether the Clear CSR checkbox is checked
     */
    public boolean getClearCsrChecked() {
        return clearCsrChecked;
    }
    
    /**
     * Sets the CSR to be cleared after the save button is pressed
     * 
     * @param checked Whether the checkbox is checked
     */
    public void setClearCsrChecked(boolean checked) {
        this.clearCsrChecked = checked;
    }
}
