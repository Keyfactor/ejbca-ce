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

import java.io.IOException;
import java.io.Serializable;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.standard.CabForumOrganizationIdentifier;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.certificate.certextensions.standard.QcStatement;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.ssh.SshEndEntityProfileFields;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.endentity.PSD2RoleOfPSPStatement;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.util.SshCertificateUtils;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
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
 */
@ManagedBean
@ViewScoped
public class RaEndEntityBean implements Serializable {
    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(RaEndEntityBean.class);
    private static final String MISSING_PERMITTED_NAME_CONSTRAINTS = "enroll_name_constraint_permitted_required";
    private static final String MISSING_EXCLUDED_NAME_CONSTRAINTS = "enroll_name_constraint_excluded_required";
    private static final String MISSING_CABF_ORGANIZATION_IDENTIFIER = "editendentity_cabf_organizationidentifier_required";
    private static final String INVALID_PERMITTED_NAME_CONSTRAINTS = "enroll_invalid_permitted_name_constraints";
    private static final String INVALID_EXCLUDED_NAME_CONSTRAINTS = "enroll_invalid_excluded_name_constraints";

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value="#{raAccessBean}")
    private RaAccessBean raAccessBean;
    public void setRaAccessBean(final RaAccessBean raAccessBean) { this.raAccessBean = raAccessBean; }

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    @ManagedProperty(value="#{msg}")
    private ResourceBundle msg;
    public void setMsg(ResourceBundle msg) {
        this.msg = msg;
    }

    private IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles = new IdNameHashMap<>();
    private IdNameHashMap<CertificateProfile> authorizedCertificateProfiles = new IdNameHashMap<>();
    private IdNameHashMap<CAInfo> authorizedCAInfos = new IdNameHashMap<>();

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
    private boolean autogeneratedPasswordChecked = false;
    private boolean clearCsrChecked = false;
    private boolean authorized = false;
    private int maxFailedLogins;
    private int remainingLogin;
    private boolean resetRemainingLoginAttempts;
    private String[] email;
    private int eepId;
    private int cpId;
    private int caId;
    private SubjectDn subjectDistinguishNames = null;
    private SubjectAlternativeName subjectAlternativeNames = null;
    private SubjectDirectoryAttributes subjectDirectoryAttributes = null;
    private String extensionData;
    private Map<Integer, String> endEntityProfiles;
    private boolean deleted = false;
    private List<String> nameConstraintsPermitted;
    private List<String> nameConstraintsExcluded;
    private int nameConstraintsPermittedUpdateStatus = 0;
    private int nameConstraintsExcludedUpdateStatus = 0;
    private String nameConstraintsPermittedString;
    private String nameConstraintsExcludedString;
    private boolean keyRecoverable;
    private boolean viewEndEntityMode = false;
    private Boolean sendNotification;
    private String psd2NcaName;
    private String psd2NcaId;
    private List<String> selectedPsd2PspRoles;
    private String cabfOrganizationIdentifier;

    // SSH fields
    private String sshKeyId;
    private String sshComment;
    List<EndEntityProfile.FieldInstance> sshPrincipals;
    private String sshCriticalOptionsForceCommand;
    private String sshCriticalOptionsSourceAddress;

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
        if (!raAccessBean.isAuthorizedToSearchEndEntities()) {
            log.debug("Not authorized to view end entities");
            return;
        }
        authorized = true;
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
        if (username != null) {
            final EndEntityInformation endEntityInformation = raMasterApiProxyBean.searchUser(raAuthenticationBean.getAuthenticationToken(), username);
            if (endEntityInformation != null) {
                cpIdToNameMap = raMasterApiProxyBean.getAuthorizedCertificateProfileIdsToNameMap(raAuthenticationBean.getAuthenticationToken());
                eepIdToNameMap = raMasterApiProxyBean.getAuthorizedEndEntityProfileIdsToNameMap(raAuthenticationBean.getAuthenticationToken());
                final List<CAInfo> caInfos = new ArrayList<>(raMasterApiProxyBean.getAuthorizedCas(raAuthenticationBean.getAuthenticationToken()));
                for (final CAInfo caInfo : caInfos) {
                    caIdToNameMap.put(caInfo.getCAId(), caInfo.getName());
                }
                raEndEntityDetails = new RaEndEntityDetails(endEntityInformation, raEndEntityDetailsCallbacks, cpIdToNameMap, eepIdToNameMap, caIdToNameMap);
                selectedTokenType = endEntityInformation.getTokenType();

                authorizedEndEntityProfiles = raMasterApiProxyBean.getAuthorizedEndEntityProfiles(raAuthenticationBean.getAuthenticationToken(), AccessRulesConstants.CREATE_END_ENTITY);
                authorizedCertificateProfiles = raMasterApiProxyBean.getAllAuthorizedCertificateProfiles(raAuthenticationBean.getAuthenticationToken());
                authorizedCAInfos = raMasterApiProxyBean.getAuthorizedCAInfos(raAuthenticationBean.getAuthenticationToken());
                endEntityProfiles = authorizedEndEntityProfiles.getIdMap()
                    .entrySet()
                    .stream()
                    .collect(Collectors.toMap(entry -> entry.getKey(), entry -> entry.getValue().getName()));

                eepId = raEndEntityDetails.getEndEntityInformation().getEndEntityProfileId();
                cpId = raEndEntityDetails.getEndEntityInformation().getCertificateProfileId();
                caId = raEndEntityDetails.getEndEntityInformation().getCAId();
                extensionData = raEndEntityDetails.getExtensionData(endEntityInformation.getExtendedInformation());
                keyRecoverable = raEndEntityDetails.getEndEntityInformation().getKeyRecoverable();
                resetMaxFailedLogins();
                email = raEndEntityDetails.getEmail() == null ? null : raEndEntityDetails.getEmail().split("@");
                if (email == null || email.length == 1)
                    email = new String[] {"", ""};
                sendNotification = endEntityInformation.getSendNotification();
                psd2NcaName = raEndEntityDetails.getPsd2NcaName();
                psd2NcaId = raEndEntityDetails.getPsd2NcaId();
                selectedPsd2PspRoles = raEndEntityDetails.getSelectedPsd2PspRoles();
                cabfOrganizationIdentifier = raEndEntityDetails.getCabfOrganizationIdentifier();
                if (endEntityInformation.isSshEndEntity()) {
                    sshKeyId = raEndEntityDetails.getSshKeyId();
                    sshComment = raEndEntityDetails.getSshComment();
                    sshCriticalOptionsForceCommand = raEndEntityDetails.getSshForceCommand();
                    sshCriticalOptionsSourceAddress = raEndEntityDetails.getSshSourceAddress();
                }
            }
        }
        issuedCerts = null;
        selectableStatuses = null;
        selectableTokenTypes = null;
        selectedStatus = -1;
        clearCsrChecked = false;
        resetRemainingLoginAttempts = false;
    }
    
    public boolean isAuthorized() {
        return authorized;
    }

    /**
     * @return the new username (can be same to old one)
     */
    public String getUsername() { return username; }

    /**
     * Sets the username to a new username
     *
     * @param username the new username
     */
    public void setUsername(String username) {
        this.username = username;
    }

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
        if (editEditEndEntityMode) {
            viewEndEntityMode=false;
        }
        reload();
    }

    /**
     * Cancels edit mode and reloads
     */
    public void editEditEndEntityCancel() {
        subjectDistinguishNames = null;
        subjectAlternativeNames = null;
        sshPrincipals = null;
        subjectDirectoryAttributes = null;

        editEditEndEntityMode = false;
        viewEndEntityMode = true;
        reload();
    }

    public boolean isViewEndEntityMode() {
        return viewEndEntityMode;
    }

    /**
     * Edits the current End Entity, cancels edit mode and reloads
     */
    public void editEditEndEntitySave() {
        boolean changed = false;
        int selectedStatus = getSelectedStatus();
        int selectedTokenType = getSelectedTokenType();
        EndEntityProfile eep = authorizedEndEntityProfiles.get(eepId).getValue();
        EndEntityInformation endEntityInformation = new EndEntityInformation(raEndEntityDetails.getEndEntityInformation());
        ExtendedInformation extendedInformation = endEntityInformation.getExtendedInformation();

        if (selectedStatus > 0 && selectedStatus != endEntityInformation.getStatus()) {
            // A new status was selected. When status changed to generated, no enrollment code is needed.
            if (endEntityInformation.getStatus() == EndEntityConstants.STATUS_NEW) {
                // Change the End Entity's status and set the new password without validation
                endEntityInformation.setStatus(selectedStatus);
                endEntityInformation.setPassword(enrollmentCode);
                endEntityInformation.setTokenType(getNewTokenTypeValue(selectedTokenType, endEntityInformation));
                changed = true;
            }else if (selectedStatus == EndEntityConstants.STATUS_NEW && isPasswordAutogenerated() && isAutogeneratedPasswordChecked()){
                endEntityInformation.setStatus(selectedStatus); 
                endEntityInformation.setPassword(eep.makeAutoGeneratedPassword()); 
                endEntityInformation.setTokenType(getNewTokenTypeValue(selectedTokenType, endEntityInformation)); 
                changed = true;     
                //verify the enrollment codes for status changes other than generated
            } else if (verifyEnrollmentCodes()) {
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
        String newUsername = null;
        if (!username.equals(endEntityInformation.getUsername())) {
            newUsername = username;
            changed = true;
        }

        if (eep.isEmailUsed()) {
            for (EndEntityProfile.FieldInstance instance: getSubjectDistinguishNames().getFieldInstances()) {
                if (isDnEmail(instance)) {
                    if (instance.isUseDataFromEmailField()) {
                        instance.setValue(email[0]+"@"+email[1]);
                    } else {
                        instance.setValue(instance.getDefaultValue());
                    }
                }
            }
        }
        String subjectDn = getSubjectDistinguishNames().getValue();
        if(!subjectDn.equals(endEntityInformation.getDN())) {
            endEntityInformation.setDN(subjectDn);
            changed = true;
        }
        if (subjectAlternativeNames == null) {
            if (StringUtils.isNotBlank(endEntityInformation.getSubjectAltName())) {
                endEntityInformation.setSubjectAltName(null);
                changed = true;
            }
        } else {
            String subjectAn = subjectAlternativeNames.getValue();
            if (!subjectAn.equals(endEntityInformation.getSubjectAltName())) {
                endEntityInformation.setSubjectAltName(subjectAn);
                changed = true;
            }
        }
        if (subjectDirectoryAttributes == null) {
            if (extendedInformation != null) {
                if (StringUtils.isNotBlank(extendedInformation.getSubjectDirectoryAttributes())) {
                    endEntityInformation.getExtendedInformation().setSubjectDirectoryAttributes(null);
                    changed = true;
                }
            }
        } else {
            String subjectDa = subjectDirectoryAttributes.getValue();
            if (extendedInformation == null) {
                if (StringUtils.isNotBlank(subjectDa)) {
                    endEntityInformation.setExtendedInformation(new ExtendedInformation());
                    endEntityInformation.getExtendedInformation().setSubjectDirectoryAttributes(subjectDa);
                    changed = true;
                }
            } else if (!subjectDa.equals(endEntityInformation.getExtendedInformation().getSubjectDirectoryAttributes())) {
                endEntityInformation.getExtendedInformation().setSubjectDirectoryAttributes(subjectDa);
                changed = true;
            }
        }

        if (extendedInformation != null && extensionData != null) {
            editExtensionData(extendedInformation);
            changed = true;
        }
        if (extendedInformation != null && maxFailedLogins != extendedInformation.getMaxLoginAttempts()) {
            endEntityInformation.getExtendedInformation().setMaxLoginAttempts(maxFailedLogins);
            changed = true;
        }
        if (extendedInformation != null && resetRemainingLoginAttempts) {
            endEntityInformation.getExtendedInformation().setRemainingLoginAttempts(maxFailedLogins);
            changed = true;
        }
        if (eep.isEmailUsed()) {
            final String newEmail = email[0]+"@"+email[1];
            if (!newEmail.equals(endEntityInformation.getEmail())) {
                if (newEmail.equals("@")) {
                    if (StringUtils.isNotBlank(endEntityInformation.getEmail())) {
                        endEntityInformation.setEmail(null);
                        changed = true;
                    }
                } else {
                    endEntityInformation.setEmail(newEmail);
                    changed = true;
                }
            }
        } else {
            endEntityInformation.setEmail(null);
        }

        if (eep.isSendNotificationUsed() && !sendNotification.equals(endEntityInformation.getSendNotification())) {
            if (verifyEmailForNotifications(endEntityInformation.getEmail())) {
                endEntityInformation.setSendNotification(sendNotification);
                changed = true;
            } else {
                return;
            }
        }
        if (eepId != endEntityInformation.getEndEntityProfileId()) {
            endEntityInformation.setEndEntityProfileId(eepId);
            changed = true;
        }
        if (cpId != endEntityInformation.getCertificateProfileId()) {
            endEntityInformation.setCertificateProfileId(cpId);
            changed = true;
        }
        if (caId != endEntityInformation.getCAId()) {
            endEntityInformation.setCAId(caId);
            changed = true;
        }
        if(nameConstraintsPermittedUpdateStatus==1) {
            endEntityInformation.getExtendedInformation().setNameConstraintsPermitted(nameConstraintsPermitted);
            changed = true;
        } else if(nameConstraintsPermittedUpdateStatus<0) {
            return;
        }
        if(nameConstraintsExcludedUpdateStatus==1) {
            endEntityInformation.getExtendedInformation().setNameConstraintsExcluded(nameConstraintsExcluded);
            changed = true;
        } else if(nameConstraintsExcludedUpdateStatus<0) {
            return;
        }
        if (keyRecoverable != endEntityInformation.getKeyRecoverable()) {
            endEntityInformation.setKeyRecoverable(keyRecoverable);
            changed = true;
        }
        if (eep.isPsd2QcStatementUsed()){
            if (endEntityInformation.getExtendedInformation() == null){
                endEntityInformation.setExtendedInformation(new ExtendedInformation());
            }
            if (!StringUtils.equals(psd2NcaName, endEntityInformation.getExtendedInformation().getQCEtsiPSD2NCAName())) {
                endEntityInformation.getExtendedInformation().setQCEtsiPSD2NcaName(StringUtils.trimToNull(psd2NcaName));
                changed = true;
            }
            if (!StringUtils.equals(psd2NcaId, endEntityInformation.getExtendedInformation().getQCEtsiPSD2NCAId())) {
                endEntityInformation.getExtendedInformation().setQCEtsiPSD2NcaId(StringUtils.trimToNull(psd2NcaId));
                changed = true;
            }
            if (psd2PspRoleSelectionChanged()) {
                final List<PSD2RoleOfPSPStatement> psd2RoleOfPSPStatements = new ArrayList<>();
                for (String role : selectedPsd2PspRoles) {
                    psd2RoleOfPSPStatements.add(new PSD2RoleOfPSPStatement(QcStatement.getPsd2Oid(role), role));
                }
                endEntityInformation.getExtendedInformation().setQCEtsiPSD2RolesOfPSP(psd2RoleOfPSPStatements);
                changed = true;
            }
        }
        if (eep.isCabfOrganizationIdentifierUsed()){
            if (!verifyCabfOrganizationIdentifier()) {
                return;
            }
            if (endEntityInformation.getExtendedInformation() == null){
                endEntityInformation.setExtendedInformation(new ExtendedInformation());
            }
            if (!StringUtils.equals(cabfOrganizationIdentifier, endEntityInformation.getExtendedInformation().getCabfOrganizationIdentifier())){
                endEntityInformation.getExtendedInformation().setCabfOrganizationIdentifier(StringUtils.trimToNull(cabfOrganizationIdentifier));
                changed = true;
            }
        }

        boolean isClearPwd = false;
        if (eep.getUse(EndEntityProfile.CLEARTEXTPASSWORD, 0)) {
            if (eep.isRequired(EndEntityProfile.CLEARTEXTPASSWORD, 0) || StringUtils.isNotEmpty(endEntityInformation.getPassword())) {
                isClearPwd = true;
            }
        }

        if (endEntityInformation.isSshEndEntity()) {
            if (sshKeyId != raEndEntityDetails.getSshKeyId()) {
                changed = true;
                endEntityInformation.setDN("CN=" + sshKeyId);
            }
            if (sshComment != raEndEntityDetails.getSshComment()
                    || raEndEntityDetails.getSshPrincipals() != sshPrincipalFieldsToString(getSshPrincipals())) {
                changed = true;
                endEntityInformation.setSubjectAltName(
                        SshCertificateUtils.createSanForStorage(sshPrincipalFieldsToString(getSshPrincipals()), sshComment));
            }
            if (sshCriticalOptionsForceCommand != raEndEntityDetails.getSshForceCommand()
                    || sshCriticalOptionsSourceAddress != raEndEntityDetails.getSshSourceAddress()) {
                changed = true;
                final Map<String, String> criticalOptions = endEntityInformation.getExtendedInformation().getSshCriticalOptions();
                criticalOptions.put(SshEndEntityProfileFields.SSH_CRITICAL_OPTION_FORCE_COMMAND_CERT_PROP, sshCriticalOptionsForceCommand);
                criticalOptions.put(SshEndEntityProfileFields.SSH_CRITICAL_OPTION_SOURCE_ADDRESS_CERT_PROP, sshCriticalOptionsSourceAddress);
                endEntityInformation.getExtendedInformation().setSshCriticalOptions(criticalOptions);
            }
        }

        if (changed) {
            // Edit the End Entity if changes were made
            try {
                boolean result = raMasterApiProxyBean.editUser(raAuthenticationBean.getAuthenticationToken(), endEntityInformation, isClearPwd, newUsername);
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
            } catch (EndEntityProfileValidationException e) {
                raLocaleBean.addMessageError("editendentity_validation_failed");
            } catch (CADoesntExistsException e) {
                raLocaleBean.addMessageError("editendentity_no_such_ca");
            } catch (CertificateSerialNumberException | IllegalNameException
                    | NoSuchEndEntityException
                    | CustomFieldException e) {
                raLocaleBean.addMessageError("editendentity_failure");
            }
        }
        editEditEndEntityCancel();
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private void editExtensionData(ExtendedInformation extendedInformation) {
        Properties properties = new Properties();
        try {
            properties.load(new StringReader(extensionData));
        } catch (IOException ex) {
            // Should not happen as we are only reading from a String.
            throw new RuntimeException(ex);
        }

        // Remove old extensiondata
        Map data = (Map) extendedInformation.getData();
        // We have to use an iterator in order to remove an item while iterating, if we try to remove an object from
        // the map while looping over keys we will get a ConcurrentModificationException
        Iterator it = data.keySet().iterator();
        while (it.hasNext()) {
            Object o = it.next();
            if (o instanceof String) {
                String key = (String) o;
                if (key.startsWith(ExtendedInformation.EXTENSIONDATA)) {
                    //it.remove() will delete the item from the map
                    it.remove();
                }
            }
        }

        // Add new extensiondata
        for (Object o : properties.keySet()) {
            if (o instanceof String) {
                String key = (String) o;
                data.put(ExtendedInformation.EXTENSIONDATA + key, properties.getProperty(key));
            }
        }

        // Updated ExtendedInformation to use the new data
        extendedInformation.loadData(data);
    }

    /**
     * Cancels edit mode and reloads
     */
    public void revokeCertificatesAndDeleteEndEntity() {
        try {
            raMasterApiProxyBean.revokeAndDeleteUser(
                raAuthenticationBean.getAuthenticationToken(),
                raEndEntityDetails.getEndEntityInformation().getUsername(),
                RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED
            );
            raLocaleBean.addMessageInfo("editendentity_deleted");
        } catch (AuthorizationDeniedException e) {
            raLocaleBean.addMessageError("editendentity_unauthorized");
        } catch (NoSuchEndEntityException e) {
            raLocaleBean.addMessageError("editendentity_no_such_ee");
        } catch (WaitingForApprovalException e) {
            raLocaleBean.addMessageError("editendentity_approval_sent");
        } catch (CouldNotRemoveEndEntityException e) {
            raLocaleBean.addMessageError("editendentity_reference_issue");
        } catch (ApprovalException e) {
            raLocaleBean.addMessageError("editendentity_approval_issue");
        }
        deleted = true;
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
        if (isPasswordAutogenerated() && !autogeneratedPasswordChecked){
            raLocaleBean.addMessageError("editendentity_autogenerate_not_checked");
            return false;
        }
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
     * @return true if enrollment code and confirm enrollment code are valid
     */
    private boolean verifyEmailForNotifications(String email) {
        if (sendNotification && StringUtils.isBlank(email)) {
            raLocaleBean.addMessageError("editendentity_email_required");
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
     * @param enrollmentCodeConfirm the new enrollment code (confirm)
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
     * Checks if checkbox Regenerate autogenerated password is checked 
     * 
     */
    public boolean isAutogeneratedPasswordChecked() {
        return autogeneratedPasswordChecked;
    }

    public void setAutogeneratedPasswordChecked(boolean autogeneratedPasswordChecked){
        this.autogeneratedPasswordChecked = autogeneratedPasswordChecked;
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
                    new SelectItem(EndEntityConstants.TOKEN_SOFT_BCFKS,
                            raLocaleBean.getMessage("component_eedetails_tokentype_bcfks")),
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

    /**
     * @return blank String ("") if username is unchanged or unique, otherwise return a message saying already exists
     */
    public String getUsernameWarning() {
        if (!username.equals(raEndEntityDetails.getUsername())
            && StringUtils.isNotBlank(username)
            && raMasterApiProxyBean.searchUser(raAuthenticationBean.getAuthenticationToken(), username) != null) {
            return msg.getString("enroll_already_exists");
        } else
            return "";
    }

    /**
     * @return maximum number of failed login attempts allowed
     */
    public int getMaxFailedLogins() {
        return maxFailedLogins;
    }

    /**
     * @return true if modifiable, otherwise false
     */
    public boolean isMaxFailedLoginsModifiable() {
        EndEntityProfile eep = authorizedEndEntityProfiles.get(eepId).getValue();
        return eep.isMaxFailedLoginsModifiable();
    }

    private void resetMaxFailedLogins() {
        if (eepId == raEndEntityDetails.getEndEntityInformation().getEndEntityProfileId()) {
            if (raEndEntityDetails.getEndEntityInformation().getExtendedInformation() == null) {
                maxFailedLogins = -1;
                remainingLogin = -1;
            } else {
                maxFailedLogins = raEndEntityDetails.getEndEntityInformation().getExtendedInformation().getMaxLoginAttempts();
                remainingLogin = raEndEntityDetails.getEndEntityInformation().getExtendedInformation().getRemainingLoginAttempts();
            }
        } else {
            EndEntityProfile eep = authorizedEndEntityProfiles.get(eepId).getValue();
            maxFailedLogins = eep.getMaxFailedLogins();
            remainingLogin = -1;
        }

    }

    public void setMaxFailedLogins(int maxFailedLogins) {
        this.maxFailedLogins = maxFailedLogins;
    }

    /**
     * @return true if unlimited number of failed login attempts allowed, otherwise false
     */
    public boolean isUnlimited() {
        return maxFailedLogins < 0;
    }

    /**
     * Sets the maximum number of failed login attempts to -1 if unlimited is true
     * Sets the maximum number of failed login attempts to 10 if unlimited is false
     *
     * @param unlimited the new value of unlimited
     */
    public void setUnlimited(boolean unlimited) {
        if (unlimited) {
            maxFailedLogins = -1;
        } else {
            maxFailedLogins = 10; // hard coded default
        }
    }

    /**
     * @return remaining number of failed login attempts
     */
    public int getRemainingLogin() {
        return remainingLogin;
    }

    /**
     * Sets the remaining number of failed login attempts
     *
     * @param remainingLogin the new remaining number of login attempts
     */
    public void setRemainingLogin(int remainingLogin) {
        this.remainingLogin = remainingLogin;
    }

    /**
     * @return true if reset is checked, otherwise false
     */
    public boolean isResetRemainingLoginAttempts() {
        return resetRemainingLoginAttempts;
    }

    /**
     * Sets the flag to reset remaining number of login attempts
     *
     * @param resetRemainingLoginAttempts the new value of the
     */
    public void setResetRemainingLoginAttempts(boolean resetRemainingLoginAttempts) {
        this.resetRemainingLoginAttempts = resetRemainingLoginAttempts;
    }

    /**
     * @return the name part of the email
     */
    public String getEmailName() {
        return email[0];
    }

    /**
     * Sets the name part of the email
     *
     * @param emailName the name part of the email
     */
    public void setEmailName(String emailName) {
        email[0] = emailName;
    }

    /**
     * @return the domain part of the email
     */
    public String getEmailDomain() {
        return email[1];
    }

    /**
     * Sets the name part of the email
     *
     * @param emailDomain the name part of the email
     */
    public void setEmailDomain(String emailDomain) {
        email[1] = emailDomain;
    }

    /**
     * @return true if email is modifiable, otherwise false
     */
    public boolean isEmailModifiable() {
        EndEntityProfile eep = authorizedEndEntityProfiles.get(eepId).getValue();
        return eep.isEmailModifiable();
    }

    /**
     * @return true if use email is checked in end entity profile, otherwise false
     */
    public boolean isEmailUsed() {
        EndEntityProfile eep = authorizedEndEntityProfiles.get(eepId).getValue();
        return eep.isEmailUsed();
    }

    /**
     * @return a map with end entity profile id as key and end entity profile name as value (for end entity profile select options)
     */
    public Map<Integer, String> getEndEntityProfiles() {
        return endEntityProfiles;
    }

    /**
     * @return selected end entity profile id
     */
    public int getEepId() {
        return eepId;
    }

    /**
     * Sets the selected end entity profile id
     *
     * @param eepId the new end entity profile id
     */
    public void setEepId(int eepId) {
        if (this.eepId != eepId) {
            this.eepId = eepId;
            EndEntityProfile eep = authorizedEndEntityProfiles.get(eepId).getValue();
            if (eep.getAvailableCertificateProfileIds().contains(cpId)) {
                setCpId(cpId);
            } else {
                setCpId(eep.getDefaultCertificateProfile());
            }

            resetMaxFailedLogins();
            subjectDistinguishNames = null;
            subjectAlternativeNames = null;
            subjectDirectoryAttributes = null;
            sshPrincipals = null;


            if (raEndEntityDetails.getEndEntityInformation().getEndEntityProfileId() == eepId) {
                email = raEndEntityDetails.getEmail() == null ? null : raEndEntityDetails.getEmail().split("@");
                if (email == null || email.length == 1)
                    email = new String[] {"", ""};
            } else {
                String defaultEmail = eep.getEmailDomain();
                if (eep.isEmailUsed()) {
                    email = new String[] {"", defaultEmail};
                } else
                    email = new String[] {"", ""};
            }
        }
    }

    /**
     * @return selected certificate profile id
     */
    public int getCpId() {
        return cpId;
    }

    /**
     * Sets the selected certificate profile id
     *
     * @param cpId the new certificate profile id
     */
    public void setCpId(int cpId) {
        this.cpId = cpId;
        int defaultCA = authorizedEndEntityProfiles.get(eepId).getValue().getDefaultCA();
        Map<Integer, String> cAs = getCertificateAuthorities();
        if (cAs.size() == 0) {
            caId = 0;
        } else {
            caId = cAs.keySet().contains(defaultCA) ? defaultCA : cAs.keySet().iterator().next();
        }
    }

    /**
     * @return a map with certificate profile id as key and certificate profile name as value (for certificate profile select options)
     */
    public Map<Integer, String> getCertificateProfiles() {
        List<Integer> availableCpIds = authorizedEndEntityProfiles.get(eepId).getValue().getAvailableCertificateProfileIds();
        return availableCpIds.stream()
                .collect(Collectors.toMap(cpId -> cpId, cpId -> authorizedCertificateProfiles.getIdMap().get(cpId).getName()));
    }

    /**
     * @return selected certificate authority id
     */
    public int getCaId() {
        return caId;
    }

    /**
     * Sets the selected certificate authority id
     *
     * @param caId the new certificate authority id
     */
    public void setCaId(int caId) {
        this.caId = caId;
    }

    /**
     * @return a map with certificate authority id as key and certificate authority name as value (for certificate authority select options)
     */
    public Map<Integer, String> getCertificateAuthorities() {
        List<Integer> eepCAs = authorizedEndEntityProfiles.get(eepId).getValue().getAvailableCAs();
        CertificateProfile cp = authorizedCertificateProfiles.get(cpId).getValue();
        List<Integer> cpCAs = authorizedCertificateProfiles.get(cpId).getValue().getAvailableCAs();
        
        Stream<Integer> usableCAs;
        if (eepCAs.contains(EndEntityConstants.EEP_ANY_CA)) {
            if (cp.isApplicableToAnyCA()) {
                usableCAs = authorizedCAInfos.idKeySet().stream();
            } else {
                usableCAs = filterAuthorizedCas(cpCAs);
            }
        } else {
            if (cp.isApplicableToAnyCA()) {
                usableCAs = filterAuthorizedCas(eepCAs);
            } else {
                usableCAs = eepCAs.stream()
                    .filter(cpCAs::contains).filter(authorizedCAInfos.idKeySet()::contains);
            }
        }

        // delayed collection to reduce instantiation of Collections
        return usableCAs.collect(
                Collectors.toMap(caId -> caId, caId -> authorizedCAInfos.get(caId).getValue().getName()));
        
    }

    private Stream<Integer> filterAuthorizedCas(final List<Integer> availableCAs) {
        return availableCAs.stream().filter(authorizedCAInfos.idKeySet()::contains);
    }

    private void handleNullSubjectDistinguishNames() {
        if (subjectDistinguishNames == null) {
            EndEntityProfile eep = authorizedEndEntityProfiles.getIdMap().get(eepId).getValue();
            subjectDistinguishNames = new SubjectDn(eep, raEndEntityDetails.getSubjectDn());

            String eeEmail = raEndEntityDetails.getEmail();
            for (EndEntityProfile.FieldInstance instance: subjectDistinguishNames.getFieldInstances()) {
                if (isDnEmail(instance)
                    && StringUtils.isNotBlank(eeEmail)
                    && instance.getValue().equals(eeEmail)) {
                    instance.setUseDataFromEmailField(true);
                }
            }
        }
    }

    /**
     * @return subject distinguish names currently typed in edit mode
     */
    public SubjectDn getSubjectDistinguishNames() {
        handleNullSubjectDistinguishNames();
        return subjectDistinguishNames;
    }

    /**
     * Sets the subject distinguish names
     *
     * @param subjectDistinguishNames the new subject distinguish names
     */
    public void setSubjectDistinguishNames(SubjectDn subjectDistinguishNames) {
        this.subjectDistinguishNames = subjectDistinguishNames;
    }

    /**
     * Retrieves and populates EndEntityProfile.FieldInstances for SSH principals (if not already set).
     */
    public void handleNullSshPrincipals() {
        if (sshPrincipals == null) {
            final String[] sshPrincipalValues = raEndEntityDetails.getSshPrincipals().split(":");
            EndEntityProfile eep = authorizedEndEntityProfiles.getIdMap().get(eepId).getValue();
            sshPrincipals = new ArrayList<>();
            final List<EndEntityProfile.FieldInstance> fieldInstances = eep.new Field(SshEndEntityProfileFields.SSH_PRINCIPAL).getInstances();
            for (int i = 0; i < fieldInstances.size(); i++) {
                if (i < sshPrincipalValues.length) {
                    fieldInstances.get(i).setValue(sshPrincipalValues[i]);
                }
                sshPrincipals.add(fieldInstances.get(i));
            }
        }
    }

    public List<EndEntityProfile.FieldInstance> getSshPrincipals() {
        handleNullSshPrincipals();
        return sshPrincipals;
    }

    public void setSshPrincipals(final List<EndEntityProfile.FieldInstance> newSshPrincipals) {
        sshPrincipals = newSshPrincipals;
    }

    private void handleNullSubjectAlternativeNames() {
        if (subjectAlternativeNames == null) {
            EndEntityProfile eep = authorizedEndEntityProfiles.getIdMap().get(eepId).getValue();
            String subjectAn = raEndEntityDetails.getSubjectAn();
            if (eep.getSubjectAltNameFieldOrderLength() > 0) {
                if (StringUtils.isBlank(subjectAn)) {
                    subjectAlternativeNames = new SubjectAlternativeName(eep);
                } else {
                    subjectAlternativeNames = new SubjectAlternativeName(eep, subjectAn);
                }
            }
        }
    }

    /**
     * @return subject alternative names currently typed in edit mode
     */
    public SubjectAlternativeName getSubjectAlternativeNames() {
        handleNullSubjectAlternativeNames();
        return subjectAlternativeNames;
    }

    /**
     * Sets the subject alternative names
     *
     * @param subjectAlternativeNames the new subject alternative names
     */
    public void setSubjectAlternativeNames(SubjectAlternativeName subjectAlternativeNames) {
        this.subjectAlternativeNames = subjectAlternativeNames;
    }

    /**
     * @return true if subjectAlternativeNames has at least 1 fieldInstance, otherwise false
     */
    public boolean getAnySubjectAlternativeName() {
        EndEntityProfile eep = authorizedEndEntityProfiles.getIdMap().get(eepId).getValue();
        return eep.getSubjectAltNameFieldOrderLength() > 0;
    }

    private void handleNullSubjectDirectoryAttributes() {
        if (subjectDirectoryAttributes == null) {
            EndEntityProfile eep = authorizedEndEntityProfiles.getIdMap().get(eepId).getValue();
            String subjectDa = raEndEntityDetails.getSubjectDa();
            if (eep.getSubjectDirAttrFieldOrderLength() > 0) {
                if (StringUtils.isBlank(subjectDa)) {
                    subjectDirectoryAttributes = new SubjectDirectoryAttributes(eep);
                } else {
                    subjectDirectoryAttributes = new SubjectDirectoryAttributes(eep, subjectDa);
                }
            }
        }
    }

    /**
     * @return subject directory attributes currently typed in edit mode
     */
    public SubjectDirectoryAttributes getSubjectDirectoryAttributes() {
        handleNullSubjectDirectoryAttributes();
        return subjectDirectoryAttributes;
    }

    /**
     * Sets the subject directory attributes
     *
     * @param subjectDirectoryAttributes the new subject directory attributes
     */
    public void setSubjectDirectoryAttributes(SubjectDirectoryAttributes subjectDirectoryAttributes) {
        this.subjectDirectoryAttributes = subjectDirectoryAttributes;
    }

    /**
     * @return true if subjectDirectoryAttributes has at least 1 fieldInstance, otherwise false
     */
    public boolean getAnySubjectDirectoryAttribute() {
        EndEntityProfile eep = authorizedEndEntityProfiles.getIdMap().get(eepId).getValue();
        return eep.getSubjectDirAttrFieldOrderLength() > 0;
    }
    
    /**
     * @return extensionData currently typed in edit mode
     */
    public String getExtensionData() {
        return extensionData;
    }
    
    /**
     * Set extensionData
     * @param extensionData the String value of extensionData
     */
    public void setExtensionData(String extensionData) {
        this.extensionData = extensionData;
    }
    
    /**
     * @return true if keyRecoverable
     */
    public boolean getKeyRecoverable() {
        return keyRecoverable;
    }
    
    /**
     * Set keyRecoverable
     * @param keyRecoverable the boolean value of keyRecoverable
     */
    public void setKeyRecoverable(boolean keyRecoverable) {
        this.keyRecoverable = keyRecoverable;
    }

    /**
     * @return true if attempted to delete end entity in edit mode, otherwise false
     */
    public boolean isDeleted() {
        return deleted;
    }

    /**
     *
     * @return true if password in EndEntityProfile is marked as autogenerated
     */
    public boolean isPasswordAutogenerated(){
        EndEntityProfile endEntityProfile = authorizedEndEntityProfiles.getIdMap().get(eepId).getValue();
        return endEntityProfile.useAutoGeneratedPasswd();
    }

    /**
     *
     * @return SubjectDn email address field name
     */
    public String getDnEmailFieldName() {
        return DnComponents.DNEMAILADDRESS;
    }    

    public String getNameConstraintsPermitted() {
        if(nameConstraintsPermitted==null) {
            nameConstraintsPermittedString = raEndEntityDetails.getNameConstraintsPermitted();
        }
        return nameConstraintsPermittedString;
    }
    
    public boolean isNameConstraintsPermittedRequired() {
        return raEndEntityDetailsCallbacks.getEndEntityProfile(eepId).isNameConstraintsPermittedRequired();
    }
    
    /**
     * Validates and sets permitted name constraints. Additionally, it check if end entity profile mandates
     * permitted name constraints and shows appropriate error messages.
     * 
     * @param nameConstraintPermitted
     */
    public void setNameConstraintsPermitted(String nameConstraintPermitted) {
        if(isNameConstraintsPermittedRequired() && nameConstraintPermitted.trim().isEmpty()) {
            raLocaleBean.addMessageError(MISSING_PERMITTED_NAME_CONSTRAINTS);
            nameConstraintsPermittedUpdateStatus = -1;
            return;
        }
        nameConstraintsPermittedString = nameConstraintPermitted;
        try {
            nameConstraintsPermitted = NameConstraint.parseNameConstraintsList(nameConstraintPermitted);
            nameConstraintsPermittedUpdateStatus = 1;
        } catch(CertificateExtensionException e) {
            raLocaleBean.addMessageError(INVALID_PERMITTED_NAME_CONSTRAINTS, e.getMessage().split(":")[1]);
            nameConstraintsPermittedUpdateStatus = -1;
        }
    }
    
    public String getNameConstraintsExcluded() {
        if(nameConstraintsExcluded==null) {
            nameConstraintsExcludedString = raEndEntityDetails.getNameConstraintsExcluded();
        }
        return nameConstraintsExcludedString;
    }
    
    public boolean isNameConstraintsExcludedRequired() {
        return raEndEntityDetailsCallbacks.getEndEntityProfile(eepId).isNameConstraintsExcludedRequired();
    }
    
    /**
     * Validates and sets excluded name constraints. Additionally, it check if end entity profile mandates
     * permitted name constraints and shows appropriate error messages.
     * 
     * @param nameConstraintExcluded
     */
    public void setNameConstraintsExcluded(String nameConstraintExcluded) {
        if(isNameConstraintsExcludedRequired() && nameConstraintExcluded.trim().isEmpty()) {
            nameConstraintsExcludedUpdateStatus = -1;
            raLocaleBean.addMessageError(MISSING_EXCLUDED_NAME_CONSTRAINTS);
            return;
        }
        nameConstraintsExcludedString = nameConstraintExcluded;
        try {
            nameConstraintsExcluded = NameConstraint.parseNameConstraintsList(nameConstraintExcluded);
            nameConstraintsExcludedUpdateStatus = 1;
        } catch(CertificateExtensionException e) {
            raLocaleBean.addMessageError(INVALID_EXCLUDED_NAME_CONSTRAINTS, e.getMessage().split(":")[1]);
            nameConstraintsExcludedUpdateStatus = -1;
        }
    }

    public Boolean getSendNotification() {
        return sendNotification;
    }

    public void setSendNotification(Boolean sendNotification) {
        this.sendNotification = sendNotification;
    }

    /**
     * @return the National Competent Authority (NCA) Name of PSD2 Qualified Certificate Statement
     */
    public String getPsd2NcaName() {
        return psd2NcaName;
    }

    /**
     * Set the National Competent Authority (NCA) Name of PSD2 Qualified Certificate Statement
     */
    public void setPsd2NcaName(String psd2NcaName) {
        this.psd2NcaName = StringUtils.trim(psd2NcaName);
    }

    /**
     * @return the National Competent Authority (NCA) Identifier of PSD2 Qualified Certificate Statement
     */
    public String getPsd2NcaId() {
        return psd2NcaId;
    }

    /**
     * Set the National Competent Authority (NCA) Identifier of PSD2 Qualified Certificate Statement
     */
    public void setPsd2NcaId(String psd2NcaId) {
        this.psd2NcaId = StringUtils.trim(psd2NcaId);
    }

    /**
     * @return selected roles of PSD2 third party Payment Service Providers (PSPs)
     */
    public List<String> getSelectedPsd2PspRoles() {
        return selectedPsd2PspRoles == null ? new ArrayList<>() : selectedPsd2PspRoles;
    }

    /**
     * Set selected roles of PSD2 third party Payment Service Providers (PSPs)
     */
    public void setSelectedPsd2PspRoles(List<String> roles) {
        selectedPsd2PspRoles = new ArrayList<>(roles);
    }

    /**
     * @return true if PSD2 PSP role selection differs from roles saved in End Entity
     */
    private boolean psd2PspRoleSelectionChanged(){
        final List<String> oldRoles = raEndEntityDetails.getSelectedPsd2PspRoles();
        final List<String> roleDiff = new ArrayList<>(oldRoles);
        roleDiff.removeAll(getSelectedPsd2PspRoles());
        if (oldRoles.size() != getSelectedPsd2PspRoles().size() || !roleDiff.isEmpty()){
            return true;
        }
        return false;
    }

    /**
     * @return the CA/B Forum Organization Identifier
     */
    public String getCabfOrganizationIdentifier() {
        return cabfOrganizationIdentifier;
    }

    /**
     * Set CA/B Forum Organization Identifier
     */
    public void setCabfOrganizationIdentifier(final String cabfOrganizationIdentifier) {
        this.cabfOrganizationIdentifier = StringUtils.trim(cabfOrganizationIdentifier);
    }

    /**
     * @return true if CA/B Forum Organization Identifier in required in the selected End Entity profile
     */
    public boolean isCabfOrganizationIdentifierRequired() {
        return raEndEntityDetailsCallbacks.getEndEntityProfile(eepId).isCabfOrganizationIdentifierRequired();
    }

    /**
     * @return true if CA/B Forum Organization Identifier field can be modified in the selected End Entity profile
     */
    public boolean isCabfOrganizationIdentifierModifiable() {
        return raEndEntityDetailsCallbacks.getEndEntityProfile(eepId).isCabfOrganizationIdentifierModifiable();
    }

    /**
     * @return validation regex for the CA/B Forum Organization Identifier field
     */
    public String getCabfOrganizationIdentifierRegex() {
        return CabForumOrganizationIdentifier.VALIDATION_REGEX;
    }

    public String getSshKeyId() {
        return sshKeyId;
    }

    public void setSshKeyId(final String newSshKeyId) {
        sshKeyId = newSshKeyId;
    }

    public String getSshComment() {
        return sshComment;
    }

    public void setSshComment(final String newSshComment) {
        sshComment = newSshComment;
    }

    public String getSshForceCommand() {
        return sshCriticalOptionsForceCommand;
    }

    public void setSshForceCommand(final String newForceCommand) {
        sshCriticalOptionsForceCommand = newForceCommand;
    }

    public boolean isSshForceCommandRequired() {
        return raEndEntityDetails.isSshForceCommandRequired();
    }

    public boolean isSshForceCommandModifiable() {
        return raEndEntityDetails.isSshForceCommandModifiable();
    }

    public String getSshSourceAddress() {
        return sshCriticalOptionsSourceAddress;
    }

    public void setSshSourceAddress(final String newSourceAddress) {
        sshCriticalOptionsSourceAddress = newSourceAddress;
    }

    public boolean isSshSourceAddressRequired() {
        return raEndEntityDetails.isSshSourceAddressRequired();
    }

    public boolean isSshSourceAddressModifiable() {
        return raEndEntityDetails.isSshSourceAddressModifiable();
    }

    /**
     * Converts principals FieldInstance list to principals String for db storage.
     * @param sshPrincipals list of EndEntityProfile.FieldInstance for principals
     * @return String of SSH principals separated by colon (:)
     */
    private static String sshPrincipalFieldsToString(List<EndEntityProfile.FieldInstance> sshPrincipals) {
        String[] sshPrincipalValues = sshPrincipals.stream().map(e -> e.getValue()).toArray(String[]::new);
        return StringUtils.join(sshPrincipalValues, ":");
    }

    /**
     * @return true if required CA/B Forum Organization Identifier is not empty, otherwise set an error message and return false
     */
    private boolean verifyCabfOrganizationIdentifier(){
        if (isCabfOrganizationIdentifierRequired() && StringUtils.isEmpty(cabfOrganizationIdentifier)){
            raLocaleBean.addMessageError(MISSING_CABF_ORGANIZATION_IDENTIFIER);
            return false;
        }
        return true;
    }

    private boolean isDnEmail(EndEntityProfile.FieldInstance instance) {
        return instance.getName().equals(DnComponents.DNEMAILADDRESS);
    }

    public String backToSearch () {
        return "search_ees.xhtml";
    }
}
