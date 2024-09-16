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
package org.ejbca.ui.web.admin.endentity;

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.annotation.PostConstruct;
import jakarta.faces.context.FacesContext;
import jakarta.faces.model.SelectItem;
import jakarta.faces.view.ViewScoped;
import jakarta.inject.Named;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.endentity.PSD2RoleOfPSPStatement;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ra.ExtendedInformationFields;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.bean.SessionBeans;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;
import org.ejbca.ui.web.admin.rainterface.UserView;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;

/**
 * JSF managed bean backing view end entity xhtml page
 */
@Named
@ViewScoped
public class ViewEndEntityMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;

    private EjbcaWebBean ejbcaWebBean;
    private CAInterfaceBean caBean;
    private RAInterfaceBean raBean;

    // Fields from legacy ViewEndEntityHelper class

    private static final String USER_PARAMETER = "username";
    private static final String TIMESTAMP_PARAMETER = "timestamp";

    private static final String BUTTON_VIEW_NEWER = "buttonviewnewer";
    private static final String BUTTON_VIEW_OLDER = "buttonviewolder";

    private static final String ACTION = "action";

    private static final int[] STATUSIDS = { EndEntityConstants.STATUS_NEW, EndEntityConstants.STATUS_FAILED, EndEntityConstants.STATUS_INITIALIZED,
            EndEntityConstants.STATUS_INPROCESS, EndEntityConstants.STATUS_GENERATED, EndEntityConstants.STATUS_REVOKED,
            EndEntityConstants.STATUS_HISTORICAL, EndEntityConstants.STATUS_KEYRECOVERY, EndEntityConstants.STATUS_WAITINGFORADDAPPROVAL };

    private static final String[] STATUSTEXTS = { "STATUSNEW", "STATUSFAILED", "STATUSINITIALIZED", "STATUSINPROCESS", "STATUSGENERATED",
            "STATUSREVOKED", "STATUSHISTORICAL", "STATUSKEYRECOVERY", "STATUSWAITINGFORADDAPPROVAL" };

    private boolean noUserParameter = true;
    private boolean notAuthorized = false;
    private boolean profileNotFound = true;

    private UserView userData = null;
    private UserView[] userDatas = null;
    private String userName = null;

    private EndEntityProfile eeProfile = null;
    
    private GlobalConfiguration globalConfiguration = null;

    private int currentUserIndex = 0;

    private String[] tokenTexts = RAInterfaceBean.tokentexts;
    private int[] tokenIds = RAInterfaceBean.tokenids;
    private String currentusername = null;
    
    private List<ImmutablePair<String, String>> subjectDnNameFieldDatas;
    private List<ImmutablePair<String, String>> subjectAltNameFieldDatas;
    private List<ImmutablePair<String, String>> subjectDirAttrsFieldDatas;

    // **************************************************************        

    // Authentication check and audit log page access request
    @PostConstruct
    public void initialize() throws EndEntityException {
        try {
            if (!getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.ROLE_ADMINISTRATOR)) {
                throw new AuthorizationDeniedException("You are not authorized to view this page.");
            }
            initData();
        } catch (Exception e) {
            throw new EndEntityException("Error while initializing the class " + this.getClass().getCanonicalName(), e);
        }
    }

    /**
     * Method that initializes the bean.
     *
     * @throws Exception 
     */
    private void initData() throws Exception {

        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();

        ejbcaWebBean = getEjbcaWebBean();
        globalConfiguration = ejbcaWebBean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR,
                AccessRulesConstants.REGULAR_VIEWENDENTITY);
        caBean = SessionBeans.getCaBean(request);
        raBean = SessionBeans.getRaBean(request);

        raBean.initialize(ejbcaWebBean);
        caBean.initialize(ejbcaWebBean);

        RequestHelper.setDefaultCharacterEncoding(request);

        parseRequest(request);
        
        checkInitParameters();
        
        initSdnFieldsData();
        initSanFieldData();
        initSdaFieldData();
    }

    private void checkInitParameters() {
        if (noUserParameter) {
            addNonTranslatedErrorMessage(ejbcaWebBean.getText("YOUMUSTSPECIFYUSERNAME"));
        } else if (userData == null) {
            addNonTranslatedErrorMessage(ejbcaWebBean.getText("ENDENTITYDOESNTEXIST"));
        } else if (notAuthorized) {
            addNonTranslatedErrorMessage(ejbcaWebBean.getText("NOTAUTHORIZEDTOVIEW"));
        } else if (profileNotFound) {
            addNonTranslatedErrorMessage(ejbcaWebBean.getText("CANNOTVIEWUSERPROFREM"));
        }
    }

    private void initSdnFieldsData() {
        subjectDnNameFieldDatas = new ArrayList<>();
        final int subjectFieldSize = eeProfile.getSubjectDNFieldOrderLength();
        for (int i = 0; i < subjectFieldSize; i++) {
            final int[] fieldData = eeProfile.getSubjectDNFieldsInOrder(i);
            final String subjectDnFieldName = ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileId(fieldData[EndEntityProfile.FIELDTYPE]));
            final String subjectDnFieldValue = userData.getSubjectDNField(DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]),
                    fieldData[EndEntityProfile.NUMBER]);
            subjectDnNameFieldDatas.add(new ImmutablePair<>(subjectDnFieldName, subjectDnFieldValue));
        }
    }
    
    private void initSanFieldData() {
        subjectAltNameFieldDatas = new ArrayList<>();

        final int subjectFieldSize = eeProfile.getSubjectAltNameFieldOrderLength();

        for (int i = 0; i < subjectFieldSize; i++) {
            final int[] fieldData = eeProfile.getSubjectAltNameFieldsInOrder(i);
            final int fieldType = fieldData[EndEntityProfile.FIELDTYPE];
            if (EndEntityProfile.isFieldImplemented(fieldType)) {
                final String subjectAltNameFieldName = ejbcaWebBean
                        .getText(DnComponents.getLanguageConstantFromProfileId(fieldData[EndEntityProfile.FIELDTYPE]));
                final String subjectAltNameFieldvalue = userData.getSubjectAltNameField(
                        DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]), fieldData[EndEntityProfile.NUMBER]);
                subjectAltNameFieldDatas.add(new ImmutablePair<>(subjectAltNameFieldName, subjectAltNameFieldvalue));
            }
        }

    }

    private void initSdaFieldData() {
        subjectDirAttrsFieldDatas = new ArrayList<>();
        final int subjectFieldSize = eeProfile.getSubjectDirAttrFieldOrderLength();

        for (int i = 0; i < subjectFieldSize; i++) {
            final int[] fieldData = eeProfile.getSubjectDirAttrFieldsInOrder(i);
            final String subjectDirAttrFieldName = ejbcaWebBean
                    .getText(DnComponents.getLanguageConstantFromProfileId(fieldData[EndEntityProfile.FIELDTYPE]));
            final String subjectDirAttrFieldvalue = userData.getSubjectDirAttributeField(
                    DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]), fieldData[EndEntityProfile.NUMBER]);
            subjectDirAttrsFieldDatas.add(new ImmutablePair<>(subjectDirAttrFieldName, subjectDirAttrFieldvalue));
        }
    }
    
    private void parseRequest(HttpServletRequest request) throws AuthorizationDeniedException, Exception {
        noUserParameter = true;
        notAuthorized = false;
        profileNotFound = true;

        RequestHelper.setDefaultCharacterEncoding(request);
        String action = request.getParameter(ACTION);
        if (action == null && request.getParameter(TIMESTAMP_PARAMETER) != null && request.getParameter(USER_PARAMETER) != null) {
            userName = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER), StandardCharsets.UTF_8);
            Date timestamp = new Date(Long.parseLong(request.getParameter(TIMESTAMP_PARAMETER)));

            notAuthorized = !populateUserDatas(userName);
            currentUserIndex = this.getTimeStampIndex(timestamp);
            if (userDatas == null || userDatas.length < 1) {
                // Make sure possibly cached value is removed
                userData = null;
                throw new ServletException("Could not find any history for this user.");
            }
            userData = userDatas[currentUserIndex];

            noUserParameter = false;
            if (userData != null) {
                eeProfile = raBean.getEndEntityProfile(userData.getEndEntityProfileId());
            }
        } else {
            if (action == null && request.getParameter(USER_PARAMETER) != null) {
                userName = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER), StandardCharsets.UTF_8);
                notAuthorized = !populateUserDatas(userName);
                noUserParameter = false;
                if ((userDatas != null) && (userDatas.length > 0)) {
                    userData = userDatas[0];
                    currentUserIndex = 0;
                    if (userData != null) {
                        eeProfile = raBean.getEndEntityProfile(userData.getEndEntityProfileId());
                    }
                } else {
                    // Make sure possibly cached value is removed
                    userData = null;
                }
            } else {
                if (action != null && request.getParameter(USER_PARAMETER) != null) {
                    userName = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER), StandardCharsets.UTF_8);
                    if (request.getParameter(BUTTON_VIEW_NEWER) != null &&  (currentUserIndex > 0)) {
                            currentUserIndex--;
                        
                    }
                    if (request.getParameter(BUTTON_VIEW_OLDER) != null &&  (currentUserIndex + 1 < userDatas.length)) {
                            currentUserIndex++;
                        
                    }

                    notAuthorized = !populateUserDatas(userName);
                    userData = userDatas[currentUserIndex];

                    noUserParameter = false;
                    if (userData != null) {
                        eeProfile = raBean.getEndEntityProfile(userData.getEndEntityProfileId());
                    }
                }
            }
        }

        if (eeProfile != null) {
            profileNotFound = false;
        } 
    }

    public String getUserName() {
        return userName;
    }
    
    public UserView getUserData() {
        return userData;
    }

    public int getCurrentUserIndex() {
        return currentUserIndex;
    }
    
    public String getUserStatus() {
        for (int i = 0; i < STATUSIDS.length; i++) {
            if (userData.getStatus() == STATUSIDS[i]) {
                return ejbcaWebBean.getText(STATUSTEXTS[i]);
            }
        }
        return StringUtils.EMPTY;
    }
    
    public String getEeCreatedTime() {
        return ejbcaWebBean.formatAsISO8601(userData.getTimeCreated());
    }
    
    public String getEeModifiedTime() {
        return ejbcaWebBean.formatAsISO8601(userData.getTimeModified()); 
    }
    
    public boolean isViewOlderEe() {
        return currentUserIndex + 1 < userDatas.length;
    }
    
    public boolean isViewNewerEe() {
        return currentUserIndex > 0;
    }
    
    public String getButtonViewOlderName() {
        return ViewEndEntityMBean.BUTTON_VIEW_OLDER;
    }
    
    public String getButtonViewNewerName() {
        return ViewEndEntityMBean.BUTTON_VIEW_NEWER;
    }
    
    public boolean isEeProfileDefined() {
        return userData.getEndEntityProfileId() != 0;
    }
    
    public String getEeProfileName() {
        if (isEeProfileDefined()) {
            return raBean.getEndEntityProfileName(userData.getEndEntityProfileId());
        } else {
            return StringUtils.EMPTY;
        }
    }
    
    public boolean isRenderUseInBatch() {
        return eeProfile.getUse(EndEntityProfile.CLEARTEXTPASSWORD, 0);
    }

    public boolean isUseCleartextPassword() {
        return userData.getClearTextPassword();
    }

    public boolean isUseEmail() {
        return eeProfile.getUse(EndEntityProfile.EMAIL, 0);
    }   
    
    public String getEeEmail() {
        if (userData.getEmail() != null) {
            return userData.getEmail();
        } else {
            return StringUtils.EMPTY;
        }
    }
    
    public boolean isRenderSubjectAltNamesSection() {
        return eeProfile.getSubjectAltNameFieldOrderLength() > 0;
    }
    
    public boolean isRenderSubjectDirAttrsSection() {
        return eeProfile.getSubjectDirAttrFieldOrderLength() > 0;
    }
    
    public List<ImmutablePair<String, String>> getSubjectDnFieldNameAndData() {
        return this.subjectDnNameFieldDatas;
    }
    
    public List<ImmutablePair<String, String>> getSubjectAltNameFieldNameAndData() {
        return this.subjectAltNameFieldDatas;
    }
    
    public List<ImmutablePair<String, String>> getSubjectDirAttrsFieldNameAndData() {
        return this.subjectDirAttrsFieldDatas;
    }
    
    public String getCertProfileName() {
        if (userData.getCertificateProfileId() != 0) {
            return raBean.getCertificateProfileName(userData.getCertificateProfileId());
        } else {
            return ejbcaWebBean.getText("NOCERTIFICATEPROFILEDEFINED");
        }
    } 
    
    public String getCaName() {
        return userData.getCAName(); 
    }
    
    public String getTokenName() {

        String tokenName = StringUtils.EMPTY;

        for (int i = 0; i < tokenTexts.length; i++) {
            if (tokenIds[i] == userData.getTokenType()) {
                if (tokenIds[i] > SecConst.TOKEN_SOFT) {
                    tokenName = tokenTexts[i];
                } else {
                    tokenName = ejbcaWebBean.getText(tokenTexts[i]);
                }
            }
        }
        return tokenName;
    }
    
    public boolean isRenderOtherCertData() {
        return eeProfile.isCustomSerialNumberUsed() || 
               eeProfile.isValidityStartTimeUsed() || 
               eeProfile.isValidityEndTimeUsed() || 
               eeProfile.isCardNumberUsed() || 
               eeProfile.isPsd2QcStatementUsed() || 
               eeProfile.isCabfOrganizationIdentifierUsed();
    }
    
    public boolean isRenderCertSerialNum() {
        final ExtendedInformation ei = userData.getExtendedInformation();
        final BigInteger oldNr = ei != null ? ei.certificateSerialNumber() : null;
        final String certSerialNr = oldNr != null ? oldNr.toString(16) : null;

        return certSerialNr != null;
    }
    
    public String getCertSerialNum() {
        final ExtendedInformation ei = userData.getExtendedInformation();
        final BigInteger oldNr = ei != null ? ei.certificateSerialNumber() : null;
        return oldNr != null ? oldNr.toString(16) : null;
    }
    
    public boolean isRenderTimeOfStart() {
        String startTime = null;
        if (eeProfile.getUse(EndEntityProfile.STARTTIME, 0)) {
            ExtendedInformation ei = userData.getExtendedInformation();
            if (ei != null) {
                startTime = ei.getCustomData(EndEntityProfile.STARTTIME);
            }
        }
        return startTime != null;
    }
    
    public String getTimeOfStart() {
        String startTime = null;
        if (eeProfile.getUse(EndEntityProfile.STARTTIME, 0)) {
            ExtendedInformation ei = userData.getExtendedInformation();
            if (ei != null) {
                startTime = ei.getCustomData(EndEntityProfile.STARTTIME);
            }
        }

        return ejbcaWebBean.getISO8601FromImpliedUTCOrRelative(startTime);
    }

    public boolean isRenderTimeOfEnd() {
        String endTime = null;
        if (eeProfile.getUse(EndEntityProfile.ENDTIME, 0)) {
            ExtendedInformation ei = userData.getExtendedInformation();
            if (ei != null) {
                endTime = ei.getCustomData(EndEntityProfile.ENDTIME);
            }
        }
        return endTime != null;
    }
    
    public String getTimeOfEnd() {
        String endTime = null;
        if (eeProfile.getUse(EndEntityProfile.ENDTIME, 0)) {
            ExtendedInformation ei = userData.getExtendedInformation();
            if (ei != null) {
                endTime = ei.getCustomData(EndEntityProfile.ENDTIME);
            }
        }

        return ejbcaWebBean.getISO8601FromImpliedUTCOrRelative(endTime);
    }
    
    public boolean isRenderCardNumber() {
        return eeProfile.getUse(EndEntityProfile.CARDNUMBER,0) && userData.getCardNumber() != null;
    }
    
    public String getCardNumber() {
        return userData.getCardNumber();
    }
    
    public boolean isRenderCertExtensionData() {
        return eeProfile.getUseExtensiondata() || !getExtensionDataAsMap().isEmpty();
    }
    
    public Map<String, String> getExtensionDataAsMap() {
        final Map<String, String> result = new HashMap<>();
        ExtendedInformation extendedInformation = userData.getExtendedInformation();
        if (extendedInformation != null) {
            @SuppressWarnings("rawtypes")
            Map data = (Map) extendedInformation.getData();
            for (Object o : data.keySet()) {
                String key = (String) o;
                if (key.startsWith(ExtendedInformation.EXTENSIONDATA)) {
                    String subKey = key.substring(ExtendedInformation.EXTENSIONDATA.length());
                    result.put(subKey, (String) data.get(key));
                }
            }
        }
        return result;
    }
    
    public boolean isRenderRawSubjectDn() {
        return userData.getExtendedInformation() != null && userData.getExtendedInformation().getRawSubjectDn() != null;
    }

    public String getRawSubjectDn() {
        return userData.getExtendedInformation().getRawSubjectDn();
    }

    public boolean isRenderPsd2NcaName() {
        return userData.getExtendedInformation() != null && userData.getExtendedInformation().getQCEtsiPSD2NCAName() != null;
    }
    
    public String getPsd2NcaName() {
        return userData.getExtendedInformation().getQCEtsiPSD2NCAName();
    }
    
    public boolean isRenderPsd2NcaId() {
        return userData.getExtendedInformation() != null && userData.getExtendedInformation().getQCEtsiPSD2NCAId() != null;
    }
    
    public String getPsd2NcaId() {
        return userData.getExtendedInformation().getQCEtsiPSD2NCAId();
    }
    
    public boolean isRenderPsd2PspRoles() {
        return userData.getExtendedInformation() != null && 
               userData.getExtendedInformation().getQCEtsiPSD2RolesOfPSP() != null &&
               userData.getExtendedInformation().getQCEtsiPSD2RolesOfPSP().size() > 0;
    }
    
    public List<SelectItem> getPsd2PspRoles(){
        
        final List<SelectItem> psdPspRoles = new ArrayList<>();

        psdPspRoles.add(new SelectItem("PSP_AS", getEjbcaWebBean().getText("PSD2_PSP_AS")));
        psdPspRoles.add(new SelectItem("PSP_PI", getEjbcaWebBean().getText("PSD2_PSP_PI")));
        psdPspRoles.add(new SelectItem("PSP_AI", getEjbcaWebBean().getText("PSD2_PSP_AI")));
        psdPspRoles.add(new SelectItem("PSP_IC", getEjbcaWebBean().getText("PSD2_PSP_IC")));

        return psdPspRoles;
        
    }
    
    public List<String> getSelectedPsd2PspRoles() {
        final List<String> selectedPsdPspRoles = new ArrayList<>();

        String[] availableRoles = { "PSP_AS", "PSP_PI", "PSP_AI", "PSP_IC" };

        for (final String role : availableRoles) {
            if (userData.getExtendedInformation().getQCEtsiPSD2RolesOfPSP() != null) {
                for (final PSD2RoleOfPSPStatement psd2role : userData.getExtendedInformation().getQCEtsiPSD2RolesOfPSP()) {
                    if (role.equals(psd2role.getName())) {
                        selectedPsdPspRoles.add(role);
                    }
                }
            }
        }
        return selectedPsdPspRoles;
    }
    
    public boolean isRenderCabfOrganizationIdentifier() {
        return userData.getExtendedInformation() != null && StringUtils.isNotEmpty(userData.getExtendedInformation().getCabfOrganizationIdentifier());
    }
    
    public String getCabfOrganizationIdentifier() {
        return userData.getExtendedInformation().getCabfOrganizationIdentifier();
    }
    
    public boolean isRenderOtherData() {
        return (eeProfile.getUse(EndEntityProfile.ALLOWEDREQUESTS, 0)
                || (eeProfile.getUse(EndEntityProfile.KEYRECOVERABLE, 0) && globalConfiguration.getEnableKeyRecovery())
                || eeProfile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0) || eeProfile.getUse(EndEntityProfile.SENDNOTIFICATION, 0)
                || eeProfile.getUsePrinting());
    }
    
    public boolean isRenderAllowedRequests() {
        return eeProfile.getUse(EndEntityProfile.ALLOWEDREQUESTS,0);
    }
    
    public String getAllowedRequests() {
        ExtendedInformation ei = userData.getExtendedInformation();
        String counter = ei != null ? ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER) : null;

        if (counter != null) {
            return counter;
        } else {
            return StringUtils.EMPTY;
        }

    }
    
    public boolean isRenderKeyRecoverable() {
        return eeProfile.getUse(EndEntityProfile.KEYRECOVERABLE,0) && globalConfiguration.getEnableKeyRecovery();
    }
    
    public String getKeyRecoverable() {
        if (userData.getKeyRecoverable()) {
            return ejbcaWebBean.getText("YES");
        } else {
            return ejbcaWebBean.getText("NO");
        }
    }
    
    public boolean isRenderIssuanceRevocationReason() {
        return eeProfile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON,0);
    }
    
    public String getIssuanceRevocationReason() {
        int revStatus = RevokedCertInfo.NOT_REVOKED;
        ExtendedInformation ei = userData.getExtendedInformation();
        if (ei != null) {
            final String revReason = ei.getCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON);
            if ((revReason != null) && ((revReason).length() > 0)) {
                revStatus = (Integer.parseInt(revReason));
            }
        }
        
        if (revStatus == RevokedCertInfo.NOT_REVOKED) {
            return ejbcaWebBean.getText("ACTIVE");
        }

        if (revStatus == RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL) {
            return ejbcaWebBean.getText("REACTIVATED_REMOVEFROMCRL");
        }

        if (revStatus == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) {
            return ejbcaWebBean.getText("SUSPENDED") + ":" + ejbcaWebBean.getText("REV_CERTIFICATEHOLD");
        }

        if (revStatus == RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED) {
            return ejbcaWebBean.getText("REVOKED") + ":" + ejbcaWebBean.getText("REV_UNSPECIFIED");
        }

        if (revStatus == RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE) {
            return ejbcaWebBean.getText("REVOKED") + ":" + ejbcaWebBean.getText("REV_KEYCOMPROMISE");
        }

        if (revStatus == RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE) {
            return ejbcaWebBean.getText("REVOKED") + ":" + ejbcaWebBean.getText("REV_CACOMPROMISE");
        }

        if (revStatus == RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED) {
            return ejbcaWebBean.getText("REVOKED") + ":" + ejbcaWebBean.getText("REV_AFFILIATIONCHANGED");
        }

        if (revStatus == RevokedCertInfo.REVOCATION_REASON_SUPERSEDED) {
            return ejbcaWebBean.getText("REVOKED") + ":" + ejbcaWebBean.getText("REV_SUPERSEDED");
        }

        if (revStatus == RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION) {
            return ejbcaWebBean.getText("REVOKED") + ":" + ejbcaWebBean.getText("REV_CESSATIONOFOPERATION");
        }

        if (revStatus == RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN) {
            return ejbcaWebBean.getText("REVOKED") + ":" + ejbcaWebBean.getText("REV_PRIVILEGEWITHDRAWN");
        }

        if (revStatus == RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE) {
            return ejbcaWebBean.getText("REVOKED") + ":" + ejbcaWebBean.getText("REV_AACOMPROMISE");
        }
        
        return StringUtils.EMPTY;

    }
    
    public boolean isRenderSendNotification() {
        return eeProfile.getUse(EndEntityProfile.SENDNOTIFICATION,0);
    }
    
    public String getSendNotification() {
        if (userData.getSendNotification()) {
            return ejbcaWebBean.getText("YES");
        } else {
            return ejbcaWebBean.getText("NO");
        }
    }    
    
    public boolean isRenderPrintUserdata() {
        return eeProfile.getUsePrinting();
    }
    
    public String getPrintUserdata() {
        if (userData.getPrintUserData()) {
            return ejbcaWebBean.getText("YES");
        } else {
            return ejbcaWebBean.getText("NO");
        }
    }   
    
    public boolean isRenderCsrSection() {
        return userData.getExtendedInformation() != null && 
                (userData.getExtendedInformation().getCertificateRequest() != null || userData.getExtendedInformation().getKeyStoreAlgorithmType() != null);
    }
    
    public boolean isRenderCsr() {
        final byte[] csr = userData.getExtendedInformation().getCertificateRequest();
        return csr != null; 
    }
    
    public String getCsr() {
        String csrPem = StringUtils.EMPTY;
        final byte[] csr = userData.getExtendedInformation().getCertificateRequest();
        if (csr != null) {
            csrPem = new String(CertTools.getPEMFromCertificateRequest(csr));
        }
        return csrPem;
    }
    
    public boolean isRenderKeyAlgType() {
        return userData.getExtendedInformation().getKeyStoreAlgorithmType() != null;
    }
    
    public String getKeyAlgType() {
        return userData.getExtendedInformation().getKeyStoreAlgorithmType();

    }
    
    public String getKeyAlgSubType() {
        return userData.getExtendedInformation().getKeyStoreAlgorithmSubType();
    }
    /* returns false if the admin isn't authorized to view user
     * Sets the available userdatas of current and previous values
     */

    private boolean populateUserDatas(String username) throws Exception {
        boolean authorized = false;

        try {
            if (currentusername == null || !currentusername.equals(username)) {
                // fetch userdata and certreqdatas and order them by timestamp, newest first.
                int currentexists = 0;
                UserView currentuser = raBean.findUser(username);
                if (currentuser != null) {
                    currentexists = 1;
                }
                List<CertReqHistory> hist = caBean.getCertReqUserDatas(username);

                userDatas = new UserView[hist.size() + currentexists];

                if (currentuser != null) {
                    userDatas[0] = currentuser;
                }
                for (int i = 0; i < hist.size(); i++) {
                    CertReqHistory next = hist.get(i);
                    userDatas[i + currentexists] = new UserView(next.getEndEntityInformation(), ejbcaWebBean.getCAIdToNameMap());
                }

            }
            authorized = true;
        } catch (AuthorizationDeniedException e) {
        }
        return authorized;
    }

    /**
     * Returns an Index to the user that related to a certain timestamp.
     * 
     * @param timestamp parameter sent from view log page
     * @return index in user datas that should be shown.
     */
    private int getTimeStampIndex(Date timestamp) {
        int i;

        for (i = 0; i < userDatas.length; i++) {
            if (timestamp.after(userDatas[i].getTimeModified()) || timestamp.equals(userDatas[i].getTimeModified())) {
                break;
            }
        }

        return i;
    }

}
