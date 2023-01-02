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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;

import javax.ejb.EJB;
import javax.faces.component.UIComponent;
import javax.faces.component.UIInput;
import javax.faces.context.FacesContext;
import javax.faces.event.ComponentSystemEvent;
import javax.faces.model.SelectItem;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.RaCertificateDataOnRenew;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaSelfRenewCertificateData;

import com.keyfactor.util.crypto.algorithm.AlgorithmConfigurationCache;


/**
 * Backing bean for the Renew Certificate page
 *
 */
@Named
@ViewScoped
public class RaRenewBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaRenewBean.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @Inject
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @Inject
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    private boolean initialized = false;
    private boolean continuePressed = false;
    private boolean notificationConfigured = false;
    private String currentSubjectDn;
    private String currentIssuerDn;
    private BigInteger currentSerialNumber;
    private String currentExpirationDate;
    private String caName;
    private String endEntityProfileName;
    private String certificateProfileName;
    private String username;
    private String newSubjectDn;
    private boolean subjectDnChanged;
    private byte[] newToken;
    private Integer newApprovalRequestId;
    private boolean certGenerationDone;
    private String enrollmentCode;
    private String confirmPassword;
    private String selectedAlgorithm;
    private boolean keyAlgorithmPreSet;
    private List<String> availableKeyAlgorithms;
    private List<Integer> availableBitLengths;
    private List<String> availableEcCurves;
    private UIComponent confirmPasswordComponent;

    public void initialize() {
        if (initialized) {
            return;
        }
        initialized = true;
        final AuthenticationToken admin = raAuthenticationBean.getAuthenticationToken();
        if (log.isDebugEnabled()) {
            log.debug("Checking certificate details for '" + admin + "'");
        }
        if(admin instanceof PublicAccessAuthenticationToken || admin instanceof X509CertificateAuthenticationToken) {
            final X509Certificate x509Cert = raAuthenticationBean.getX509CertificateFromRequest();
            if (x509Cert!=null) {
                currentSubjectDn = CertTools.getSubjectDN(x509Cert);
                final Date notAfter = CertTools.getNotAfter(x509Cert);
                if (notAfter != null) {
                    currentExpirationDate = ValidityDate.formatAsISO8601ServerTZ(notAfter.getTime(), TimeZone.getDefault());
                } else {
                    log.warn("Existing admin certificate has no expiration date.");
                }
                currentIssuerDn = CertTools.getIssuerDN(x509Cert);
                currentSerialNumber = CertTools.getSerialNumber(x509Cert);
            }
        }
    }

    public String getCurrentSubjectDn() { return currentSubjectDn; }
    public String getCurrentIssuerDn() { return currentIssuerDn; }
    public String getCurrentSerialNumber() { return currentSerialNumber != null ? currentSerialNumber.toString(16) : ""; }
    public String getCurrentExpirationDate() { return currentExpirationDate; }
    public boolean isKeyAlgorithmPreSet() { return keyAlgorithmPreSet; }

    public boolean isContinueButtonShown() {
        return currentSerialNumber != null && !continuePressed;
    }

    /** Called when the Continue button is pressed */
    public void checkAndShowDetails() {
        log.debug("Performing dry run of admin client certificate renewal.");
        if (renewCertificate(true)) {
            subjectDnChanged = !newSubjectDn.equals(currentSubjectDn);
            continuePressed = true;
        }
    }

    public boolean isNewDetailsShown() {
        return continuePressed;
    }

    public String getCaName() { return caName; }
    public String getEndEntityProfileName() { return endEntityProfileName; }
    public String getCertificateProfileName() { return certificateProfileName; }
    public String getUsername() { return username; }
    public String getNewSubjectDn() { return newSubjectDn; }
    public boolean isSubjectDnChanged() { return subjectDnChanged; }
    public String getEnrollmentCode() { return enrollmentCode; }
    public void setEnrollmentCode(String enrollmentCode) { this.enrollmentCode = enrollmentCode; }
    public String getConfirmPassword() { return confirmPassword; }
    public void setConfirmPassword(String confirmPassword) { this.confirmPassword = confirmPassword; }
    public boolean isNotificationConfigured() { return notificationConfigured; }
    public String getSelectedAlgorithm() { return selectedAlgorithm; }
    public void setSelectedAlgorithm(String selectedAlgorithm) { this.selectedAlgorithm = selectedAlgorithm; }
    public UIComponent getConfirmPasswordComponent() { return confirmPasswordComponent; }
    public void setConfirmPasswordComponent(UIComponent confirmPasswordComponent) { this.confirmPasswordComponent = confirmPasswordComponent; }

    public boolean isRequestRenewalButtonShown() {
        return continuePressed;
    }
    public String renewCertificate() {
        final String tokenContentType = "application/x-pkcs12";
        final String tokenFileExtension = ".p12"; 
        if (certGenerationDone || renewCertificate(false)) {
            certGenerationDone = true; // Don't generate certificate twice, if the user retries the download (or double clicks the button)
            if (newToken != null) {
                log.debug("Admin client certificate renewal was successful. Sending token file to browser.");
                String name = CertTools.getPartFromDN(newSubjectDn, "CN");
                if (name == null){
                    name = "certificate";
                }
                try {
                    DownloadHelper.sendFile(newToken, tokenContentType, name + tokenFileExtension);
                } catch (IOException e) {
                    log.info("Token " + name + " could not be downloaded", e);
                    raLocaleBean.addMessageError("enroll_token_could_not_be_downloaded", name);
                }
            } else {
                log.debug("Admin client certificate renewal was requested, and is waiting for approval.");
            }
        }
        return "";
    }

    public Integer getNewApprovalRequestId() { return newApprovalRequestId; }

    public boolean renewCertificate(boolean dryRun) {
        log.debug("Performing admin client certificate renewal.");

        RaCertificateDataOnRenew certificateDataForRenew = raMasterApiProxyBean.getCertificateDataForRenew(currentSerialNumber, currentIssuerDn);

        if (certificateDataForRenew != null) {
            username = certificateDataForRenew.getUsername();
            if (certificateDataForRenew.isRevoked()) {
                raLocaleBean.addMessageInfo("renewcertificate_page_certificate_revoked_message", currentSerialNumber, currentIssuerDn);
                return true;
            }
            caName = certificateDataForRenew.getCaName();
            endEntityProfileName = certificateDataForRenew.getEndEntityProfileName();
            certificateProfileName = certificateDataForRenew.getCertificateProfileName();
            notificationConfigured = certificateDataForRenew.isNotificationConfigured();
            keyAlgorithmPreSet = certificateDataForRenew.isKeyAlgorithmPreSet();
            if (!keyAlgorithmPreSet) {
                availableKeyAlgorithms = certificateDataForRenew.getAvailableKeyAlgorithms();
                availableBitLengths = certificateDataForRenew.getAvailableBitLengths();
                availableEcCurves = certificateDataForRenew.getAvailableEcCurves();
            }
            if (StringUtils.isEmpty(newSubjectDn)) {
                newSubjectDn = currentSubjectDn;
            }
        } else {
            raLocaleBean.addMessageInfo("renewcertificate_page_no_user_message");
            return false;
        }

        if (!dryRun) {
            RaSelfRenewCertificateData renewCertificateData = new RaSelfRenewCertificateData();
            renewCertificateData.setUsername(username);
            if (!isNotificationConfigured()) {
                renewCertificateData.setPassword(getEnrollmentCode());
            }
            renewCertificateData.setClientIPAddress(raAuthenticationBean.getUserRemoteAddr());
            if (!keyAlgorithmPreSet) {
                if (!setKeyAlgorithm(renewCertificateData)) {
                    return false;
                }
            }
            try {
                byte[] keystoreAsByteArray  = raMasterApiProxyBean.selfRenewCertificate(renewCertificateData);
                try(ByteArrayOutputStream buffer = new ByteArrayOutputStream()){
                    buffer.write(keystoreAsByteArray);
                    newToken = buffer.toByteArray();
                }
            }  catch (ApprovalException e) {
                raLocaleBean.addMessageInfo("renewcertificate_page_certificate_waiting_for_approval_message");
            } catch (WaitingForApprovalException e) {
                newApprovalRequestId = e.getRequestId();
            } catch (Exception e) {
                log.error("Failed to renew certificate for user " + username + " with serial number " + currentSerialNumber
                + " and issuer " + currentIssuerDn, e);
                raLocaleBean.addMessageError("renewcertificate_page_certificate_renew_error");
            }
        }
        return true;
    }

    private boolean setKeyAlgorithm(RaSelfRenewCertificateData renewCertificateData) {
        if (StringUtils.isEmpty(selectedAlgorithm)) {
            raLocaleBean.addMessageError("enroll_no_key_algorithm");
            log.info("No key algorithm was provided.");
            return false;
        }
        final String[] parts = StringUtils.split(selectedAlgorithm, '_');
        if (parts == null || parts.length < 1) {
            raLocaleBean.addMessageError("enroll_no_key_algorithm");
            log.info("No full key algorithm was provided: "+selectedAlgorithm);
            return false;
        }
        final String keyAlg = parts[0];
        if (StringUtils.isEmpty(keyAlg)) {
            raLocaleBean.addMessageError("enroll_no_key_algorithm");
            log.info("No key algorithm was provided: "+selectedAlgorithm);
            return false;
        }
        final String keySpec;
        if (parts.length > 1) { // It's ok for some algs (EdDSA) to have no keySpec
            keySpec = parts[1];
            if (StringUtils.isEmpty(keySpec)) {
                raLocaleBean.addMessageError("enroll_no_key_specification");
                log.info("No key specification was provided: "+selectedAlgorithm);
                return false;
            }
        } else {
            keySpec = null;
        }
        renewCertificateData.setKeyAlg(keyAlg);
        renewCertificateData.setKeySpec(keySpec);
        return true;
    }

    public List<SelectItem> getAvailableAlgorithmSelectItems() {
        final List<SelectItem> availableAlgorithmSelectItems = new ArrayList<>();
         if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_DSA)) {
                for (final int availableBitLength : availableBitLengths) {
                    if (availableBitLength == 1024) {
                        availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_DSA + "_" + availableBitLength,
                                AlgorithmConstants.KEYALGORITHM_DSA + " " + availableBitLength + " bits"));
                    }
                }
            }
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_RSA)) {
                for (final int availableBitLength : availableBitLengths) {
                    if (availableBitLength >= 1024) {
                        availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_RSA + "_" + availableBitLength,
                                AlgorithmConstants.KEYALGORITHM_RSA + " " + availableBitLength + " bits"));
                    }
                }
            }
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ED25519)) {
                availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_ED25519,
                        AlgorithmConstants.KEYALGORITHM_ED25519));
            }
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ED448)) {
                availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_ED448,
                        AlgorithmConstants.KEYALGORITHM_ED448));
            }
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ECDSA)) {
                final Set<String> ecChoices = new HashSet<>();
                if (availableEcCurves.contains(CertificateProfile.ANY_EC_CURVE)) {
                    for (final String ecNamedCurve : AlgorithmTools.getNamedEcCurvesMap(false).keySet()) {
                        if (CertificateProfile.ANY_EC_CURVE.equals(ecNamedCurve)) {
                            continue;
                        }
                        final int bitLength = AlgorithmTools.getNamedEcCurveBitLength(ecNamedCurve);
                        if (availableBitLengths.contains(bitLength)) {
                            ecChoices.add(ecNamedCurve);
                        }
                    }
                }
                ecChoices.addAll(availableEcCurves);
                ecChoices.remove(CertificateProfile.ANY_EC_CURVE);
                final List<String> ecChoicesList = new ArrayList<>(ecChoices);
                Collections.sort(ecChoicesList);
                for (final String ecNamedCurve : ecChoicesList) {
                    if (!AlgorithmTools.isKnownAlias(ecNamedCurve)) {
                        log.warn("Ignoring unknown curve " + ecNamedCurve + " from being displayed in the RA web.");
                        continue;
                    }
                    availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_ECDSA + "_" + ecNamedCurve, AlgorithmConstants.KEYALGORITHM_ECDSA + " "
                            + StringTools.getAsStringWithSeparator(" / ", AlgorithmTools.getAllCurveAliasesFromAlias(ecNamedCurve))));
                }
            }
            for (final String algName : AlgorithmConfigurationCache.INSTANCE.getConfigurationDefinedAlgorithms()) {
                if (availableKeyAlgorithms.contains(AlgorithmConfigurationCache.INSTANCE.getConfigurationDefinedAlgorithmTitle(algName))) {
                    for (final String subAlg : CesecoreConfiguration.getExtraAlgSubAlgs(algName)) {
                        final String name = CesecoreConfiguration.getExtraAlgSubAlgName(algName, subAlg);
                        final int bitLength = AlgorithmTools.getNamedEcCurveBitLength(name);
                        if (availableBitLengths.contains(bitLength)) {
                            availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConfigurationCache.INSTANCE.getConfigurationDefinedAlgorithmTitle(algName) + "_" + name,
                                    CesecoreConfiguration.getExtraAlgSubAlgTitle(algName, subAlg)));
                        } else {
                            if (log.isTraceEnabled()) {
                                log.trace("Excluding " + name + " from enrollment options since bit length " + bitLength + " is not available.");
                            }
                        }
                    }
                }
            }
            if (availableAlgorithmSelectItems.size() < 1) {
                availableAlgorithmSelectItems.add(new SelectItem(null, raLocaleBean.getMessage("enroll_select_ka_nochoice"), raLocaleBean.getMessage("enroll_select_ka_nochoice"), true));
            }
        EnrollMakeNewRequestBean.sortSelectItemsByLabel(availableAlgorithmSelectItems);
        return availableAlgorithmSelectItems;
    }

    /**
     * Validate that password and password confirm entries match and render error messages otherwise.
     */
    public final void validatePassword(ComponentSystemEvent event) {
        if (!isNotificationConfigured()) {
            FacesContext fc = FacesContext.getCurrentInstance();
            UIComponent components = event.getComponent();
            UIInput uiInputPassword = (UIInput) components.findComponent("enrollmentCode");
            String password = uiInputPassword.getLocalValue() == null ? "" : uiInputPassword.getLocalValue().toString();
            UIInput uiInputConfirmPassword = (UIInput) components.findComponent("passwordConfirmField");
            String confirmPassword = uiInputConfirmPassword.getLocalValue() == null ? "" : uiInputConfirmPassword.getLocalValue().toString();
            if (password.isEmpty()) {
                fc.addMessage(confirmPasswordComponent.getClientId(fc), raLocaleBean.getFacesMessage("enroll_password_can_not_be_empty"));
                fc.renderResponse();
            }
            if (!password.equals(confirmPassword)) {
                fc.addMessage(confirmPasswordComponent.getClientId(fc), raLocaleBean.getFacesMessage("enroll_passwords_are_not_equal"));
                fc.renderResponse();
            }
        }
    }

}
