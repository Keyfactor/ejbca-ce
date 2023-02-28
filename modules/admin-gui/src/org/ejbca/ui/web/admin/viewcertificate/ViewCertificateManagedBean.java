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
package org.ejbca.ui.web.admin.viewcertificate;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.faces.context.FacesContext;
import javax.faces.event.ComponentSystemEvent;
import javax.faces.view.ViewScoped;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.CertificateView;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.bean.SessionBeans;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;

/**
 * JavaServer Faces Managed Bean for managing viewcertificate popup view.
 * View scoped
 *
 */
@ViewScoped
@Named("viewCertificateMBean")
public class ViewCertificateManagedBean extends BaseManagedBean implements Serializable {
    private static final Logger log = Logger.getLogger(ViewCertificateManagedBean.class);

    private static final long serialVersionUID = 1L;
    
    private static final String CA_ID_PARAMETER            = "caid";
    private static final String USER_PARAMETER             = "username";
    private static final String CERTSERNO_PARAMETER        = "certsernoparameter";
    private static final String CACERT_PARAMETER           = "caid";
    private static final String SERNO_PARAMETER            = "serno";
    // Used for backlink to Role Members page & IKB page
    private static final String ROLE_ID                    = "roleId";
    private static final String KEYBINDING_ID              = "keyBindingId";

    private static final int RETURN_TO_AUDITLOG = 0;
    private static final int RETURN_TO_PEERCONNECTORS = 1;
    private static final int RETURN_TO_OCSPKB = 2;
    private static final int RETURN_TO_AUTHKB = 3;
    private static final int RETURN_TO_EDITIKB= 4;
    private static final int RETURN_TO_ROLEMEMBERS = 5;
    
    private static final String HIDDEN_INDEX               = "hiddenindex";
    
    private boolean noparameter = true;
    private boolean cacerts = false;
    private boolean useKeyRecovery = false;   
    private CertificateView certificateData = null;
    private String certificateSerNo = null;
    private String userName = null;         
    private String tokenSn = null;
    private String message = null;
    private int numberOfCertificates = 0;
    private int currentIndex = 0;
    private int caId = 0;
    private int roleId = 0;
    private int keyBindingId = 0;
    
    private EjbcaWebBean ejbcaBean;
    private CAInterfaceBean caBean;
    private RAInterfaceBean raBean;
    
    private String caName;
    private String formattedCertSn;
    private String issuerDnUnescaped;
    private String subjectDnUnescaped;
    private String subjectDnEscapedWithLanguageConsideration;
    private List<String> subjectAltName;
    private String subjectDirAttributes;
    private String publicKey;
    private String basicConstraints;
    private String keyUsage;
    private String extendedKeyUsage;
    private List<String> aiaOcspServiceLocators ;
    private List<String> aiaCaIssuerUris;
    private boolean hasAuthorityInformationAccess;
    private String fingerPrint;
    private String revoked;
    private boolean hasNameConstraints;
    private boolean qcStatement;
    private boolean certificateTransparencySCTs;
    private boolean isCvc;
    private String accountBindingId;
    
    private String downloadCertificateLink;
    
    private String revokeReason;
    private Map<Integer, String> revokeReasons;

    private String returnToLink = null;
    
    // Authentication check and audit log page access request
    public void initialize(final ComponentSystemEvent event) throws Exception {
        // Invoke on initial request only
        if (!FacesContext.getCurrentInstance().isPostback()) {
            initialize();
        } else if (!getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.ROLE_ADMINISTRATOR)) {
            throw new AuthorizationDeniedException("You are not authorized to view this page.");
        }
    }
    
    /**
     * Method that initializes the bean.
     *
     * @throws Exception 
     */
    public void initialize() throws Exception {
        
        final HttpServletRequest request = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
        
        ejbcaBean = getEjbcaWebBean();
        final GlobalConfiguration globalconfiguration = ejbcaBean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR);
        caBean = SessionBeans.getCaBean(request);
        raBean = SessionBeans.getRaBean(request);
        
        final String caIdParameter = request.getParameter(CA_ID_PARAMETER);
        if (caIdParameter != null) {
            caId = Integer.parseInt(caIdParameter);           
        }
        
        raBean.initialize(ejbcaBean);
        caBean.initialize(ejbcaBean);
        
        useKeyRecovery = globalconfiguration.getEnableKeyRecovery() && ejbcaBean.isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_KEYRECOVERY);
        RequestHelper.setDefaultCharacterEncoding(request);
        
        parseRequest(request);
        
        assertRequestValid(caIdParameter);
        
        composeCertificateData(request, globalconfiguration);
    }

    private void composeCertificateData(final HttpServletRequest request, final GlobalConfiguration globalconfiguration) {
        if (certificateData != null) {
            caName = caBean.getName(caId);
            formattedCertSn = raBean.getFormatedCertSN(certificateData);
            issuerDnUnescaped = certificateData.getUnescapedRdnValue(certificateData.getIssuerDNUnEscaped());
            subjectDnUnescaped = certificateData.getUnescapedRdnValue(certificateData.getSubjectDNUnescaped());
            subjectDnEscapedWithLanguageConsideration = certificateData.getUnescapedRdnValue(certificateData.getSubjectDnEscapedWithLanguageConsideration());
            subjectAltName = certificateData.getSubjectAltName() != null ? Stream.of(certificateData.getSubjectAltName().replace("\\,", ",").split(", ")).collect(Collectors.toCollection(ArrayList::new)) : new ArrayList<>();
            subjectDirAttributes = (certificateData.getSubjectDirAttr() == null) ? ejbcaBean.getText("SDA_NONE") : certificateData.getSubjectDirAttr();
            publicKey = composePublicKeyValue();
            accountBindingId = certificateData.getAccountBindingId();
            
            basicConstraints = certificateData.getBasicConstraints(ejbcaBean.getText("EXT_UNUSED"), 
                    ejbcaBean.getText("EXT_PKIX_BC_CANOLIMIT"), 
                    ejbcaBean.getText("EXT_PKIX_BC_ENDENTITY"), 
                    ejbcaBean.getText("EXT_PKIX_BC_CAPATHLENGTH"));
            
            keyUsage = composeKeyUsage();
            extendedKeyUsage = composeExtendedKeyUsage();
            
            aiaOcspServiceLocators = certificateData.getAuthorityInformationAccessOcspUrls();
            aiaCaIssuerUris = certificateData.getAuthorityInformationAccessCaIssuerUris();
            hasAuthorityInformationAccess = certificateData.hasAuthorityInformationAccess();

            fingerPrint = composeFingerPrint();
            revoked = composeRevokedText();

            revokeReasons = idToText(SecConst.reasontexts);

            isCvc = certificateData.getType().equalsIgnoreCase("CVC");
            hasNameConstraints = certificateData.hasNameConstraints();
            qcStatement = certificateData.hasQcStatement();
            certificateTransparencySCTs = certificateData.hasCertificateTransparencySCTs();
            
            downloadCertificateLink = ejbcaBean.getBaseUrl() + globalconfiguration.getCaPath() + "/endentitycert";
            
            returnToLink = composeReturnToLink(request, globalconfiguration);
        }
    }

    private String composeReturnToLink(final HttpServletRequest request, final GlobalConfiguration globalconfiguration) {
        String returnToLink = null;
        final String RETURNTO_PARAMETER = "returnTo";
        final String returnToParameter = request.getParameter(RETURNTO_PARAMETER);
        try {
            final int returnToId = Integer.parseInt(returnToParameter);
            switch (returnToId) {
            case RETURN_TO_AUDITLOG: // 0 = send user to the audit log page
                returnToLink = ejbcaBean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "audit/search.xhtml";
                break;
            case RETURN_TO_PEERCONNECTORS: // 1 = send user to the peer overview page
                returnToLink = ejbcaBean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "peerconnector/peerconnectors.xhtml";
                break;
            case RETURN_TO_OCSPKB: // 2 = send user to the IKB OCSP page
                returnToLink = ejbcaBean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "keybind/ocspresponders.xhtml";
                break;
            case RETURN_TO_AUTHKB: // 3 = send user to the IKB AKB page
                returnToLink = ejbcaBean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "keybind/keybindings.xhtml";
                break;
            case RETURN_TO_EDITIKB: // 4 = send user back to Edit IKB page (default to IKB page)
                if (keyBindingId != 0) {
                    returnToLink = ejbcaBean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "keybind/keybinding.xhtml?internalKeyBindingId=" + keyBindingId;
                } else {
                    returnToLink = ejbcaBean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "keybind/keybindings.xhtml";
                }
                break;
            case RETURN_TO_ROLEMEMBERS: // 5 = send user back to role members page
                if (roleId != 0) {
                    returnToLink = ejbcaBean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "administratorprivileges/rolemembers.xhtml?roleId=" + roleId;
                } else {
                    returnToLink = ejbcaBean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "administratorprivileges/roles.xhtml";
                }
            }
        } catch (final NumberFormatException e) {
            // do nothing. null will be returned, if 'return-to' was not specified
        }
        return returnToLink;
    }

    private Map<Integer, String> idToText(final String[] keys) {
        final Map<Integer, String> idToText= new HashMap<>();
        for (int i = 0; i < keys.length; i++) {
            if (keys[i].equals("REV_UNUSED")) {
                continue;
            }
            if (certificateData.isRevokedAndOnHold() && keys[i].equals("REV_CERTIFICATEHOLD")) {
                continue;
            }
            if (keys[i].equals("REV_REMOVEFROMCRL")) {
                continue;
            }
            idToText.put(i, ejbcaBean.getText(keys[i]));
        }
        return idToText;
    }

    private String composeRevokedText() {
        String revokedText = "";
        if (certificateData.isRevoked()) {
            revokedText += ejbcaBean.getText("YES") 
                    + "<br/>"
                    + ejbcaBean.getText("CRL_ENTRY_REVOCATIONDATE") + " "
                    + ejbcaBean.formatAsISO8601(certificateData.getRevocationDate()) 
                    + "<br/>"
                    + ejbcaBean.getText("REVOCATIONREASONS") + " ";
            final String reason = certificateData.getRevocationReason();
            if (reason != null) {
                revokedText += ejbcaBean.getText(reason);
            }
          } else {
              revokedText += ejbcaBean.getText("NO");
          }
        return revokedText;
    }


    private String composeFingerPrint() {
        final String fingerprint = certificateData.getSHA256Fingerprint();
        
         if (fingerprint.length()>32) {
            return fingerprint.substring(0,32) + "<br/>" + fingerprint.substring(32);
        } else {
            return fingerprint;
        }
    }

    private String composeExtendedKeyUsage() {
        final List<String> texts = new ArrayList<>();
        final AvailableExtendedKeyUsagesConfiguration configuration = ejbcaBean.getAvailableExtendedKeyUsagesConfiguration();
        final String[] extendedKeyUsageAsTexts = certificateData.getExtendedKeyUsageAsTexts(configuration);
        for (String extendedKeyUsageAsText : extendedKeyUsageAsTexts) {
            texts.add(ejbcaBean.getText(extendedKeyUsageAsText));
        }
        return (texts.isEmpty()) ? ejbcaBean.getText("EKU_NONE") : StringUtils.join(texts, ',');
    }
    
    private String composeKeyUsage() {
        final List<String> keyUsageTexts = new ArrayList<>();
        
        if (certificateData.getKeyUsage(CertificateConstants.DIGITALSIGNATURE)) {
            keyUsageTexts.add(ejbcaBean.getText("KU_DIGITALSIGNATURE"));
        }
        if (certificateData.getKeyUsage(CertificateConstants.NONREPUDIATION)) {
            keyUsageTexts.add(ejbcaBean.getText("KU_NONREPUDIATION"));
        }
        if (certificateData.getKeyUsage(CertificateConstants.KEYENCIPHERMENT)) {
            keyUsageTexts.add(ejbcaBean.getText("KU_KEYENCIPHERMENT"));
        }
        if (certificateData.getKeyUsage(CertificateConstants.DATAENCIPHERMENT)) {
            keyUsageTexts.add(ejbcaBean.getText("KU_DATAENCIPHERMENT"));
        }
        if (certificateData.getKeyUsage(CertificateConstants.KEYAGREEMENT)) {
            keyUsageTexts.add(ejbcaBean.getText("KU_KEYAGREEMENT"));
        }
        if (certificateData.getKeyUsage(CertificateConstants.KEYCERTSIGN)) {
            keyUsageTexts.add(ejbcaBean.getText("KU_KEYCERTSIGN"));
        }
        if (certificateData.getKeyUsage(CertificateConstants.CRLSIGN)) {
            keyUsageTexts.add(ejbcaBean.getText("KU_CRLSIGN"));
        }
        if (certificateData.getKeyUsage(CertificateConstants.ENCIPHERONLY)) {
            keyUsageTexts.add(ejbcaBean.getText("KU_ENCIPHERONLY"));
        }
        if (certificateData.getKeyUsage(CertificateConstants.DECIPHERONLY)) {
            keyUsageTexts.add(ejbcaBean.getText("KU_DECIPHERONLY"));
        }
        return (keyUsageTexts.isEmpty()) ? ejbcaBean.getText("KU_NONE") : StringUtils.join(keyUsageTexts, ',');
    }


    private String composePublicKeyValue() {
        String publicKeyValue = certificateData.getPublicKeyAlgorithm() + " (" + certificateData.getKeySpec(ejbcaBean.getText("BITS")) + ")";
        if (certificateData.getPublicKeyModulus() != null) {
            publicKeyValue += ": " + certificateData.getPublicKeyModulus();  
        }
        return publicKeyValue;
    }

    private void parseRequest(final HttpServletRequest request) throws AuthorizationDeniedException, UnsupportedEncodingException {

        if (request.getParameter(USER_PARAMETER) != null) {
            noparameter = false;
            if (ejbcaBean.isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_VIEWCERTIFICATE)) {
                userName = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER), "UTF-8");
                raBean.loadCertificates(userName);
            }
        }

        if (request.getParameter(CERTSERNO_PARAMETER) != null) {
            final String certSernoParam = java.net.URLDecoder.decode(request.getParameter(CERTSERNO_PARAMETER), "UTF-8");
            if (certSernoParam != null) {
                final String[] certdata = ejbcaBean.getCertSernoAndIssuerdn(certSernoParam);
                if (certdata != null && certdata.length > 0) {
                    raBean.loadCertificates(new BigInteger(certdata[0], 16), certdata[1]);
                }
            }
            noparameter = false;
        }

        if (request.getParameter(ROLE_ID) != null) {
            roleId = Integer.parseInt(request.getParameter(ROLE_ID));
        }
        
        if (request.getParameter(KEYBINDING_ID) != null) {
            keyBindingId = Integer.parseInt(request.getParameter(KEYBINDING_ID));
        }
        
        if (request.getParameter(SERNO_PARAMETER) != null && request.getParameter(CACERT_PARAMETER) != null) {
            certificateSerNo = request.getParameter(SERNO_PARAMETER);
            noparameter = false;
            try {
                final BigInteger serNo = new BigInteger(certificateSerNo, 16);
                caId = Integer.parseInt(request.getParameter(CACERT_PARAMETER));
                raBean.loadCertificates(serNo, caId);
            } catch (NumberFormatException e) {
                log.debug("Invalid input of cert serial or caid: " + certificateSerNo + ", " + request.getParameter(CACERT_PARAMETER));
            }
        } else if (request.getParameter(CACERT_PARAMETER) != null) {
            caId = Integer.parseInt(request.getParameter(CACERT_PARAMETER));
            raBean.loadCACertificates(caBean.getCACertificates(caId));
            numberOfCertificates = raBean.getNumberOfCertificates();
            if (numberOfCertificates > 0) {
                currentIndex = 0;
            }
            noparameter = false;
            cacerts = true;
        }
        if (request.getParameter(HIDDEN_INDEX) != null) {
            currentIndex = Integer.parseInt(request.getParameter(HIDDEN_INDEX));
            certificateData = raBean.getCertificate(currentIndex);
        }
        if (!noparameter) {
            numberOfCertificates = raBean.getNumberOfCertificates();
            if (numberOfCertificates > 0)
                certificateData = raBean.getCertificate(currentIndex);
        }
    }
    
    private void assertRequestValid(final String caIdParameter) {
        if (noparameter) {
            addErrorMessage("YOUMUSTSPECIFYCERT");
        } else if (caIdParameter == null && !ejbcaBean.isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_VIEWCERTIFICATE)) {
            addErrorMessage("NOTAUTHORIZEDTOVIEWCERT");
        } else if (certificateData == null) {
            addErrorMessage("CERTIFICATEDOESNTEXIST");
        } else if (message != null) {
            addErrorMessage(message);
        }
    }
    
    public boolean isCacerts() {
        return cacerts;
    }
    
    public CertificateView getCertificateData() {
        return certificateData;
    }
    
    public String getCaName() {
        return caName;
    }
    
    public int getCaId() {
        return caId;
    }
    
    public String getUserName() {
        return userName;
    }

    public String getTokenSn() {
        return tokenSn;
    }
    
    public int getNumberOfCertificates() {
        return numberOfCertificates;
    }


    public int getCurrentIndex() {
        return currentIndex;
    }    

    public int getNextIndex() {
        return currentIndex + 1;
    }
    
    public String getFormattedCertSn() {
        return formattedCertSn;
    }
    
    public String getIssuerDnUnescaped() {
        return issuerDnUnescaped;
    }
    
    public String getSubjectDnUnescaped() {
        return subjectDnUnescaped;
    }
    
    public String getSubjectDnEscapedWithLanguageConsideration() {
        return subjectDnEscapedWithLanguageConsideration;
    }
    
    public List<String> getSubjectAltName() {
        return subjectAltName;
    }
    
    public String getSubjectDirAttributes() {
        return subjectDirAttributes;
    }
    
    public String getPublicKey() {
        return publicKey;
    }
    
    public String getAccountBindingId() {
        return accountBindingId;
    }
    
    public String getBasicConstraints() {
        return basicConstraints;
    }
    
    public String getKeyUsage() {
        return keyUsage;
    }
    
    public String getExtendedKeyUsage() {
        return extendedKeyUsage;
    }
    
    public String getFingerPrint() {
        return fingerPrint;
    }
    
    public String getRevoked() {
        return revoked;
    }
    
    public boolean getHasNameConstraints() {
        return hasNameConstraints;
    }

    public boolean getHasAuthorityInformationAccess() {
        return hasAuthorityInformationAccess;
    }

    public boolean isQcStatement() {
        return qcStatement;
    }
    
    public boolean isCertificateTransparencySCTs() {
        return certificateTransparencySCTs;
    }
    
    public boolean getIsCvc() {
        return isCvc;
    }

    public boolean isKeyRecoveryPossible() throws AuthorizationDeniedException {
        boolean keyRecoveryPossible = raBean.keyRecoveryPossible(certificateData.getCertificate(), certificateData.getUsername());
        return !cacerts &&  keyRecoveryPossible && useKeyRecovery;
    }

    public boolean isRepublishPossible() throws Exception {
        return !cacerts &&  raBean.userExist(certificateData.getUsername()) && raBean.isAuthorizedToEditUser(certificateData.getUsername());
    }
    
    public boolean isAuthorizedToRevoke() throws AuthorizationDeniedException {
        return !cacerts && raBean.authorizedToRevokeCert(certificateData.getUsername()) && ejbcaBean.isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_REVOKEENDENTITY);
    }
    
    public boolean isRevokedOrSuspended() {
        return !certificateData.isRevoked() || certificateData.isRevokedAndOnHold();
    }
    
    public boolean getCanBeUnrevoked() {
        return !cacerts && certificateData.isRevokedAndOnHold();
    }
    
    public String getRevokeReason() {
        return revokeReason;
    }
    
    public void setRevokeReason(final String revokeReason) {
        this.revokeReason = revokeReason;
    }

    public Map<Integer, String> getRevokeReasons() {
        return revokeReasons;
    }
    
    public String getDownloadCertificateLink() {
        return downloadCertificateLink;
    }

    public boolean isDisplayShowOlderButton() {
        return currentIndex < numberOfCertificates - 1;
    }
    
    public boolean isDisplayShowNewerButton() {
        return currentIndex > 0;
    }
    
    public String getReturnToLink() {
        return returnToLink;
    }
    
    
    public List<String> getAiaOcspServiceLocators() {
        return aiaOcspServiceLocators;
    }

    public List<String> getAiaCaIssuerUris() {
        return aiaCaIssuerUris;
    }

    public String getLink() throws UnsupportedEncodingException {
        return ejbcaBean.getBaseUrl()+ ejbcaBean.getGlobalConfiguration().getAdminWebPath() + java.net.URLEncoder.encode("viewcertificate.xhtml","UTF-8") ;
    }

    public void actionKeyRecovery() throws CADoesntExistsException, AuthorizationDeniedException {
        if (!cacerts && raBean.keyRecoveryPossible(certificateData.getCertificate(), certificateData.getUsername()) && useKeyRecovery) {
            try {
                raBean.markForRecovery(certificateData.getUsername(), certificateData.getCertificate());
            } catch (final org.ejbca.core.model.approval.ApprovalException e) {
                message = "THEREALREADYEXISTSAPPROVAL";
            } catch (final org.ejbca.core.model.approval.WaitingForApprovalException e) {
                message = "REQHAVEBEENADDEDFORAPPR";
            }
        }
        try {
            if (userName != null) {
                raBean.loadCertificates(userName);
            } else {
                raBean.loadCertificates(certificateData.getSerialNumberBigInt(), certificateData.getIssuerDNUnEscaped());
            }
        } catch (final AuthorizationDeniedException e) {
            // ignore
        }
        numberOfCertificates = raBean.getNumberOfCertificates();
        certificateData = raBean.getCertificate(currentIndex);
    }
    
    public void actionRepublish() throws AuthorizationDeniedException {
        // Mark certificate for key recovery.
        message = caBean.republish(certificateData);
        try {
            if (userName != null) {
                raBean.loadCertificates(userName);
            } else {
                raBean.loadCertificates(certificateData.getSerialNumberBigInt(), certificateData.getIssuerDNUnEscaped());
            }
        } catch (final AuthorizationDeniedException e) {
            // ignore
        }
        numberOfCertificates = raBean.getNumberOfCertificates();
    }
    
    
    public void actionRevoke() throws AuthorizationDeniedException {
        final int reason = Integer.valueOf(revokeReason);
        if (!cacerts && raBean.authorizedToRevokeCert(certificateData.getUsername())
                && ejbcaBean.isAuthorizedNoLog(AccessRulesConstants.REGULAR_REVOKEENDENTITY)
                && (!certificateData.isRevoked() || certificateData.isRevokedAndOnHold())) {
            try {
                raBean.revokeCert(certificateData.getSerialNumberBigInt(), certificateData.getIssuerDNUnEscaped(), certificateData.getUsername(), reason);
            } catch (final org.ejbca.core.model.approval.ApprovalException e) {
                message = "THEREALREADYEXISTSAPPOBJ";
            } catch (final org.ejbca.core.model.approval.WaitingForApprovalException e) {
                message = "REQHAVEBEENADDEDFORAPPR";
            }
        }
        try {
            if (userName != null) {
                raBean.loadCertificates(userName);
            } else {
                raBean.loadCertificates(certificateData.getSerialNumberBigInt(), certificateData.getIssuerDNUnEscaped());
            }
        } catch (final AuthorizationDeniedException e) {
            // ignore
        }
        numberOfCertificates = raBean.getNumberOfCertificates();
        certificateData = raBean.getCertificate(currentIndex);
    }
    
    public void actionUnrevoke() throws AuthorizationDeniedException {
        if (!cacerts && raBean.authorizedToRevokeCert(certificateData.getUsername())
                && ejbcaBean.isAuthorizedNoLog(AccessRulesConstants.REGULAR_REVOKEENDENTITY) && certificateData.isRevokedAndOnHold()) {
            //-- call to unrevoke method
            try {
                raBean.unrevokeCert(certificateData.getSerialNumberBigInt(), certificateData.getIssuerDNUnEscaped(),
                        certificateData.getUsername());
            } catch (final org.ejbca.core.model.approval.ApprovalException e) {
                message = "THEREALREADYEXISTSAPPOBJ";
            } catch (final org.ejbca.core.model.approval.WaitingForApprovalException e) {
                message = "REQHAVEBEENADDEDFORAPPR";
            }
        }

        try {
            if (userName != null) {
                raBean.loadCertificates(userName);
            } else {
                raBean.loadCertificates(certificateData.getSerialNumberBigInt(), certificateData.getIssuerDNUnEscaped());
            }
        } catch (final AuthorizationDeniedException e) {
            // ignore
        }

        numberOfCertificates = raBean.getNumberOfCertificates();
        certificateData = raBean.getCertificate(currentIndex);
    }
}
