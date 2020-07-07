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
package org.ejbca.ui.web.admin.ca;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.FacesException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.component.UIInput;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAFactory;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.CmsCertificatePathMissingException;
import org.cesecore.certificates.ca.ExtendedUserDataHandler;
import org.cesecore.certificates.ca.ExtendedUserDataHandlerFactory;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.ssh.SshCa;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.PrivateKeyNotExtractableException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.BaseSigningCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.attribute.AttributeMapping.REQUEST;
import org.ejbca.ui.web.admin.attribute.AttributeMapping.SESSION;
import org.ejbca.ui.web.admin.bean.SessionBeans;
import org.ejbca.ui.web.admin.cainterface.CADataHandler;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.cainterface.CaInfoDto;
import org.ejbca.ui.web.admin.certprof.CertProfileBean.ApprovalRequestItem;

/**
 *
 * JSF MBean backing the edit ca page.
 *
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class EditCAsMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EditCAsMBean.class);

    private String CRYPTO_TOKEN_LINK = StringUtils.EMPTY;

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private KeyValidatorSessionLocal keyValidatorSession;

    private CAInterfaceBean caBean;
    private String editCaName;
    private int caid = 0;

    private final TreeMap<String,Integer> rootCaProfiles = getEjbcaWebBean().getAuthorizedRootCACertificateProfileNames();
    private final TreeMap<String,Integer> subCaProfiles = getEjbcaWebBean().getAuthorizedSubCACertificateProfileNames();

    private CaInfoDto caInfoDto = new CaInfoDto();
    private boolean isEditCA;


    private int caRevokeReason;
    private String certSignKeyReNewValue;
    private String certExtrSignKeyReNewValue;
    private String certSignKeyRequestValue;
    private boolean checkBoxFutureRollOver;
    private List<String> availableCryptoTokenKeyAliases;
    private List<String> availableCryptoTokenMixedAliases;
    private List<String> availableCryptoTokenEncryptionAliases;
    private boolean createLinkCertificate;

    private CAInfo cainfo = null;
    private CAToken catoken = null;
    private boolean isCaexternal = false;
    private boolean isCaRevoked = false;
    private Map<Integer, String> keyValidatorMap = getEjbcaWebBean().getEjb().getKeyValidatorSession().getKeyValidatorIdToNameMap();
    private final Map<Integer, String> approvalProfileMap = getEjbcaWebBean().getApprovalProfileIdToNameMap();
    private final TreeMap<String, Integer> certProfilesOfEndEntityType = getEjbcaWebBean().getAuthorizedEndEntityCertificateProfileNames();
    private boolean isUniqueIssuerDnSerialNoIndexPresent;
    private boolean isCvcAvailable;
    private boolean signbyexternal = false;
    private boolean revokable = true;
    private boolean waitingresponse = false;
    private boolean isCaUninitialized = false;
    private CmsCAServiceInfo cmscainfo = null;
    private X509Certificate cmscert = null;
    private List<ApprovalRequestItem> approvalRequestItems = null;
    private String extendedServicesKeySpecParam = null;

    private boolean suitableCryptoTokenExists;
    private List<SelectItem> availableCryptoTokenSelectItems;
    private Map<String,String> failedCryptoTokenLinkMap;
    private int currentCryptoTokenId = 0;
    private boolean currentCryptoTokenPresent;
    private String currentCryptoTokenName;
    private String currentCryptoTokenLink;

    private final Map<String, String> aliasUsedMap = new HashMap<>();

    // These two are used in CA life cycle section of edit ca page.
    private boolean cANameChange;
    private String newSubjectDn;


    private GlobalConfiguration globalconfiguration;
    private CADataHandler cadatahandler;
    private Map<Integer, String> caIdToNameMap;
    private final Map<String,Integer> caSigners = getEjbcaWebBean().getActiveCANames();
    private final Map<Integer,String> publisheridtonamemap = getEjbcaWebBean().getPublisherIdToNameMapByValue();
    private String crlCaCRLDPExternal;
    private List<String> usedCrlPublishers;
    private Collection<Integer> usedValidators;
    private boolean hideValidity = false;
    private String caCryptoTokenKeyEncryptKey;
    private String caCryptoTokenTestKey;

    private UploadedFile fileRecieveFileMakeRequest;
    private UploadedFile fileRecieveFileRecieveRequest;
    private UploadedFile fileRecieveFileImportRenewal;

    private String viewCertLink;
    private boolean hasLinkCertificate;
    private String issuerDn = "unknown";
    private Date rolloverNotBefore = null;
    private Date rolloverNotAfter = null;
    private Date caCertNotAfter = null;


    public UploadedFile getFileRecieveFileImportRenewal() {
        return fileRecieveFileImportRenewal;
    }

    public void setFileRecieveFileImportRenewal(final UploadedFile fileRecieveFileImportRenewal) {
        this.fileRecieveFileImportRenewal = fileRecieveFileImportRenewal;
    }

    public CaInfoDto getCaInfoDto() {
        return caInfoDto;
    }

    public void setCaInfoDto(CaInfoDto caInfoDto) {
        this.caInfoDto = caInfoDto;
    }

    public UploadedFile getFileRecieveFileMakeRequest() {
        return fileRecieveFileMakeRequest;
    }

    public void setFileRecieveFileMakeRequest(final UploadedFile fileRecieveFileMakeRequest) {
        this.fileRecieveFileMakeRequest = fileRecieveFileMakeRequest;
    }

    public EditCAsMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource());
        globalconfiguration = getEjbcaWebBean().getGlobalConfiguration();
    }

    @PostConstruct
    public void initialize() {
        EditCaUtil.navigateToManageCaPageIfNotPostBack();

        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        try {
            caBean = SessionBeans.getCaBean(request);
        } catch (ServletException e) {
            throw new IllegalStateException("Could not initiate CAInterfaceBean", e);
        }

        cadatahandler = caBean.getCADataHandler();
        caIdToNameMap = caSession.getCAIdToNameMap();
        isUniqueIssuerDnSerialNoIndexPresent = caBean.isUniqueIssuerDNSerialNoIndexPresent();
        isCvcAvailable = caBean.isCvcAvailable();

        final Map<String, Object> requestMap = FacesContext.getCurrentInstance().getExternalContext().getRequestMap();
        initPageVariables(requestMap);

        viewCertLink = getEjbcaWebBean().getBaseUrl() + globalconfiguration.getAdminWebPath() + "viewcertificate.xhtml";

        try {
            cainfo = caBean.getCAInfo(caid).getCAInfo();
        } catch (final AuthorizationDeniedException e) {
            log.error("Error while trying to get the ca info!", e);
        }

        CRYPTO_TOKEN_LINK = getEjbcaWebBean().getBaseUrl() + globalconfiguration.getAdminWebPath()
        + "cryptotoken/cryptotoken.jsf?cryptoTokenId=";

        // Init include health check
        caInfoDto.setIncludeInHealthCheck(cainfo != null && cainfo.getIncludeInHealthCheck());

        // Here we do initialize the sub views.
        if (isEditCA) {
            initEditCaPage();
        } else {
            initCreateCaPage();
        }
        updateKeyAliases();

        // Is this CA is a root CA? Then create link certificate on renewal by default
        createLinkCertificate = cainfo != null && CAInfo.SELFSIGNED == cainfo.getSignedBy();
    }


    public String getNewSubjectDn() {
        return newSubjectDn;
    }

    public void setNewSubjectDn(final String newSubjectDn) {
        this.newSubjectDn = newSubjectDn;
    }

    public boolean iscANameChange() {
        return cANameChange;
    }

    public void setcANameChange(final boolean cANameChange) {
        this.cANameChange = cANameChange;
    }

    public int getCaid() {
        return caid;
    }

    public void setCaTypeX509() {
        caInfoDto.setCaType(CAInfo.CATYPE_X509);
    }

    public void setCaTypeCVC() {
        caInfoDto.setCaType(CAInfo.CATYPE_CVC);
    }

    public void setCaTypeSSH() {
        caInfoDto.setCaType(CAInfo.CATYPE_SSH);
    }

    public String getCurrentCaType() {
        switch (caInfoDto.getCaType()) {
        case CAInfo.CATYPE_X509:
            return "X509";
        case CAInfo.CATYPE_CVC:
            return "CVC";
        case CAInfo.CATYPE_SSH:
            return SshCa.CA_TYPE;
        default:
            return "UNKNOWN";
        }
    }

    public boolean isEditCA() {
        return isEditCA;
    }

    public void setEditCA(final boolean isEditCA) {
        this.isEditCA = isEditCA;
    }

    public String getButtonEditCAValue() {
        return isViewOnly() ? getEjbcaWebBean().getText("VIECA") : getEjbcaWebBean().getText("EDITCA");
    }

    public String getImportKeystoreText() {
        return getEjbcaWebBean().getText("IMPORTCA_KEYSTORE") + "...";
    }

    public String getImportCertificateText() {
        return getEjbcaWebBean().getText("IMPORTCA_CERTIFICATE") + "...";
    }

    public boolean isCanRemoveResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAREMOVE.resource());
    }

    public boolean isCanAddResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAADD.resource());
    }

    public boolean isCanRenewResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CARENEW.resource());
    }

    public boolean isCanEditResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource());
    }

    public boolean isCanAddOrEditResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAADD.resource())
                || getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource());
    }

    public boolean isCaUninitialized() {
        return isCaUninitialized;
    }

    public boolean isCaExternal() {
        return isCaexternal;
    }

    public boolean isSignByExternal() {
        return signbyexternal;
    }

    public String getCurrentCaSigningAlgorithm() {
        if (this.cainfo != null) {
            final String signAlgorithm = cainfo.getCAToken().getSignatureAlgorithm();
            if (signAlgorithm != null) {
                return signAlgorithm;
            }
            return getEjbcaWebBean().getText("NOTUSED");
        }
        return StringUtils.EMPTY;
    }

    public String getEditCAPageTitle() {
        if (this.isEditCA && caBean.hasEditRight()) {
            return getEjbcaWebBean().getText("EDITCA");
        } else if (this.isEditCA){
            return getEjbcaWebBean().getText("VIEWCA");
        } else {
            return getEjbcaWebBean().getText("CREATECA");
        }
    }

    public boolean isHasEditRight() {
        return caBean.hasEditRight();
    }

    public boolean isHasCreateRight() {
        return caBean.hasCreateRight();
    }

    public String getCurrentCaCryptoTokenLink() {
        return currentCryptoTokenLink;
    }

    public String getCurrentCaCryptoTokenName() {
        return currentCryptoTokenName;
    }

    public boolean isCurrentCaCryptoTokenPresent() {
        return currentCryptoTokenPresent;
    }

    public String getCurrentCaCryptoTokenDefaultKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_DEFAULT);
            } catch (final CryptoTokenOfflineException e) {
                log.error("CA token offile exception!", e);
            }
        }
        return StringUtils.EMPTY;
    }

    public String getCurrentCaCryptoTokenCertSignKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
            } catch (final CryptoTokenOfflineException e) {
                log.error("CA token offile exception!", e);
            }
        }
        return StringUtils.EMPTY;
    }

    public String getCurrentCaCryptoTokenCrlSignKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
            } catch (final CryptoTokenOfflineException e) {
                log.error("CA token offile exception!", e);
            }
        }
        return StringUtils.EMPTY;
    }

    public String getCurrentCaCryptoTokenKeyEncryptKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
            } catch (final CryptoTokenOfflineException e) {
                log.error("CA token offile exception!", e);
            }
        }
        return this.caCryptoTokenKeyEncryptKey;
    }

    public String getCurrentCaCryptoTokenTestKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYTEST);
            } catch (final CryptoTokenOfflineException e) {
                log.error("CA token offile exception!", e);
            }
        }
        return this.caCryptoTokenTestKey;
    }

    public String getEditCaName() {
        return " : " + EditCaUtil.getTrimmedName(this.editCaName);
    }

    public String getCreateCaNameTitle() {
        return " : " + caInfoDto.getCaName();
    }

    public List<SelectItem> getKeySequenceFormatList() {
        final List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, getEjbcaWebBean().getText("NUMERIC")));
        resultList.add(new SelectItem(StringTools.KEY_SEQUENCE_FORMAT_ALPHANUMERIC, getEjbcaWebBean().getText("ALPHANUMERIC")));
        resultList.add(new SelectItem(StringTools.KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_NUMERIC, getEjbcaWebBean().getText("COUNTRYCODEPLUSNUMERIC")));
        resultList.add(new SelectItem(StringTools.KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_ALPHANUMERIC, getEjbcaWebBean().getText("COUNTRYCODEPLUSALPHANUMERIC")));
        return resultList;
    }

    public String getKeySequence() {
        if (catoken != null) {
            caInfoDto.setKeySequence(catoken.getKeySequence());
        }
        return caInfoDto.getKeySequence();
    }

    public void setKeySequence(final String keySequenceValue) {
        caInfoDto.setKeySequence(keySequenceValue);
    }

    public String getCheckboxUseCollapsedText() {
        return getEjbcaWebBean().getText("USE") + "...";
    }

    public String getCaIssuerDN() {
        return issuerDn;
    }

    public String getSignedByAsText() {
        switch (caInfoDto.getSignedBy()) {
        case CAInfo.SELFSIGNED: return getEjbcaWebBean().getText("SELFSIGNED");
        case CAInfo.SIGNEDBYEXTERNALCA: return getEjbcaWebBean().getText("EXTERNALCA");
        default:
            final String caName = caIdToNameMap.get(caInfoDto.getSignedBy());
            if (caName != null) {
                return caName;
            }
            log.warn("Missing signed by CA ID " + caInfoDto.getSignedBy());
            return "Missing CA ID " + caInfoDto.getSignedBy();
        }
    }

    public List<SelectItem> getSignedByList() {
        final List<SelectItem> signedByList = new ArrayList<>();

        signedByList.add(new SelectItem(CAInfo.SELFSIGNED, getEjbcaWebBean().getText("SELFSIGNED"), ""));
        signedByList.add(new SelectItem(CAInfo.SIGNEDBYEXTERNALCA, getEjbcaWebBean().getText("EXTERNALCA"), ""));

        for (final String nameOfCa : caSigners.keySet()) {
            final int entryId = caSigners.get(nameOfCa);
            if (entryId == caid) {
                continue;
            }
            signedByList.add(new SelectItem(entryId, nameOfCa, ""));
        }
        return signedByList;
    }

    public String getCertificateProfileEditCAUninitialized() {
        if (cainfo.getCertificateProfileId() != 0) {
            return certificateProfileSession.getCertificateProfileName(cainfo.getCertificateProfileId());
        }
        return getEjbcaWebBean().getText("NOTUSED");
    }

    public List<SelectItem> getCertificateProfiles() {
        final List<SelectItem> resultList = new ArrayList<>();
        if (caInfoDto.getSignedBy() == CAInfo.SELFSIGNED) {
            for (final Entry<String, Integer> entry : rootCaProfiles.entrySet()) {
                resultList.add(new SelectItem(entry.getValue(), entry.getKey()));
            }
        } else if (caInfoDto.getSignedBy() != 0) {
            for (final Entry<String, Integer> entry : subCaProfiles.entrySet()) {
                resultList.add(new SelectItem(entry.getValue(), entry.getKey()));
            }
        }
        return resultList;
    }

    public String getCaEncodedValidity() {
        if (cainfo != null) {
            return cainfo.getEncodedValidity();
        }
        return caInfoDto.getCaEncodedValidity();
    }

    public void setCaEncodedValidity(final String validity) {
        caInfoDto.setCaEncodedValidity(validity);
    }

    public boolean getHideValidity() {
        return hideValidity;
    }

    public boolean isCaTypeCVC() {
        return caInfoDto.getCaType() == CAInfo.CATYPE_CVC;
    }

    public boolean isCaTypeSSH() {
        return caInfoDto.getCaType() == CAInfo.CATYPE_SSH;
    }

    public String getCaSubjectAltName() {
        return caInfoDto.getCaSubjectAltName();

    }

    public void setCaSubjectAltName(final String subjectAltName) {
        caInfoDto.setCaSubjectAltName(subjectAltName);
    }

    public boolean getWaitingResponse() {
        return this.waitingresponse;
    }

    public void setWaitingResponse(final boolean waitingResponse) {
        this.waitingresponse = waitingResponse;
    }

    public String getCrlCaCRLDPExternal() {
        return this.crlCaCRLDPExternal;
    }

    public void setCrlCaCRLDPExternal(final String crlCaCRLDPExternal) {
        this.crlCaCRLDPExternal = crlCaCRLDPExternal;
    }

    private boolean isEditCaAndCaTypeX509() {
        return isEditCA && caInfoDto.isCaTypeX509();
    }

    public boolean isCheckboxAuthorityKeyIdentifierCriticalDisabled() {
        return isEditCaAndCaTypeX509() && (!caInfoDto.isUseAuthorityKeyIdentifier() || isCaexternal);
    }

    public boolean isCheckboxCrlNumberCriticalDisabled() {
        return isEditCaAndCaTypeX509() && (!caInfoDto.isUseCrlNumber() || isCaexternal);
    }

    public boolean isCheckboxCrlDistributionPointOnCrlCriticalDisabled() {
        return isEditCaAndCaTypeX509() && (!caInfoDto.isUseCrlDistributiOnPointOnCrl() || isCaexternal);
    }

    public boolean isUsePartitionedCrlChecked() {
        final UIInput checkbox = (UIInput) FacesContext.getCurrentInstance().getViewRoot().findComponent(":editcapage:checkboxusecrlpartitions");
        final Boolean submittedValue = (Boolean) checkbox.getSubmittedValue(); // check if there is a changed value (which might not have passed validation)
        return submittedValue != null ? submittedValue : caInfoDto.isUsePartitionedCrl();
    }

    public List<SelectItem> getAvailableCrlPublishers() {
        final List<SelectItem> ret = new ArrayList<>();
        final Set<Integer> publishersIds = publisheridtonamemap.keySet();

        for (final int id: publishersIds) {
            ret.add(new SelectItem(id, publisheridtonamemap.get(id), "", !isHasEditRight()));
        }
        return ret;
    }

    public List<SelectItem> getAvailableRequestPreProcessors() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem(null, "None", "", !isHasEditRight()));
        for (ExtendedUserDataHandler implementation : ExtendedUserDataHandlerFactory.INSTANCE.getAllImplementations()) {
            ret.add(new SelectItem(implementation.getClass().getCanonicalName(), implementation.getReadableName(), implementation.getReadableName(),
                    !isHasEditRight()));
        }
        return ret;
    }

    public List<Integer> getUsedCrlPublishers() {
        Collection<?> usedpublishers = null;
        final List<Integer> ret = new ArrayList<>();
        if (isEditCA) {
            usedpublishers = cainfo.getCRLPublishers();
        }
        final Set<Integer> publishersIds = publisheridtonamemap.keySet();

        for (final int id : publishersIds) {
            if (isEditCA && usedpublishers.contains(id)) {
                ret.add(id);
            }
        }
        return ret;
    }

    public void setUsedCrlPublishers(final List<String> publishers) {
        this.usedCrlPublishers = publishers;
    }

    public void genDefaultCrlDistPoint() {
        final StringBuilder sb = new StringBuilder();
        sb.append(globalconfiguration.getStandardCRLDistributionPointURINoDN());
        if (!isEditCA) {
            sb.append(encode(caInfoDto.getCaSubjectDN()));
        } else {
            sb.append(encode(cainfo.getSubjectDN()));
        }
        if (isUsePartitionedCrlChecked()) {
            sb.append("&partition=*");
        }
        caInfoDto.setDefaultCRLDistPoint(sb.toString());
    }

    private String encode(final String text) {
        try {
            return URLEncoder.encode(text, "UTF-8");
        } catch (final UnsupportedEncodingException e) {
            log.error("Error while encoding text " + text, e);
        }
        return StringUtils.EMPTY;
    }

    public void genDefaultCrlIssuer() {
        if (!isEditCA) {
            caInfoDto.setDefaultCRLIssuer(caInfoDto.getCaSubjectDN());
        } else {
            caInfoDto.setDefaultCRLIssuer(cainfo.getSubjectDN());
        }
    }

    public void genCaDefinedFreshestCrl() {
        final StringBuilder sb = new StringBuilder();
        sb.append(globalconfiguration.getStandardDeltaCRLDistributionPointURINoDN());
        if (!isEditCA) {
            sb.append(encode(caInfoDto.getCaSubjectDN()));
        } else {
            sb.append(encode(cainfo.getSubjectDN()));
        }
        if (isUsePartitionedCrlChecked()) {
            sb.append("&partition=*");
        }
        caInfoDto.setCaDefinedFreshestCRL(sb.toString());
    }

    public void genDefaultOcspLocator() {
        caInfoDto.setDefaultOCSPServiceLocator(globalconfiguration.getStandardOCSPServiceLocatorURI());
    }

    public List<ApprovalRequestItem> getApprovalRequestItems() {
        if (approvalRequestItems == null || approvalRequestItems.isEmpty()) {
            approvalRequestItems = new ArrayList<>();
            final Map<ApprovalRequestType, Integer> approvals = getApprovals();
            for (final ApprovalRequestType approvalRequestType : ApprovalRequestType.values()) {
                int approvalProfileId;
                approvalProfileId = approvals.getOrDefault(approvalRequestType, -1);
                approvalRequestItems.add(new ApprovalRequestItem(approvalRequestType, approvalProfileId));
            }
        }
        return approvalRequestItems;
    }

    public void setApprovalRequestItems(final List<ApprovalRequestItem> approvalRequestItems) {
        this.approvalRequestItems = approvalRequestItems;
    }

    public List<SelectItem> getAvailableApprovalProfiles() {
        final List<SelectItem> resultList = new ArrayList<>();
        final List<Integer> approvalProfileIds = getEjbcaWebBean().getSortedApprovalProfileIds();
        for(final Integer approvalProfileId : approvalProfileIds) {
            resultList.add(new SelectItem(approvalProfileId, approvalProfileMap.get(approvalProfileId)));
        }
        return resultList;
    }

    public List<SelectItem> getAvailableValidators() {
        final List<SelectItem> ret = new ArrayList<>();
        for (final int validatorId : keyValidatorMap.keySet()) {
                ret.add(new SelectItem(validatorId, keyValidatorMap.get(validatorId), "", !isHasEditRight()));
        }
        ret.sort((o1, o2) -> o1.getLabel().compareToIgnoreCase(o2.getLabel()));
        return ret;
    }

    public Collection<Integer> getUsedValidators() {
        return usedValidators;
    }

    public void setUsedValidators(final Collection<Integer> validators) {
        this.usedValidators = validators;
    }

    public boolean isRenderCmsInfo() {
        return caInfoDto.isCaTypeX509() && !isEditCA || (isEditCA && cmscainfo != null);
    }

    public boolean isCmsButtonDisabled() {
        return waitingresponse || (isEditCA && !isCaUninitialized && cmscainfo == null);
    }

    public boolean isWaitingForResponse() {
        return this.waitingresponse;
    }

    public boolean isRenderViewCmsCert() {
        return isEditCA && !isCaUninitialized && cmscert != null;
    }

    public boolean isRenderCaLifeCycle() {
        return isEditCA && isHasEditRight() && revokable;
    }

    public List<SelectItem> getRevokeReasonList() {
        return Arrays.stream(RevocationReasons.values())
                .filter(reason -> reason != RevocationReasons.CERTIFICATEHOLD)
                .filter(reason -> reason != RevocationReasons.REMOVEFROMCRL)
                .filter(reason -> reason != RevocationReasons.NOT_REVOKED)
                .map(reason -> new SelectItem(reason.getDatabaseValue(), reason.getHumanReadable()))
                .collect(Collectors.toList());
    }

    public int getCaRevokeReason() {
        return caRevokeReason;
    }

    public void setCaRevokeReason(final int caRevokeReason) {
        this.caRevokeReason = caRevokeReason;
    }

    public List<SelectItem> getExtrAndCertSignKeyReNewList() {
        final List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(StringUtils.EMPTY, getEjbcaWebBean().getText("RENEWCA_USINGKEYSEQUENCE")));
        for (final String alias : availableCryptoTokenKeyAliases) {
            resultList.add(new SelectItem(alias, alias, ""));
        }
        return resultList;
    }

    public List<SelectItem> getCertSignKeyRecieveReqList() {
        final List<SelectItem> resultList = new ArrayList<>();
        for (final String alias : availableCryptoTokenKeyAliases) {
            resultList.add(new SelectItem(alias, alias, ""));
        }
        return resultList;
    }

    public String getCertSignKeyReNewValue() {
        return this.certSignKeyReNewValue;
    }

    public void setCertSignKeyReNewValue(final String certSignKeyReNewValue) {
        this.certSignKeyReNewValue = certSignKeyReNewValue;
    }

    public String getCertSignKeyRecieveReqValue() {
        return this.certSignKeyRequestValue;
    }

    public void setCertSignKeyRecieveReqValue(final String certSignKeyRequestValue) {
        this.certSignKeyRequestValue = certSignKeyRequestValue;
    }

    public String getExtrCertSignKeyReNewValue() {
        return this.certExtrSignKeyReNewValue;
    }

    public void setExtrCertSignKeyReNewValue(final String certExtrSignKeyReNewValue) {
        this.certExtrSignKeyReNewValue = certExtrSignKeyReNewValue;
    }

    public boolean isRenderUseCaNameChange() {
        if (cainfo != null) {
            return caInfoDto.isCaTypeX509() && cainfo.getSignedBy() == CAInfo.SELFSIGNED && globalconfiguration.getEnableIcaoCANameChange();
        }
        return false;
    }

    public String getNewSubjectDNValue() {
        if (cainfo != null) {
            return cainfo.getSubjectDN();
        }
        return StringUtils.EMPTY;
    }

    public String getBinaryCaIdLink() {
        return EditCaUtil.LINK_CERT_BASE_URI + "format=binary&caid=" + caid;
    }

    public String getCaIdLink() {
        return EditCaUtil.LINK_CERT_BASE_URI + "caid=" + caid;
    }

    public boolean isRenderLinkCertificate() {
        return hasLinkCertificate;
    }

    public boolean isRollOverDate() {
        return rolloverNotBefore != null;
    }

    public String getCaNotAfter() {
        return caCertNotAfter != null ? getEjbcaWebBean().formatAsISO8601(caCertNotAfter) : StringUtils.EMPTY;
    }

    public String getCaRollOverNotBefore() {
        return rolloverNotBefore != null ? getEjbcaWebBean().formatAsISO8601(rolloverNotBefore) : StringUtils.EMPTY;
    }
    public String getCaRollOverNotAfter() {
        return rolloverNotAfter != null ? getEjbcaWebBean().formatAsISO8601(rolloverNotAfter) : StringUtils.EMPTY;
    }

    public String getConfirmRolloverDate() {
        final Date now = new Date();
        if (rolloverNotBefore != null) {
            return rolloverNotBefore.after(now) ? " onclick=\"return confirm('Next certificate is not yet valid! Are you sure?')\"" : StringUtils.EMPTY;
        }
        return StringUtils.EMPTY;
    }

    public boolean isRenderRepublishCA() {
        return isEditCA && !isCaexternal && !waitingresponse && isHasEditRight();
    }

    public boolean isCheckBoxFutureRollOver() {
        return checkBoxFutureRollOver;
    }

    public void setCheckBoxFutureRollOver(final boolean checkBoxFutureRollOver) {
        this.checkBoxFutureRollOver = checkBoxFutureRollOver;
    }

    public boolean isRenderFutureRollOver() {
        return caInfoDto.isCaTypeX509() && !isWaitingForResponse();
    }

    public boolean isCaExportable() {
        return caBean.isCaExportable(cainfo);
    }

    public boolean isEditCANotUninitializedNotExternal() {
        return isEditCA && !isCaUninitialized && !isCaexternal;
    }

    public List<SelectItem> getAvailableSigningAlgList() {
        final List<SelectItem> resultList = new ArrayList<>();
        for (final String current : AlgorithmConstants.AVAILABLE_SIGALGS) {
            if (!AlgorithmTools.isSigAlgEnabled(current)) {
                continue; // e.g. GOST3410 if not configured
            }
            resultList.add(new SelectItem(current, current, ""));
        }
        return resultList;
    }

    public boolean isCryptoTokenSuitable() {
        return suitableCryptoTokenExists;
    }

    public List<SelectItem> getAvailableCryptoTokenList() {
        return availableCryptoTokenSelectItems;
    }

    public boolean isCryptoTokenNeedExistingOrGen() {
        return (isCryptoTokenIdParamNull() && !isCaUninitialized);
    }

    public boolean isCryptoTokenIdParamNull() {
        return caInfoDto.getCryptoTokenIdParam() == null;
    }

    public boolean isCryptoTokenIdParamNotNull() {
        return caInfoDto.getCryptoTokenIdParam() != null;
    }

    public boolean isFailedCryptoTokenExist() {
        return failedCryptoTokenLinkMap != null && !failedCryptoTokenLinkMap.isEmpty();
    }

    public Map<String, String> failedCryptoTokenLinkMap() {
        return failedCryptoTokenLinkMap;
    }


    public String getCryptoTokenIdParam() {
        return caInfoDto.getCryptoTokenIdParam();
    }

    public void setCryptoTokenIdParam(final String cryptoTokenIdParam) {
        caInfoDto.setCryptoTokenIdParam(cryptoTokenIdParam);
        // Create already in use key map
        if (!isEditCA || isCaUninitialized) {
            updateKeyAliases();
        }
    }

    private void setDefaultKeyAliases() {
        // Make up defaults based on key alias names
        caInfoDto.setSelectedKeyEncryptKey("");
        caInfoDto.setTestKey("");

        for (final String alias : availableCryptoTokenEncryptionAliases) {
            if (CAToken.SOFTPRIVATEDECKEYALIAS.equals(alias) || StringUtils.containsIgnoreCase(alias, "default")) {
                caInfoDto.setCryptoTokenDefaultKey(alias);
            } else if (CAToken.SOFTPRIVATESIGNKEYALIAS.equals(alias) || StringUtils.containsIgnoreCase(alias, "sign")) {
                caInfoDto.setCryptoTokenCertSignKey(alias);
            } else if (StringUtils.containsIgnoreCase(alias, "test")) {
                caInfoDto.setTestKey(alias);
            }
        }

        for (final String alias : availableCryptoTokenKeyAliases) {
            if (CAToken.SOFTPRIVATEDECKEYALIAS.equals(alias) || StringUtils.containsIgnoreCase(alias, "default")) {
                caInfoDto.setCryptoTokenDefaultKey(alias);
            } else if (CAToken.SOFTPRIVATESIGNKEYALIAS.equals(alias) || StringUtils.containsIgnoreCase(alias, "sign"))  {
                caInfoDto.setCryptoTokenCertSignKey(alias);
            } else if (StringUtils.containsIgnoreCase(alias, "test")) {
                caInfoDto.setTestKey(alias);
            }
        }
    }

    private void setKeyAliasesFromCa() throws CryptoTokenOfflineException {
        caInfoDto.setCryptoTokenDefaultKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_DEFAULT));
        caInfoDto.setCryptoTokenCertSignKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        caInfoDto.setSelectedKeyEncryptKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
        caInfoDto.setTestKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYTEST));
        // For renewal
        certSignKeyRequestValue = catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        certExtrSignKeyReNewValue = catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        certSignKeyReNewValue = catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
    }

    public List<SelectItem> getKeyAliasesList(final String keyType) {
        final List<SelectItem> resultList = new ArrayList<>();
        switch (keyType) {
        case "defaultKey":
            for (final String alias : availableCryptoTokenMixedAliases) {
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
            return resultList;
        case "certSignKey":
        case "testKey":
            for (final String alias : availableCryptoTokenKeyAliases) {
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
            return resultList;
        case "keyEncryptKey":
            for (final String alias : availableCryptoTokenEncryptionAliases) {
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
            return resultList;
        default:
            return Collections.emptyList();
        }
    }

    public List<SelectItem> getKeyAliasesListWithDefault(final String keyType) {
        final List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(StringUtils.EMPTY, getEjbcaWebBean().getText("CRYPTOTOKEN_DEFAULTKEY")));
        resultList.addAll(getKeyAliasesList(keyType));
        return resultList;
    }

    public List<SelectItem> getExTServicesKeySpecList() {
        return caBean.getAvailableKeySpecs()
                .stream()
                .sorted(Entry.comparingByValue())
                .map(e -> new SelectItem(e.getKey(), e.getValue()))
                .collect(Collectors.toList());
    }

    public String getSelectedCryptoTokenDefaultKey() {
        return caInfoDto.getCryptoTokenDefaultKey();
    }

    public void setSelectedCryptoTokenDefaultKey(final String selectedCryptoTokenDefaultKey) {
        caInfoDto.setCryptoTokenDefaultKey(StringUtils.defaultString(selectedCryptoTokenDefaultKey));
    }

    public boolean isRenderCreateCaTokenKeys() {
        if (!isEditCA || isCaUninitialized) {
            return (!isCryptoTokenIdParamNull() && !caInfoDto.getCryptoTokenIdParam().isEmpty() && Integer.parseInt(caInfoDto.getCryptoTokenIdParam()) != 0);
        }
        return false;
    }

    public String getSelectedCryptoTokenCertSignKey() {
        return caInfoDto.getCryptoTokenCertSignKey();
    }

    public void setSelectedCryptoTokenCertSignKey(final String selectedCryptoTokenCertSignKey) {
        caInfoDto.setCryptoTokenCertSignKey(StringUtils.defaultString(selectedCryptoTokenCertSignKey));
    }

    public String getSelectedKeyEncryptKey() {
        return caInfoDto.getSelectedKeyEncryptKey();
    }

    public void setSelectedKeyEncryptKey(final String selectedKeyEncryptKey) {
        caInfoDto.setSelectedKeyEncryptKey(StringUtils.defaultString(selectedKeyEncryptKey));
    }

    public String getSelectTestKey() {
        return caInfoDto.getTestKey();
    }

    public void setSelectTestKey(final String testKey) {
        caInfoDto.setTestKey(StringUtils.defaultString(testKey));
    }

    public String getCertificateValidityHelp() {
        return getEjbcaWebBean().getText("DATE_HELP") + "=" + getEjbcaWebBean().getDateExample() + "." + getEjbcaWebBean().getText("YEAR365DAYS")
                + ", " + getEjbcaWebBean().getText("MO30DAYS");
    }

    public boolean isRenderSaveExternalCa() {
        return caInfoDto.isCaTypeX509() && isHasEditRight();
    }

    public String getCmsCertLink() throws UnsupportedEncodingException {
        if (cmscert != null) {
            return viewCertLink + "?certsernoparameter="
                    + java.net.URLEncoder.encode(cmscert.getSerialNumber().toString(16) + "," + CertTools.getIssuerDN(cmscert), "UTF-8");
        }
        return StringUtils.EMPTY;
    }

    public boolean isRenderRenewCA() {
        final int cryptoTokenId = catoken == null ? currentCryptoTokenId : catoken.getCryptoTokenId();
        try {
            return isEditCA && !isCaexternal && !waitingresponse &&
                    cryptoTokenManagementSession.isCryptoTokenPresent(getAdmin(), cryptoTokenId) &&
                    cryptoTokenManagementSession.isCryptoTokenStatusActive(getAdmin(), cryptoTokenId) &&
                    cainfo.getSignedBy()!=CAInfo.SIGNEDBYEXTERNALCA && !isCaRevoked;
        } catch (final AuthorizationDeniedException e) {
            log.error("Error while accessing ca bean!", e);
        }
        return false;
    }

    public boolean isRenderSelectCertificateProfile() {
        return !isEditCA || isCaUninitialized;
    }

    public boolean isRenderOcspPreProduction() {
        return getEjbcaWebBean().isRunningEnterprise();
    }

    public String getCaCertLink() {
        return viewCertLink + "?caid=" + caid;
    }

    public boolean isEditCaUninitializedHasEditRights() {
        return isEditCA && isCaUninitialized && isHasEditRight();
    }

    public boolean isEditCaNotUninitializedHasEditRights() {
        return isEditCA && !isCaUninitialized && isHasEditRight();
    }

    public boolean isCheckboxAcceptRevocationsNonExistingEntryDisabled() {
        return (!isHasEditRight() || caInfoDto.isUseCertificateStorage());
    }

    public boolean isCertificateProfileForNonExistingDisabled(){
        return (!isHasEditRight() || caInfoDto.isUseCertificateStorage() || !caInfoDto.isAcceptRevocationsNonExistingEntry());
    }

    public List<SelectItem> getThrowAwayDefaultProfileList() {
        final List<SelectItem> resultList = new ArrayList<>();
        for (final String profilename : certProfilesOfEndEntityType.keySet()) {
            final int certprofid = certProfilesOfEndEntityType.get(profilename);
            resultList.add(new SelectItem(certprofid, profilename, "", isCertificateProfileForNonExistingDisabled()));
        }
        return resultList;
    }

    public boolean isRenderCvcAvailable() {
        return (caInfoDto.getCaType() == CAInfo.CATYPE_CVC) && (!isCvcAvailable || isUniqueIssuerDnSerialNoIndexPresent);
    }

    public boolean isRenderSshAvailable() {
        return CAFactory.INSTANCE.existsCaType(SshCa.CA_TYPE);
    }

    public boolean isCvcAvailable() {
        return isCvcAvailable;
    }


    public boolean isRenderExternallySignedCaCreationRenewal() {
        final int cryptoTokenId = catoken == null ? currentCryptoTokenId : catoken.getCryptoTokenId();
        try {
            return !isCaexternal && cryptoTokenManagementSession.isCryptoTokenPresent(getAdmin(), cryptoTokenId) &&
                    cryptoTokenManagementSession.isCryptoTokenStatusActive(getAdmin(), cryptoTokenId) &&
                    isHasEditRight();
        } catch (final AuthorizationDeniedException e) {
            log.error("Error calling ca bean!", e);
        }
        return false;
    }

    public UploadedFile getFileRecieveFileRecieveRequest() {
        return fileRecieveFileRecieveRequest;
    }

    public void setFileRecieveFileRecieveRequest(final UploadedFile fileRecieveFileRecieveRequest) {
        this.fileRecieveFileRecieveRequest = fileRecieveFileRecieveRequest;
    }

    public boolean isSignedByExternal() {
        return caInfoDto.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA;
    }

    public void resetSignedBy() {
        caInfoDto.setSignedBy(CAInfo.SELFSIGNED);
    }

    public boolean isCreateLinkCertificate() {
        return createLinkCertificate;
    }

    public void setCreateLinkCertificate(final boolean createLinkCertificate) {
        this.createLinkCertificate = createLinkCertificate;
    }

    public void resetCryptoTokenParam() {
        caInfoDto.setCryptoTokenIdParam(StringUtils.EMPTY);
        updateAvailableCryptoTokenList();
    }

    // ===================================================== Create CA Actions ============================================= //

    /**
     * Ca creation button pressed
     * @return Navigation
     */
    public String createCa() {
        return createCaOrMakeRequest(true, false); // We are creating a ca!
    }

    /**
     * This one used by both edit and create ca pages.
     * @return Navigation
     */
    public String makeRequest() {
        if (isEditCA) {
            return makeRequestEditCa();
        }
        return createCaOrMakeRequest(false, true); // We are making a request!
    }

    public String cancel() {
        return EditCaUtil.MANAGE_CA_NAV;
    }

    // ======================================= Helpers ===================================================================//
    private String createCaOrMakeRequest(final boolean createCa, final boolean makeRequest) {
        boolean illegalDnOrAltName;

        if (makeRequest) {
            final byte[] fileBuffer = EditCaUtil.getUploadedFileBuffer(fileRecieveFileMakeRequest);
            try {
                illegalDnOrAltName = saveOrCreateCaInternal(createCa, makeRequest, fileBuffer);
                if (illegalDnOrAltName) {
                    addErrorMessage("INVALIDSUBJECTDN");
                }
            } catch (final Exception e) {
                addNonTranslatedErrorMessage(e);
                return "";
            }
        } else {
            try {
                illegalDnOrAltName = saveOrCreateCaInternal(createCa, makeRequest, null);
                if (illegalDnOrAltName) {
                    addErrorMessage("INVALIDSUBJECTDN");
                }
            } catch (final Exception e) {
                addNonTranslatedErrorMessage(e);
                return "";
            }
        }

        final long crlperiod = SimpleTime.getInstance(caInfoDto.getCrlCaCrlPeriod(), "0" + SimpleTime.TYPE_MINUTES).getLong();

        if (caInfoDto.isCaTypeX509() && crlperiod != 0 && !illegalDnOrAltName && createCa) {
            return EditCaUtil.MANAGE_CA_NAV;
        }
        if (caInfoDto.getCaType() == CAInfo.CATYPE_CVC && !illegalDnOrAltName && createCa) {
            caid = CertTools.stringToBCDNString(caInfoDto.getCaSubjectDN()).hashCode();
            return EditCaUtil.MANAGE_CA_NAV;
        }

        if (makeRequest && !illegalDnOrAltName) {
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("caname", caInfoDto.getCaName());
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("filemode", EditCaUtil.CERTREQGENMODE);
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put(SESSION.CA_INTERFACE_BEAN, caBean);
            return EditCaUtil.DISPLAY_RESULT_NAV;
        }
        return EditCaUtil.MANAGE_CA_NAV;
    }

    private boolean saveOrCreateCaInternal(final boolean createCa, final boolean makeRequest, final byte[] fileBuffer)
            throws Exception {
       return caBean.actionCreateCaMakeRequest(caInfoDto, getApprovals(), getAvailablePublisherValues(),
                    getAvailableKeyValidatorValues(), createCa, makeRequest, fileBuffer);
    }

    // ===================================================== Create CA Actions ============================================= //
    // ===================================================== Edit CA Actions =============================================== //


    /**
     * Renew and revoke a CMS certificate
     *
     * @return Navigates back to manage ca page if successful
     */
    public String renewAndRevokeCmsCertificate() {
        try {
            caAdminSession.renewAndRevokeCmsCertificate(getAdmin(), caid);
            addInfoMessage(getEjbcaWebBean().getText("CMSCERTIFICATERENEWED"));
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (CADoesntExistsException | CAOfflineException | CertificateRevokeException | AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    /**
     * Renews a ca
     * @return navigates back to manage ca page if successful.
     */
    public String renewCa() {
        try {
            if (caSession.getCAInfo(getAdmin(), caid).getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
                addNonTranslatedErrorMessage("Cannot renew an externally signed CA."); // Button should not even be available in this case
                return "";
            }
            if (cANameChange && newSubjectDn != null && !newSubjectDn.isEmpty()) {
                cadatahandler.renewAndRenameCA(caid, certSignKeyReNewValue, createLinkCertificate, newSubjectDn);
            } else {
                cadatahandler.renewCA(caid, certSignKeyReNewValue, createLinkCertificate);
            }
            addInfoMessage(getEjbcaWebBean().getText("CARENEWED"));
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (final Exception e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    /**
     * Revoke a ca (in editca page) and navigates back to the managecas.xhtml
     * @return navigation
     */
    public String revokeCa() {
        try {
            caAdminSession.revokeCA(getAdmin(), caid, caRevokeReason);
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (CADoesntExistsException | AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    /**
     * Saves external ca (in edit ca page) and navigates back to managecas.xhtml
     * @return Navigation
     */
    public String saveExternalCA() {
        if (caInfoDto.getCaType()==CAInfo.CATYPE_X509) {
            final X509CAInfo x509caInfo = (X509CAInfo)cainfo;
            x509caInfo.setExternalCdp(crlCaCRLDPExternal.trim());
            x509caInfo.setDoPreProduceOcspResponses(caInfoDto.isDoPreProduceOcspResponses());
            x509caInfo.setDoStoreOcspResponsesOnDemand(caInfoDto.isDoStoreOcspResponsesOnDemand());
            return saveCaInternal(x509caInfo);
        }
        return "";
    }

    /**
     * Initialize a ca (in editca page) and navigates back to managecas.xhtml if successful.
     * The CA status is set to active and certificates are generated.
     * @return Navigation
     */
    public String initializeCa() {
        try {
            final CAInfo cainfo = getCaInfo();
            final int certprofileid = (caInfoDto.getCurrentCertProfile() == null ? 0 : Integer.parseInt(caInfoDto.getCurrentCertProfile()));
            cainfo.setSignedBy(caInfoDto.getSignedBy());
            cainfo.setCertificateProfileId(certprofileid);
            cainfo.setDefaultCertificateProfileId(caInfoDto.getDefaultCertProfileId());
            cainfo.setUseNoConflictCertificateData(caInfoDto.isUseNoConflictCertificateData());
            CAInfo oldinfo = caSession.getCAInfo(getAdmin(), cainfo.getCAId());
            cainfo.setName(oldinfo.getName());
            caAdminSession.initializeCa(getAdmin(), cainfo);
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (CryptoTokenOfflineException | InvalidAlgorithmException |
                NumberFormatException | AuthorizationDeniedException | InternalKeyBindingNonceConflictException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    /**
     * Save changes in the ca (in editca page) and navigates back to managecas.xhtml if successful.
     * @return Navigation
     */
    public String saveCa() {
        try {
            final CAInfo caInfo = getCaInfo();
            if (caInfo == null) {
                // Error already added by getCaInfo
                return "";
            }
            return saveCaInternal(caInfo);
        } catch (NumberFormatException | AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    /**
     * Republishs a ca and navigates back to manageca page with the result if successful.
     * @return Navigation
     */
    public String publishCA() {
        try {
            caAdminSession.publishCA(getAdmin(), caid);
            addInfoMessage(getEjbcaWebBean().getText("CACERTPUBLISHINGQUEUED"));
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    /**
     * Rollovers a ca and navigates back to manageca page if successful.
     *
     * @return Navigation
     */
    public String rolloverCA() {
        try {
            caAdminSession.rolloverCA(getAdmin(), caid);
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    /**
     * Receives a request (in editcas page) and navigates to managecas.xhtml page
     * @return Navigation
     */
    public String receiveResponse() {
        final byte[] fileBuffer = EditCaUtil.getUploadedFileBuffer(fileRecieveFileRecieveRequest);
        try {
            cadatahandler.receiveResponse(caid, fileBuffer, certSignKeyRequestValue, checkBoxFutureRollOver);
            try {
                rolloverNotBefore = caBean.getRolloverNotBefore(caid);
                rolloverNotAfter = caBean.getRolloverNotAfter(caid);
                caCertNotAfter = caBean.getCANotAfter(caid);
            } catch (CADoesntExistsException | AuthorizationDeniedException e) {
                log.warn("Failed to get CA notAfter and/or rollover date", e);
            }
            if (rolloverNotBefore != null) {
                addInfoMessage(getEjbcaWebBean().getText("CAROLLOVERPENDING") + getEjbcaWebBean().formatAsISO8601(rolloverNotBefore));
            } else {
                addInfoMessage(getEjbcaWebBean().getText("CAACTIVATED"));
            }
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (final Exception e) {
            log.debug("Error occurred while receiving response", e);
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    /**
     * Imports CA certificate and navigates back to the manage CA page with results.
     * @return Navigation
     */
    public String importCACertUpdate() {
        final byte[] fileBuffer = EditCaUtil.getUploadedFileBuffer(fileRecieveFileImportRenewal);

        if (fileBuffer==null) {
           addNonTranslatedErrorMessage("No file selected or upload failed");
           return "";
        }

        try {
            cadatahandler.importCACertUpdate(caid, fileBuffer);
            addInfoMessage(getEjbcaWebBean().getText("CARENEWED"));
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (final Exception e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    /**
     * Exports the current ca crypto token if allowed be the configuration.
     */
    public void exportCA() {
        try {
            FacesContext ctx = FacesContext.getCurrentInstance();
            ExternalContext ectx = ctx.getExternalContext();
            HttpServletRequest request = (HttpServletRequest) ectx.getRequest();

            //Try the password before moving on in order to verify
            CAToken caToken = caSession.getCAInfoInternal(getCaid()).getCAToken();
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(caToken.getCryptoTokenId());
            try {
                 ((SoftCryptoToken) cryptoToken).checkPasswordBeforeExport(request.getParameter(getTextFieldExportCaPassword()).toCharArray());
            } catch (CryptoTokenAuthenticationFailedException | CryptoTokenOfflineException | PrivateKeyNotExtractableException e) {
                addNonTranslatedErrorMessage(e.getLocalizedMessage());
                return;
            }

            HttpServletResponse response = (HttpServletResponse) ectx.getResponse();
            RequestDispatcher dispatcher = request.getRequestDispatcher(EditCaUtil.CA_EXPORT_PATH);
            request.setAttribute(REQUEST.AUTHENTICATION_TOKEN, getAdmin());
            dispatcher.forward(request, response);
            ctx.responseComplete();
        } catch (ServletException | IOException ex) {
            log.info("Error happened while trying to forward the request to ca export servlet!", ex);
        }

    }

    /**
     * Small utility function to return the current ca name used in export ca part of edit ca page.
     */
    public String getCaName() {
        return cainfo.getName();
    }

    /**
     * Returns the text field name of the export ca password field.
     */
    public String getTextFieldExportCaPassword() {
        return EditCaUtil.TEXTFIELD_EXPORTCA_PASSWORD;
    }

    /**
     * Returns the hidden ca name used in export ca function in edit ca page.
     */
    public String getHiddenCaName() {
        return EditCaUtil.HIDDEN_CANAME;
    }

    // ======================================= Helpers ===================================================================//

    private String makeRequestEditCa() {
        try {
            getCaInfo();
        } catch (NumberFormatException | AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
        final byte[] fileBuffer = EditCaUtil.getUploadedFileBuffer(fileRecieveFileMakeRequest);

        byte[] certreq;
        try {
            certreq = cadatahandler.makeRequest(caid, fileBuffer, this.certExtrSignKeyReNewValue);
        } catch (CADoesntExistsException | CryptoTokenOfflineException | AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
        caBean.saveRequestData(certreq);

        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("caname", editCaName);
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("filemode", EditCaUtil.CERTREQGENMODE);
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put(SESSION.CA_INTERFACE_BEAN, caBean);

        return EditCaUtil.DISPLAY_RESULT_NAV;
    }

    private String saveCaInternal(final CAInfo cainfo) {
        try {
            caAdminSession.editCA(getAdmin(), cainfo);
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (AuthorizationDeniedException | CmsCertificatePathMissingException | InternalKeyBindingNonceConflictException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    private CAInfo getCaInfo() throws NumberFormatException, AuthorizationDeniedException {
        CAInfo cainfo;

        //External CAs do not require a validity to be set
        if (caInfoDto.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
            caInfoDto.setCaEncodedValidity(null);
        }

        try {
            cainfo = caBean.createCaInfo(caInfoDto, caid, getSubjectDn(), getApprovals(),
                    getAvailablePublisherValues(), getAvailableKeyValidatorValues());
        } catch (final Exception e) {
            addNonTranslatedErrorMessage(e);
            return null;
        }

        if (caSession.getCAInfo(getAdmin(), caid).getStatus() == CAConstants.CA_UNINITIALIZED) {
            // Allow changing of subjectDN etc. for uninitialized CAs
            cainfo.setSubjectDN(getSubjectDn());

            // We can only update the CAToken properties if we have selected a valid cryptotoken
            if (!StringUtils.isEmpty(caInfoDto.getCryptoTokenIdParam())) {
                final int cryptoTokenId = Integer.parseInt(caInfoDto.getCryptoTokenIdParam());

                final Properties caTokenProperties = new Properties();
                caTokenProperties.putAll(cainfo.getCAToken().getProperties());
                caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, caInfoDto.getCryptoTokenDefaultKey());
                if (caInfoDto.getCryptoTokenCertSignKey().length() > 0) {
                    caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, caInfoDto.getCryptoTokenCertSignKey());
                    caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, caInfoDto.getCryptoTokenCertSignKey());
                }
                if (caInfoDto.getSelectedKeyEncryptKey().length() > 0) {
                    caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, caInfoDto.getSelectedKeyEncryptKey());
                }
                if (caInfoDto.getTestKey().length() > 0) {
                    caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, caInfoDto.getTestKey());
                }

                final CAToken newCAToken = new CAToken(cryptoTokenId, caTokenProperties);
                newCAToken.setSignatureAlgorithm(caInfoDto.getSignatureAlgorithmParam());
                newCAToken.setEncryptionAlgorithm(cainfo.getCAToken().getEncryptionAlgorithm());
                newCAToken.setKeySequence(cainfo.getCAToken().getKeySequence());
                newCAToken.setKeySequenceFormat(cainfo.getCAToken().getKeySequenceFormat());
                cainfo.setCAToken(newCAToken);
            }

            final int certprofileid = caInfoDto.getCurrentCertProfileAsInteger();
            if (caInfoDto.getSignedBy() == caid) {
                caInfoDto.setSignedBy(CAInfo.SELFSIGNED);
            }
            cainfo.setCertificateProfileId(certprofileid);
            cainfo.setDefaultCertificateProfileId(caInfoDto.getDefaultCertProfileId());
            cainfo.setUseNoConflictCertificateData(caInfoDto.isUseNoConflictCertificateData());
            cainfo.setSignedBy(caInfoDto.getSignedBy());

            List<CertificatePolicy> policies = null;
            if (cainfo instanceof X509CAInfo) {
                policies = caBean.parsePolicies(caInfoDto.getPolicyId());
            }

            List<ExtendedCAServiceInfo> extendedCaServices;
            if (cainfo instanceof X509CAInfo) {
                final X509CAInfo x509cainfo = (X509CAInfo) cainfo;
                final String signkeyspec = caInfoDto.getSignKeySpec() != null ? caInfoDto.getSignKeySpec() : EditCaUtil.DEFAULT_KEY_SIZE;
                extendedCaServices = caBean.makeExtendedServicesInfos(signkeyspec, cainfo.getSubjectDN(), caInfoDto.isServiceCmsActive());
                x509cainfo.setExtendedCAServiceInfos(extendedCaServices);
                x509cainfo.setSubjectAltName(caInfoDto.getCaSubjectAltName());
                x509cainfo.setPolicies(policies);
            }
        }
        return cainfo;
    }

    // ===================================================== Edit CA Actions ============================================= //


    // ===================================================== Other helpers   ============================================= //

    private Map<ApprovalRequestType, Integer> getApprovals() {
        final Map<ApprovalRequestType, Integer> approvals = new LinkedHashMap<>();
        if (approvalRequestItems != null && !approvalRequestItems.isEmpty()) {
            for (final ApprovalRequestItem approvalRequestItem : approvalRequestItems) {
                approvals.put(approvalRequestItem.getRequestType(), approvalRequestItem.getApprovalProfileId());
            }
        }
        return approvals;
    }

    private String getAvailablePublisherValues() {
        String availablePublisherValues = null;
        if (usedCrlPublishers != null && !usedCrlPublishers.isEmpty()) {
            availablePublisherValues = StringUtils.join(this.usedCrlPublishers.toArray(), ";");
        }
        return availablePublisherValues;
    }

    private String getAvailableKeyValidatorValues() {
        String availableKeyValidatorValues = null;
        if (usedValidators != null && !usedValidators.isEmpty()) {
            availableKeyValidatorValues = StringUtils.join(usedValidators.toArray(), ";");
       }
        return availableKeyValidatorValues;
    }

    private String getSubjectDn() {
        return caInfoDto.getCaSubjectDN();
    }

    private boolean isViewOnly() {
        boolean onlyView = false;
        if (getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource())
                || getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAVIEW.resource())) {
            onlyView = !getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource())
                    && getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAVIEW.resource());
        }
        return onlyView;
    }

    private void initCreateCaPage() {
        // Defaults in the create CA page
        if (StringUtils.isEmpty(caInfoDto.getSignatureAlgorithmParam())) {
            caInfoDto.setSignatureAlgorithmParam(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        }
        if (isCaexternal) {
            caInfoDto.setDescription(cainfo.getDescription());
        }

        if (isCryptoTokenIdParamNotNull() && caInfoDto.getCryptoTokenIdParam().length() > 0 && Integer.parseInt(caInfoDto.getCryptoTokenIdParam()) != 0) {
            currentCryptoTokenId = Integer.parseInt(caInfoDto.getCryptoTokenIdParam());
        }

        caInfoDto.setCaSubjectDN("CN=" + caInfoDto.getCaName());


        if (isCaUninitialized && caInfoDto.isCaTypeX509()) {
            String policies = "";
            final X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            final List<CertificatePolicy> list = x509cainfo.getPolicies();
            final CertificatePolicy cp = (list != null && !list.isEmpty()) ? list.get(0) : null;
            if (cp != null) {
                policies += cp.getPolicyID();
                if (cp.getQualifier() != null) {
                    policies += " "+cp.getQualifier();
                }
            }
            caInfoDto.setPolicyId(policies);
            caInfoDto.setCaSubjectAltName(x509cainfo.getSubjectAltName());
        }

        if (caInfoDto.isCaTypeX509()) {
            final X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            if(x509cainfo != null) {
                final List<String> uris = x509cainfo.getAuthorityInformationAccess();
                caInfoDto.setAuthorityInformationAccess(null != uris ? StringUtils.join(uris, ";") : "");
            }
        }

        if (isCaexternal) {
            caInfoDto.setCrlCaCrlPeriod(SimpleTime.getInstance(cainfo.getCRLPeriod()).toString(SimpleTime.TYPE_MINUTES));
            caInfoDto.setCrlCaIssueInterval(SimpleTime.getInstance(cainfo.getCRLIssueInterval()).toString(SimpleTime.TYPE_MINUTES));
            caInfoDto.setCrlCaOverlapTime(SimpleTime.getInstance(cainfo.getCRLOverlapTime()).toString(SimpleTime.TYPE_MINUTES));
            caInfoDto.setCrlCaDeltaCrlPeriod(SimpleTime.getInstance(cainfo.getDeltaCRLPeriod()).toString(SimpleTime.TYPE_MINUTES));
        } else {
            caInfoDto.setCrlCaCrlPeriod("1" + SimpleTime.TYPE_DAYS);
            caInfoDto.setCrlCaIssueInterval("0" + SimpleTime.TYPE_MINUTES);
            caInfoDto.setCrlCaOverlapTime("10" + SimpleTime.TYPE_MINUTES);
            caInfoDto.setCrlCaDeltaCrlPeriod("0" + SimpleTime.TYPE_MINUTES);
        }

        caInfoDto.setSignedBy(CAInfo.SELFSIGNED);
        caInfoDto.setCaSerialNumberOctetSize(String.valueOf(CesecoreConfiguration.getSerialNumberOctetSizeForNewCa()));
        usedValidators = new ArrayList<>();

        updateAvailableCryptoTokenList();
    }

    private void initEditCaPage() {

        catoken = cainfo.getCAToken();
        keyValidatorMap = keyValidatorSession.getKeyValidatorIdToNameMap(cainfo.getCAType());
        if (StringUtils.isEmpty(caInfoDto.getSignatureAlgorithmParam())) {
            caInfoDto.setSignatureAlgorithmParam(catoken.getSignatureAlgorithm());
        }
        signbyexternal = cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA;
        isCaexternal = cainfo.getStatus() == CAConstants.CA_EXTERNAL;
        isCaRevoked = cainfo.getStatus() == CAConstants.CA_REVOKED || RevokedCertInfo.isRevoked(cainfo.getRevocationReason());
        revokable = cainfo.getStatus() != CAConstants.CA_REVOKED && cainfo.getStatus() != CAConstants.CA_WAITING_CERTIFICATE_RESPONSE
                && cainfo.getStatus() != CAConstants.CA_EXTERNAL && !RevokedCertInfo.isPermanentlyRevoked(cainfo.getRevocationReason());
        waitingresponse = cainfo.getStatus() == CAConstants.CA_WAITING_CERTIFICATE_RESPONSE;
        isCaUninitialized = cainfo.getStatus() == CAConstants.CA_UNINITIALIZED;
        caInfoDto.setCaType(cainfo.getCAType());
        caInfoDto.setKeySequenceFormat(cainfo.getCAToken().getKeySequenceFormat());

        if (!isCaexternal) {
            for (final ExtendedCAServiceInfo extendedCAServiceInfo : cainfo.getExtendedCAServiceInfos()) {
                if (extendedCAServiceInfo instanceof CmsCAServiceInfo) {
                    cmscainfo = (CmsCAServiceInfo) extendedCAServiceInfo;
                    if (cmscainfo.getCertificatePath() != null) {
                        cmscert = (java.security.cert.X509Certificate) cmscainfo.getCertificatePath().get(0);
                    }
                }

                if (extendedServicesKeySpecParam == null && extendedCAServiceInfo instanceof BaseSigningCAServiceInfo) {
                    extendedServicesKeySpecParam = ((BaseSigningCAServiceInfo) extendedCAServiceInfo).getKeySpec();
                }
            }
        }

        caInfoDto.setDescription(cainfo.getDescription());
        caInfoDto.setDoEnforceUniquePublickeys(cainfo.isDoEnforceUniquePublicKeys());
        caInfoDto.setDoEnforceKeyRenewal(cainfo.isDoEnforceKeyRenewal());
        caInfoDto.setDoEnforceUniqueDN(cainfo.isDoEnforceUniqueDistinguishedName());
        caInfoDto.setDoEnforceUniqueSubjectDNSerialnumber(cainfo.isDoEnforceUniqueSubjectDNSerialnumber());
        caInfoDto.setUseCertificateStorage(cainfo.isUseCertificateStorage());
        caInfoDto.setAcceptRevocationsNonExistingEntry(cainfo.isAcceptRevocationNonExistingEntry());
        caInfoDto.setDefaultCertificateProfile(String.valueOf(cainfo.getDefaultCertificateProfileId()));
        caInfoDto.setUseNoConflictCertificateData(cainfo.isUseNoConflictCertificateData());

        if (isCaUninitialized) {
            caInfoDto.setCurrentCertProfile(String.valueOf(cainfo.getCertificateProfileId()));
        } else {
            if (cainfo.getCertificateProfileId() != 0) {
                caInfoDto.setCurrentCertProfile(certificateProfileSession.getCertificateProfileName(cainfo.getCertificateProfileId()));
            } else {
                caInfoDto.setCurrentCertProfile(getEjbcaWebBean().getText("NOTUSED"));
            }
        }

        currentCryptoTokenId = catoken.getCryptoTokenId();
        caInfoDto.setCryptoTokenIdParam(String.valueOf(catoken.getCryptoTokenId()));

        if (cainfo.getSignedBy() >= 0 && cainfo.getSignedBy() <= CAInfo.SPECIALCAIDBORDER) {
            if (cainfo.getSignedBy() == CAInfo.SELFSIGNED) {
                caInfoDto.setSignedBy(CAInfo.SELFSIGNED);
            }
            if (cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
                caInfoDto.setSignedBy(CAInfo.SIGNEDBYEXTERNALCA);
            }
        } else {
            caInfoDto.setSignedBy(cainfo.getSignedBy());
        }

        caInfoDto.setCaEncodedValidity(cainfo.getEncodedValidity());
        final boolean validityNotUsed = (isCaexternal || (!isCaUninitialized && signbyexternal));
        if (validityNotUsed && (StringUtils.isBlank(caInfoDto.getCaEncodedValidity()) || "0d".equals(caInfoDto.getCaEncodedValidity()))) {
            hideValidity = true;
            caInfoDto.setCaEncodedValidity("");
        }

        caInfoDto.setUseCertReqHistory(cainfo.isUseCertReqHistory());
        caInfoDto.setUseUserStorage(cainfo.isUseUserStorage());

        if (caInfoDto.isCaTypeX509() && cainfo != null) {
            final X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            caInfoDto.setDefaultCRLDistPoint(x509cainfo.getDefaultCRLDistPoint());
            caInfoDto.setDefaultCRLIssuer(x509cainfo.getDefaultCRLIssuer());
            caInfoDto.setCaDefinedFreshestCRL(x509cainfo.getCADefinedFreshestCRL());
            caInfoDto.setDefaultOCSPServiceLocator(x509cainfo.getDefaultOCSPServiceLocator());
            caInfoDto.setCaSerialNumberOctetSize(String.valueOf(x509cainfo.getCaSerialNumberOctetSize()));
            caInfoDto.setDoPreProduceOcspResponses(x509cainfo.isDoPreProduceOcspResponses());
            caInfoDto.setDoStoreOcspResponsesOnDemand(x509cainfo.isDoStoreOcspResponsesOnDemand());

            if(x509cainfo.getPolicies() == null || (x509cainfo.getPolicies().isEmpty())) {
                caInfoDto.setPolicyId(getEjbcaWebBean().getText("NONE"));
             } else {
               // Some special handling to handle the upgrade case after CertificatePolicy changed classname
               String policyId = null;
               final Object obj = x509cainfo.getPolicies().get(0);
               if (obj instanceof CertificatePolicy) {
                 policyId = ((CertificatePolicy)obj).getPolicyID();
               } else {
                 policyId = ((org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy)obj).getPolicyID();
               }
               if (policyId == null) {
                   caInfoDto.setPolicyId(getEjbcaWebBean().getText("NONE"));
               } else {
                   caInfoDto.setPolicyId(policyId);
               }
             }
            caInfoDto.setUseUtf8Policy(x509cainfo.getUseUTF8PolicyText());
            caInfoDto.setUsePrintableStringSubjectDN(x509cainfo.getUsePrintableStringSubjectDN());
            caInfoDto.setUseLdapDNOrder(x509cainfo.getUseLdapDnOrder());
            caInfoDto.setNameConstraintsExcluded(NameConstraint.formatNameConstraintsList(x509cainfo.getNameConstraintsExcluded()));
            caInfoDto.setNameConstraintsPermitted(NameConstraint.formatNameConstraintsList(x509cainfo.getNameConstraintsPermitted()));
            crlCaCRLDPExternal = x509cainfo.getExternalCdp();
            caInfoDto.setUseAuthorityKeyIdentifier(x509cainfo.getUseAuthorityKeyIdentifier());
            caInfoDto.setAuthorityKeyIdentifierCritical(x509cainfo.getAuthorityKeyIdentifierCritical());
            caInfoDto.setUseCrlNumber(x509cainfo.getUseCRLNumber());
            caInfoDto.setCrlNumberCritical(x509cainfo.getCRLNumberCritical());
            caInfoDto.setUseCrlDistributiOnPointOnCrl(x509cainfo.getUseCrlDistributionPointOnCrl());
            caInfoDto.setCrlDistributionPointOnCrlCritical(x509cainfo.getCrlDistributionPointOnCrlCritical());

            final List<String> urisAuthorityInformationAccess = x509cainfo.getAuthorityInformationAccess();
            final List<String> urisCertificateAiaDefaultCaIssuerUri = x509cainfo.getCertificateAiaDefaultCaIssuerUri();
            caInfoDto.setAuthorityInformationAccess(null != urisAuthorityInformationAccess ? StringUtils.join(urisAuthorityInformationAccess, ";") : "");
            caInfoDto.setCertificateAiaDefaultCaIssuerUri(null != urisCertificateAiaDefaultCaIssuerUri ? StringUtils.join(urisCertificateAiaDefaultCaIssuerUri, ";") : "");
            caInfoDto.setKeepExpiredOnCrl(x509cainfo.getKeepExpiredCertsOnCRL());
            caInfoDto.setUsePartitionedCrl(x509cainfo.getUsePartitionedCrl());
            caInfoDto.setCrlPartitions(x509cainfo.getCrlPartitions());
            caInfoDto.setSuspendedCrlPartitions(x509cainfo.getSuspendedCrlPartitions());

            if (isCaexternal) {
                caInfoDto.setCrlCaCrlPeriod(SimpleTime.getInstance(cainfo.getCRLPeriod()).toString(SimpleTime.TYPE_MINUTES));
                caInfoDto.setCrlCaIssueInterval(SimpleTime.getInstance(cainfo.getCRLIssueInterval()).toString(SimpleTime.TYPE_MINUTES));
                caInfoDto.setCrlCaOverlapTime(SimpleTime.getInstance(cainfo.getCRLOverlapTime()).toString(SimpleTime.TYPE_MINUTES));
                caInfoDto.setCrlCaDeltaCrlPeriod(SimpleTime.getInstance(cainfo.getDeltaCRLPeriod()).toString(SimpleTime.TYPE_MINUTES));

              } else {
                caInfoDto.setCrlCaCrlPeriod(SimpleTime.getInstance(cainfo.getCRLPeriod()).toString(SimpleTime.TYPE_MINUTES));
                caInfoDto.setCrlCaIssueInterval(SimpleTime.getInstance(cainfo.getCRLIssueInterval()).toString(SimpleTime.TYPE_MINUTES));
                caInfoDto.setCrlCaOverlapTime(SimpleTime.getInstance(cainfo.getCRLOverlapTime()).toString(SimpleTime.TYPE_MINUTES));
                caInfoDto.setCrlCaDeltaCrlPeriod(SimpleTime.getInstance(cainfo.getDeltaCRLPeriod()).toString(SimpleTime.TYPE_MINUTES));
              }
        }

        if (caInfoDto.isCaTypeX509() && cmscainfo != null) {
            caInfoDto.setServiceCmsActive(cmscainfo.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE);
        }

        caInfoDto.setFinishUser(cainfo.getFinishUser());

        if (caInfoDto.isCaTypeX509()) {
            caInfoDto.setSharedCmpRaSecret(((X509CAInfo) cainfo).getCmpRaAuthSecret());
        }

        if (isCaUninitialized && caInfoDto.isCaTypeX509()) {
            String policies = "";
            final X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            final List<CertificatePolicy> list = x509cainfo.getPolicies();
            final CertificatePolicy cp = (list != null && !list.isEmpty()) ? list.get(0) : null;
            if (cp != null) {
                policies += cp.getPolicyID();
                if (cp.getQualifier() != null) {
                    policies += " "+cp.getQualifier();
                }
            }
            caInfoDto.setPolicyId(policies);
        }

        if (caInfoDto.isCaTypeX509()) {
            final X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            if (!isCaUninitialized) {
                if (x509cainfo.getSubjectAltName() == null || x509cainfo.getSubjectAltName().trim().equals("")) {
                    caInfoDto.setCaSubjectAltName(getEjbcaWebBean().getText("NONE"));
                } else {
                    caInfoDto.setCaSubjectAltName(x509cainfo.getSubjectAltName());
                }
                try {
                    rolloverNotBefore = caBean.getRolloverNotBefore(caid);
                    rolloverNotAfter = caBean.getRolloverNotAfter(caid);
                    caCertNotAfter = caBean.getCANotAfter(caid);
                } catch (CADoesntExistsException | AuthorizationDeniedException e) {
                    log.warn("Failed to get CA notAfter and/or rollover date", e);
                }
            } else {
                caInfoDto.setCaSubjectAltName(x509cainfo.getSubjectAltName());
            }
            caInfoDto.setRequestPreProcessor(x509cainfo.getRequestPreProcessor());
        }

        caInfoDto.setCaSubjectDN(cainfo.getSubjectDN());
        approvalRequestItems = initApprovalRequestItems();
        final Collection<Certificate> cachain = cainfo.getCertificateChain();
        if (cachain != null && !cachain.isEmpty()) {
            final Iterator<Certificate> iter = cachain.iterator();
            final Certificate cacert = iter.next();
            issuerDn = CertTools.getIssuerDN(cacert);
        }
        usedValidators = cainfo.getValidators();

        if (isCaUninitialized) {
            createLinkCertificate = false;
        } else {
            hasLinkCertificate = (caAdminSession.getLatestLinkCertificate(caid) != null);
        }

        if (isRenderUseCaNameChange()) {
            newSubjectDn = cainfo.getSubjectDN();
        }

        if (isCaUninitialized) {
            updateAvailableCryptoTokenList();
        }
    }

    private void updateAvailableCryptoTokenList() {
        // Defaults if an error occurs
        suitableCryptoTokenExists = true;
        availableCryptoTokenSelectItems = Collections.emptyList();
        try {
            List<Entry<String, String>> availableCryptoTokens = caBean.getAvailableCryptoTokens(caInfoDto.getSignatureAlgorithmParam(), isEditCA);
            if (availableCryptoTokens == null) {
                availableCryptoTokens = Collections.emptyList();
            }
            suitableCryptoTokenExists = !availableCryptoTokens.isEmpty();

            final List<SelectItem> resultList = new ArrayList<>();
            int numSelected = 0; // should be 1 after the loop

            for (final Entry<String, String> entry : availableCryptoTokens) {
                // Ensure that we have a default for the next section
                if (isCryptoTokenIdParamNull() || caInfoDto.getCryptoTokenIdParam().length() == 0) {
                    caInfoDto.setCryptoTokenIdParam(entry.getKey());
                }

                final boolean selectCurrent = entry.getKey().equals(caInfoDto.getCryptoTokenIdParam());
                numSelected += selectCurrent ? 1 : 0;
                if (currentCryptoTokenId == 0 || selectCurrent) {
                    currentCryptoTokenId = Integer.parseInt(entry.getKey());
                }
                resultList.add(new SelectItem(entry.getKey(), entry.getValue(), ""));
            }

            if (numSelected == 0) {
                resultList.add(new SelectItem(caInfoDto.getCryptoTokenIdParam(), "-" + getEjbcaWebBean().getText("CRYPTOTOKEN_MISSING_OR_EMPTY") + " "
                        + caInfoDto.getCryptoTokenIdParam() + "-"));
                caInfoDto.setCryptoTokenIdParam(null);
                currentCryptoTokenId = 0;
            }
            availableCryptoTokenSelectItems = resultList;
        } catch (final AuthorizationDeniedException e) {
            log.error("Error while listing available CryptoTokens!", e);
        }
        failedCryptoTokenLinkMap = new HashMap<>();
        try {
            List<Entry<String, String>> failedCryptoTokens = caBean.getFailedCryptoTokens(caInfoDto.getSignatureAlgorithmParam());
            for (final Entry<String, String> entry : failedCryptoTokens) {
                failedCryptoTokenLinkMap.put(entry.getKey(), entry.getValue());
            }
        } catch (final AuthorizationDeniedException e) {
            log.error("Error while listing failed CryptoTokens!", e);
        }
    }

    private void updateCryptoTokenInfo() {
        currentCryptoTokenName = "";
        currentCryptoTokenPresent = false;
        currentCryptoTokenLink = "";
        if (currentCryptoTokenId != 0) {
            try {
                final CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(getAdmin(), currentCryptoTokenId);
                if (cryptoTokenInfo == null) {
                    final String errMsg = "CryptoToken " + currentCryptoTokenId + " not found.";
                    log.info(errMsg);
                    currentCryptoTokenName = errMsg;
                } else {
                    currentCryptoTokenName = cryptoTokenInfo.getName();
                    currentCryptoTokenLink = CRYPTO_TOKEN_LINK + currentCryptoTokenId;
                    currentCryptoTokenPresent = cryptoTokenManagementSession.isCryptoTokenPresent(getAdmin(), currentCryptoTokenId);
                }
            } catch (final AuthorizationDeniedException e) {
                log.error("Error while getting crypto token info!", e);
            }
        }
    }

    /** Lists the key aliases from the selected crypto token, and sets defaults and updates the "in use" map. */
    private void updateKeyAliases() {
        if (isCryptoTokenIdParamNotNull() && caInfoDto.getCryptoTokenIdParam().length() > 0 && Integer.parseInt(caInfoDto.getCryptoTokenIdParam()) != 0) {
            currentCryptoTokenId = Integer.parseInt(caInfoDto.getCryptoTokenIdParam());
        }
        availableCryptoTokenKeyAliases = new ArrayList<>(); // Avoids NPE in getters if the code below fails.
        availableCryptoTokenMixedAliases = new ArrayList<>();
        availableCryptoTokenEncryptionAliases = new ArrayList<>();
        if (!isCaexternal) {
            updateCryptoTokenInfo();
            if (currentCryptoTokenId != 0) {
                try {
                    // List of key aliases is needed even on Edit CA page, to show the renew key dropdown list
                    updateAvailableKeyAliasesList();
                    generateKeyAlreadyInUseMap();
                    if (isEditCA) {
                        setKeyAliasesFromCa();
                    } else {
                        setDefaultKeyAliases();
                    }
                } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
                    log.error("Error while listing crypto token key aliases!", e);
                }
            }
        }
    }

    private void updateAvailableKeyAliasesList() throws CryptoTokenOfflineException, AuthorizationDeniedException {
        final List<KeyPairInfo> keyPairInfos = caBean.getKeyPairInfos(currentCryptoTokenId);
        availableCryptoTokenKeyAliases = caBean.getAvailableCryptoTokenAliases(keyPairInfos, caInfoDto.getSignatureAlgorithmParam());
        availableCryptoTokenMixedAliases = caBean.getAvailableCryptoTokenMixedAliases(keyPairInfos, caInfoDto.getSignatureAlgorithmParam());
        availableCryptoTokenEncryptionAliases = caBean.getAvailableCryptoTokenEncryptionAliases(keyPairInfos, caInfoDto.getSignatureAlgorithmParam());
    }

    private void generateKeyAlreadyInUseMap() {
        // Create already in use key map
        for (final String alias : availableCryptoTokenMixedAliases) {
            final String alreadyInUse = caBean.isKeyInUse(caSession.getAuthorizedCaIds(getAdmin()), alias, currentCryptoTokenId) ? " (Already in use)"
                    : StringUtils.EMPTY;
            aliasUsedMap.put(alias, alreadyInUse);
        }
    }

    private void initPageVariables(final Map<String, Object> requestMap) {
        // Make sure we have required parameters available in request map
        if (requestMap != null && requestMap.get("iseditca") instanceof Boolean) {
            isEditCA = (Boolean) requestMap.get("iseditca");
            if (isEditCA) {
                editCaName = (String) requestMap.get("editcaname");
                caid = (Integer) requestMap.get("caid");
            } else {
                caInfoDto.setCaName((String) requestMap.get("createcaname"));
            }
        } else { // This page is accessed not via manage ca page we should not continue!
            try {
                FacesContext.getCurrentInstance().getExternalContext().redirect(EditCaUtil.MANAGE_CA_NAV + ".xhtml");
            } catch (final IOException e) {
                throw new FacesException("Cannot redirect to " + EditCaUtil.MANAGE_CA_NAV + " due to IO exception.", e);
            }
        }
    }

    private List<ApprovalRequestItem> initApprovalRequestItems() {
        final List<ApprovalRequestItem> approvalRequestItems = new ArrayList<>();
        if (cainfo != null && cainfo.getApprovals() != null) {
            final LinkedHashMap<ApprovalRequestType, Integer> approvals = (LinkedHashMap<ApprovalRequestType, Integer>) cainfo.getApprovals();
            for (final ApprovalRequestType approvalRequestType : ApprovalRequestType.values()) {
                approvalRequestItems.add(new ApprovalRequestItem(approvalRequestType, approvals.getOrDefault(approvalRequestType, -1)));
            }
        }
        return approvalRequestItems;
    }

}
