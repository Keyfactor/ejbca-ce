package org.ejbca.ui.web.admin.ca;

import java.beans.Beans;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
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
import java.util.Set;
import java.util.TreeMap;

import javax.annotation.PostConstruct;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSession;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.BaseSigningCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.ui.web.ParameterException;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.cainterface.CADataHandler;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.certprof.CertProfileBean.ApprovalRequestItem;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

@ManagedBean
@ViewScoped
public class EditCAsMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EditCAsMBean.class);

    private CAInterfaceBean caBean;
    private TreeMap<String, Integer> canames = getEjbcaWebBean().getCANames();
    private String editCaName;
    private int currentCaId;
    private int currentCaStatus;
    private String currentCaType;
    private String currentCaSigningAlgorithm;
    private String keySequenceFormat;
    private String keySequenceValue = CAToken.DEFAULT_KEYSEQUENCE;
    private boolean doEnforceUniquePublickeys;
    private boolean doEnforceUniqueDistinguishedName;
    private boolean doEnforceUniqueSubjectDNSerialnumber;
    private boolean useCertReqHistory;
    private boolean useUserStorage;
    private boolean useCertificateStorage;
    private boolean isEditCA;
    private boolean isCaTypeX509;
    private String caSubjectDN;
    private String currentCertProfile;
    private String defaultCertificateProfile;
    private String caRevokeReason;
    private String certSignKeyReNewValue;
    private String certExtrSignKeyReNewValue;
    private String certSignKeyRequestValue;
    private boolean checkBoxFutureRollOver;
    private String createCaName;
    private int signedByValue;
    private String signingAlgorithm;
    private String selectedCryptoToken = "0";
    private String cryptoTokenDefaultKey;
    private String cryptoTokenCertSignKey;
    private String selectedKeyEncryptKey;
    private String hardTokenEncryptKey;
    private String testKey;
    private String description;
    private boolean useNoConflictCertificateData;
    private boolean acceptRevocationsNonExistingEntry;

    private CAInfo cainfo = null;
    private CAToken catoken = null;
    private int catype = CAInfo.CATYPE_X509;
    private boolean isCaexternal = false;
    private boolean isCaRevoked = false;
    private Map<Integer, String> keyValidatorMap = getEjbcaWebBean().getEjb().getKeyValidatorSession().getKeyValidatorIdToNameMap();
    private boolean signbyexternal = false;
    private boolean revokable = true;
    private boolean waitingresponse = false;  
    private boolean isCaUninitialized = false;
    private CmsCAServiceInfo cmscainfo = null; 
    private X509Certificate cmscert = null; 
    private List<ApprovalRequestItem> approvalRequestItems = null;
    private Map<Integer, String> approvalProfileMap = getEjbcaWebBean().getApprovalProfileIdToNameMap();
    private String signatureAlgorithmParam = StringUtils.EMPTY;
    private String extendedServicesKeySpecParam = null;
    private int currentCryptoTokenId = 0;

    private String cryptoTokenIdParam = "";
    private final Map<String, String> aliasUsedMap = new HashMap<String, String>();
    private String policyId;
    private boolean useUtf8Policy;
    
    GlobalConfiguration globalconfiguration;
    CADataHandler cadatahandler;
    Map<Integer, String> caidtonamemap;
    Map<String,Integer> casigners = getEjbcaWebBean().getActiveCANames();
    Map<Integer,String> publisheridtonamemap = getEjbcaWebBean().getPublisherIdToNameMapByValue();
    private boolean usePrintableStringSubjectDN;
    private boolean useLdapDNOrder;
    private String nameConstraintsPermitted;
    private String nameConstraintsExcluded;
    private String crlCaCRLDPExternal;
    private boolean useAuthorityKeyIdentifier;
    private boolean authorityKeyIdentifierCritical;
    private boolean useCrlNumber;
    private boolean crlNumberCritical;
    private boolean useCrlDistributiOnPointOnCrl;
    private boolean crlDistributionPointOnCrlCritical;
    private String authorityInformationAccess;
    private boolean keepExpiredOnCrl;
    private String crlCaCrlPeriod;
    private String crlCaIssueInterval;
    private String crlCaOverlapTime;
    private String crlCaDeltaCrlPeriod;
    private List<String> usedCrlPublishers;
    private String defaultCRLDistPoint;
    private String defaultCRLIssuer;
    private String caDefinedFreshestCRL;
    private String defaultOCSPServiceLocator;
    private String certificateAiaDefaultCaIssuerUri;
    private List<String> usedValidators;
    private boolean serviceCmsActive;
    private boolean finishUser;
    private String sharedCmpRaSecret;
    private boolean includeInHealthCheck;
    private String signedBy;
    private String caEncodedValidity;
    private String caSubjectAltName;
    private String caCryptoTokenKeyEncryptKey;
    private String caCryptoTokenTestKey;
    private String signKeySpec;

    private byte[] fileBuffer;
    final Map<String, String> requestMap = new HashMap<String, String>();

    private String viewCertLink; 

        
    public void initAccess() throws Exception {
        // To check access 
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
        }
    }
       
    @PostConstruct
    private void init() {
        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        caBean = (CAInterfaceBean) request.getSession().getAttribute("caBean");
        if (caBean == null) {
            try {
                caBean = (CAInterfaceBean) Beans.instantiate(Thread.currentThread().getContextClassLoader(), CAInterfaceBean.class.getName());
            } catch (ClassNotFoundException | IOException e) {
                log.error("Error while initializing ca bean!", e);
            }
            request.getSession().setAttribute("cabean", caBean);
        }
        caBean.initialize(getEjbcaWebBean());

        try {
            globalconfiguration = getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource());
        } catch (Exception e) {
            log.error("Error while initializing the global configuration!", e);
        }
        cadatahandler = caBean.getCADataHandler();
        caidtonamemap = caBean.getCAIdToNameMap();

        try {
            fileBuffer = caBean.parseRequestParameters(request, requestMap);
        } catch (IOException e) {
            log.error("Error while getting file buffer from the request!", e);
        }

        editCaName = (String) FacesContext.getCurrentInstance().getExternalContext().getRequestMap().get("editCaName");
        createCaName = (String) FacesContext.getCurrentInstance().getExternalContext().getRequestMap().get("createCaName");
        isEditCA = (Boolean) FacesContext.getCurrentInstance().getExternalContext().getRequestMap().get("isEditCA");
        viewCertLink = getEjbcaWebBean().getBaseUrl() + globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";
        
        if (isEditCA) {
            initEditCaPage();
        } else {
            initCreateCaPage();
        }

    }

    public int getCurrentCryptoTokenId() {
        return Integer.parseInt(this.selectedCryptoToken);
    }
    
    public List<String> getListOfCas() {
        final List<String> caList = new ArrayList<String>();
        for (final String nameofca : canames.keySet()) {
            int caId = canames.get(nameofca).intValue();
            int caStatus = caBean.getCAStatusNoAuth(caId);

            String nameandstatus = nameofca + ", (" + getEjbcaWebBean().getText(CAConstants.getStatusText(caStatus)) + ")";
            if (caBean.isAuthorizedToCa(caId)) {
                caList.add(nameandstatus);
            }
        }
        return caList;
    }

    public String getCurrentCertProfile() {
        return currentCertProfile;
    }

    public void setCurrentCertProfile(String currentCertProfile) {
        this.currentCertProfile = currentCertProfile;
    }

    public String getSignKeySpec() {
        return signKeySpec;
    }

    public void setSignKeySpec(final String signKeySpec) {
        this.signKeySpec = signKeySpec;
    }
    
    private void initCreateCaPage() {
        // Defaults in the create CA page
        if (signatureAlgorithmParam == null || signatureAlgorithmParam.length() == 0) {
            signatureAlgorithmParam = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        }
    }
    
    private void generateCryptoAlreadyInUseMap() {
        // Create already in use key map
        
        log.info("Amin gooooooooli we are in already in use map and current crypto token id is " + getCurrentCryptoTokenId());
        
        try {
            for (final String alias : caBean.getAvailableCryptoTokenMixedAliases(getCurrentCryptoTokenId(), signatureAlgorithmParam)) {
                final String alreadyInUse = caBean.isKeyInUse(caBean.getAuthorizedCAs(), alias, getCurrentCryptoTokenId()) ? " (Already in use)" : StringUtils.EMPTY;
                log.info("Amin jan already in use is " + alreadyInUse);
                log.info("Amin jan alias is " + alias);
                aliasUsedMap.put(alias, alreadyInUse);
            }
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            log.error("Error while accessing ca bean!", e);
        }
        
    }
    
    private void initEditCaPage() {
        try {
            cainfo = caBean.getCAInfo(getCurrentCaId()).getCAInfo();
        } catch (AuthorizationDeniedException e) {
            log.error("Error while trying to get the ca info!", e);
        }

        if (cainfo == null) {
            // Not yet initialized.
            return;
        }
        catoken = cainfo.getCAToken();
        keyValidatorMap = getEjbcaWebBean().getEjb().getKeyValidatorSession().getKeyValidatorIdToNameMap(cainfo.getCAType());
        if (signatureAlgorithmParam == null || signatureAlgorithmParam.isEmpty()) {
            signatureAlgorithmParam = catoken.getSignatureAlgorithm();
        }
        signbyexternal = cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA;
        isCaexternal = cainfo.getStatus() == CAConstants.CA_EXTERNAL;
        isCaRevoked = cainfo.getStatus() == CAConstants.CA_REVOKED || cadatahandler.isCARevoked(cainfo);
        revokable = cainfo.getStatus() != CAConstants.CA_REVOKED && cainfo.getStatus() != CAConstants.CA_WAITING_CERTIFICATE_RESPONSE
                && !cadatahandler.isCARevoked(cainfo);
        waitingresponse = cainfo.getStatus() == CAConstants.CA_WAITING_CERTIFICATE_RESPONSE;
        isCaUninitialized = cainfo.getStatus() == CAConstants.CA_UNINITIALIZED;
        try {
            catype = cadatahandler.getCAInfo(getCurrentCaId()).getCAInfo().getCAType();
        } catch (AuthorizationDeniedException e) {
            log.error("Error while trying to get ca info!", e);
        }

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
    }
    
    public int getCaType() {
        return catype;
    }

    public void setCaType(final int catype) {
        log.info("Hi Amin the type is set to " + catype);
        this.catype = catype;
    }
    
    public void setCaTypeX509() {
        this.catype = CAInfo.CATYPE_X509;
    }

    public void setCaTypeCVC() {
        this.catype = CAInfo.CATYPE_CVC;
    }

    public int getCurrentCaId() {
        Integer caId = canames.get(getTrimmedName(this.editCaName));
        if (caId != null) {
            this.currentCaId = caId.intValue();
        }
        return this.currentCaId;
    }

    public int getCurrentCaStatus() {
        return currentCaStatus;
    }
    
    public String getCurrentCaType() {
        
        log.info("Hi amin the edit ca name is " + editCaName);
        Integer caId = canames.get(getTrimmedName(this.editCaName));
        if (caId != null) {
            try {
                int caType = cadatahandler.getCAInfo(caId).getCAInfo().getCAType();
                switch (caType) {
                case CAInfo.CATYPE_X509:
                    this.currentCaType = "X509"; 
                    break;
                case CAInfo.CATYPE_CVC:
                    this.currentCaType = "CVC";
                    break;
                default:
                    this.currentCaType = "UNKNOWN";
                }
            } catch (AuthorizationDeniedException e) {
                log.error("Error while trying to get the current ca type!", e);
            }
        }
        return this.currentCaType;
    }
    
    public String getThisFileName() {
        return globalconfiguration.getAdminWebPath() + "/editcas/editcapage.jsp";
    }

    public boolean isEditCA() {
        return isEditCA;
    }

    public void setEditCA(final boolean isEditCA) {
        this.isEditCA = isEditCA;
    }

    public String getButtonEditCAValue() {
        return isAuthorized() ? getEjbcaWebBean().getText("VIECA") : getEjbcaWebBean().getText("EDITCA");
    }

    public String actionImportCA() {
        return "";
    }

    public String getImportKeystoreText() {
        return getEjbcaWebBean().getText("IMPORTCA_KEYSTORE") + "...";
    }

    public String getImportCertificateText() {
        return getEjbcaWebBean().getText("IMPORTCA_CERTIFICATE") + "...";
    }

    private boolean isAuthorized() {
        boolean onlyView = false;
        if (getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource())
                || getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAVIEW.resource())) {
            onlyView = !getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource())
                    && getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAVIEW.resource());
        }
        return onlyView;
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
        return this.isCaUninitialized;
    }
    
    public boolean isCaExternal() {
        return this.isCaexternal;
    }
    
    public boolean isSignByExternal() {
        return this.signbyexternal;
    }
    
    public String getCurrentCaSigningAlgorithm() {
        if (this.cainfo != null) {
            String signAlgorithm = cainfo.getCAToken().getSignatureAlgorithm();
            if (signAlgorithm != null) {
                this.currentCaSigningAlgorithm = signAlgorithm;
            } else {
                this.currentCaSigningAlgorithm = getEjbcaWebBean().getText("NOTUSED");
            }
        }
        return this.currentCaSigningAlgorithm;
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
        try {
            return getEjbcaWebBean().getBaseUrl() + globalconfiguration.getAdminWebPath() 
                    + "cryptotoken/cryptotoken.jsf?cryptoTokenId=" 
                    + caBean.getCAInfo(getCurrentCaId()).getCAInfo().getCAToken().getCryptoTokenId();
        } catch (AuthorizationDeniedException e) {
            log.error("Error while getting the ca info!", e);
            return StringUtils.EMPTY;
        }
    }
    
    public String getCurrentCaCryptoTokenName() {
        if(cainfo != null) {
            try {
                return caBean.getCryptoTokenName(cainfo.getCAToken().getCryptoTokenId());
            } catch (AuthorizationDeniedException e) {
                log.error("Error while getting crypto token name!", e);
                return StringUtils.EMPTY;
            }
        } else {
            return StringUtils.EMPTY;
        }
    }
    
    public boolean isCurrentCaCryptoTokenPresent() {
        if (caBean != null) {
            try {
                return caBean.isCryptoTokenPresent(cainfo.getCAToken().getCryptoTokenId());
            } catch (AuthorizationDeniedException e) {
                log.error("Error while getting the ca info!", e);
                return false;
            }
        }
        return false;
    }
    
    public String getCurrentCaCryptoTokenDefaultKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_DEFAULT);
            } catch (CryptoTokenOfflineException e) {
                log.error("CA token offile exception!", e);
            }
        }
        return StringUtils.EMPTY;
    }

    public String getCurrentCaCryptoTokenCertSignKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
            } catch (CryptoTokenOfflineException e) {
                log.error("CA token offile exception!", e);
            }
        }
        return StringUtils.EMPTY;
    }
    
    public String getCurrentCaCryptoTokenCrlSignKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
            } catch (CryptoTokenOfflineException e) {
                log.error("CA token offile exception!", e);
            }
        }
        return StringUtils.EMPTY;
    }

    public String getCurrentCaCryptoTokenKeyEncryptKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
            } catch (CryptoTokenOfflineException e) {
                log.error("CA token offile exception!", e);
            }
        }
        return this.caCryptoTokenKeyEncryptKey;
    }
    
    public void setCurrentCaCryptoTokenKeyEncryptKey(final String currentCaCryptoTokenKeyEncryptKey) {
        this.caCryptoTokenKeyEncryptKey = currentCaCryptoTokenKeyEncryptKey;
    }

    public String getCurrentCaCryptoTokenHardTokenEncrypt() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT);
            } catch (CryptoTokenOfflineException e) {
                log.error("CA token offile exception!", e);
            }
        }
        return StringUtils.EMPTY;
    }

    public String getCurrentCaCryptoTokenTestKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYTEST);
            } catch (CryptoTokenOfflineException e) {
                log.error("CA token offile exception!", e);
            }
        }
        return this.caCryptoTokenTestKey;
    }
    
    public void setCurrentCaCryptoTokenTestKey(final String currentCaCryptoTokenTestKey) {
        this.caCryptoTokenTestKey = currentCaCryptoTokenTestKey;
    }
    
    public String getEditCaName() {
        return cainfo != null ? cainfo.getName() : StringUtils.EMPTY;
    }
    
    public String getCreateCaNameTitle() {
        return " : " + this.createCaName;
    }

    public String getKeySequenceFormat() {
        return keySequenceFormat;
    }

    public void setKeySequenceFormat(final String keySequenceFormat) {
        this.keySequenceFormat = keySequenceFormat;
    }
    
    public int keySequenceFormatNumeric() {
        return StringTools.KEY_SEQUENCE_FORMAT_NUMERIC;
    }

    public int keySequenceFormatAlphaNumeric() {
        return StringTools.KEY_SEQUENCE_FORMAT_ALPHANUMERIC;
    }

    public int keySequenceFormatCountryCodePlusNumeric() {
        return StringTools.KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_NUMERIC;
    }

    public int keySequenceFormatCountryCodePlusAlphaNumeric() {
        return StringTools.KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_ALPHANUMERIC;
    }

    public String getKeySequenceValue() {
        if (catoken != null) {
            return catoken.getKeySequence();
        }
        return keySequenceValue;
    }

    public void setKeySequenceValue(final String keySequenceValue) {
        this.keySequenceValue = keySequenceValue;
    }

    public String getDescriptionExternal() {
        if (cainfo != null) {
            return cainfo.getDescription();
        } else {
            return StringUtils.EMPTY;
        }
    }
    
    public String getDescription() {
        if (isEditCA) {
            if (cainfo != null) {
                return cainfo.getDescription();
            } else {
                return StringUtils.EMPTY;
            }
        } else {
            return this.description;
        }
    }
    
    public void setDescription(final String description) {
        this.description = description;
    }
    
    public boolean isDoEnforceUniquePublickeys() {
        return (isEditCA && cainfo.isDoEnforceUniquePublicKeys()) || !isEditCA;
    }

    public void setDoEnforceUniquePublickeys(final boolean doEnforceUniquePublickeys) {
        this.doEnforceUniquePublickeys = doEnforceUniquePublickeys;
    }
   
    public boolean isDoEnforceUniqueDistinguishedName() {
        return (isEditCA && cainfo.isDoEnforceUniqueDistinguishedName()) || !isEditCA;
    }
    
    public void setDoEnforceUniqueDistinguishedName(final boolean doEnforceUniqueDistinguishedName) {
        this.doEnforceUniqueDistinguishedName = doEnforceUniqueDistinguishedName;
    }
    
    public boolean isDoEnforceUniqueSubjectDNSerialnumber() {
        return (isEditCA && cainfo.isDoEnforceUniqueSubjectDNSerialnumber()) || !isEditCA;
    }
    
    public void setDoEnforceUniqueSubjectDNSerialnumber(final boolean doEnforceUniqueSubjectDNSerialnumber) {
        this.doEnforceUniqueSubjectDNSerialnumber = doEnforceUniqueSubjectDNSerialnumber;
    }
    
    public boolean isUseCertReqHistory() {
        return (isEditCA && cainfo.isUseCertReqHistory()) || !isEditCA;
    }
    
    public void setUseCertReqHistory(final boolean useCertReqHistory) {
        if (cainfo != null) {
            cainfo.setUseCertReqHistory(useCertReqHistory);
        }
    }
    
    public boolean isUseUserStorage() {
        return (isEditCA && cainfo.isUseUserStorage()) || !isEditCA;
    }
    
    public void setUseUserStorage(final boolean useUserStorage) {
        this.useUserStorage = useUserStorage;
    }
    
    public boolean isUseCertificateStorage() {
        return (isEditCA && cainfo.isUseCertificateStorage()) || !isEditCA;
    }
    
    public void setUseCertificateStorage(final boolean useCertificateStorage) {
        if (cainfo != null) {
            cainfo.setUseCertificateStorage(useCertificateStorage);
        }
    }
    
    public String getCheckboxUseCertificateStorageText() {
        return getEjbcaWebBean().getText("USE") + "...";
    }
    
    public String getCaSubjectDN() {
        return isEditCA ? cainfo.getSubjectDN() : "CN=" + createCaName;
    }

    public void setCaSubjectDN(final String subjectDn) {
        this.caSubjectDN = subjectDn;
    }
    
    public String getCaIssuerDN() {
        String issuerDN = "unknown";
        try {
            Collection cachain = cainfo.getCertificateChain();
            if (cachain != null) {
                Iterator iter = cachain.iterator();
                Certificate cacert = (Certificate) iter.next();
                issuerDN = CertTools.getIssuerDN(cacert);
            }
        } catch (Exception e) {
            // En error happended
            issuerDN = e.getMessage();
        }
        return issuerDN;
    }
    
    public String getSignedBy() {
        if (cainfo != null) {
            if (cainfo.getSignedBy() >= 0 && cainfo.getSignedBy() <= CAInfo.SPECIALCAIDBORDER) {
                if (cainfo.getSignedBy() == CAInfo.SELFSIGNED) {
                    return getEjbcaWebBean().getText("SELFSIGNED");
                }
                if (cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
                    return getEjbcaWebBean().getText("SIGNEDBYEXTERNALCA");
                }
            } else {
                return (String) caidtonamemap.get(Integer.valueOf(cainfo.getSignedBy()));
            }
        }
        return this.signedBy;
    }
    
    public void setSignedBy(final String signedBy) {
        this.signedBy = signedBy;
    }
    
    public List<String> getSignedByListUninitialized() {
        List<String> signedByList = new ArrayList<>();
        for (final Object nameOfCa : casigners.keySet()) {
            int entryId = casigners.get(nameOfCa.toString());
            if (entryId == cainfo.getCAId()) {
                continue;
            }

            if (cainfo.getSignedBy() == entryId) {
                signedByList.add(nameOfCa.toString());
            }
        }
        return signedByList;
    }
    
    public List<SelectItem> getSignedByCreateCAList() {
        List<SelectItem> resultList = new ArrayList<>();

        resultList.add(new SelectItem(CAInfo.SELFSIGNED, getEjbcaWebBean().getText("SELFSIGNED"), ""));
        resultList.add(new SelectItem(CAInfo.SIGNEDBYEXTERNALCA, getEjbcaWebBean().getText("EXTERNALCA"), ""));

        for (final Object nameOfCa : casigners.keySet()) {
            resultList.add(new SelectItem(casigners.get(nameOfCa.toString()), nameOfCa.toString()));
        }
        return resultList;
    }
    
    public int getSignedByValue() {
        return this.signedByValue;
    }
    
    public void setSignedByValue(final int signedByValue) {
        this.signedByValue = signedByValue;
    }
    
    public String getCertificateProfileEditCAUninitialized() { 
        if (cainfo.getCertificateProfileId() != 0) {
            return getEjbcaWebBean().getCertificateProfileName(cainfo.getCertificateProfileId());
        } else {
            return getEjbcaWebBean().getText("NOTUSED");
        }
    }
    
    public List<SelectItem> getCertificateProfiles() {
        List<SelectItem> resultList = new ArrayList<>();
        for(Entry<String, String> entry : caBean.getAvailableCaCertificateProfiles())
        {
            resultList.add(new SelectItem(entry.getKey(), (String) getTrimmedName(entry.getValue()), ""));
        }
        return resultList;
    }
    
    public String certValidityOutputText() {
        if (StringUtils.isNotBlank(cainfo.getEncodedValidity())) {
            return cainfo.getEncodedValidity();
        } else {
            return getEjbcaWebBean().getText("NOTUSED");
        }
    }
    
    public String getCaEncodedValidity() {
        if (cainfo != null) {
            return cainfo.getEncodedValidity();
        }
        return this.caEncodedValidity;
    }
    
    public void setCaEncodedValidity(final String validity) {
        this.caEncodedValidity = validity;
    }
    
    public boolean isCaTypeX509() {
        return catype == CAInfo.CATYPE_X509;
    }
    
    public boolean isCaTypeCVC() {
        return catype == CAInfo.CATYPE_CVC;
    }
    
    public String getCaSubjectAltName() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;

            if (x509cainfo.getSubjectAltName() == null || x509cainfo.getSubjectAltName().trim().equals("")) {
                return getEjbcaWebBean().getText("NONE");
            } else {
                return x509cainfo.getSubjectAltName();
            }
        } else {
            return StringUtils.EMPTY;
        }
    }
    
    
    public String getCaSubjectAltNameTextField() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return isCaUninitialized ? x509cainfo.getSubjectAltName() : StringUtils.EMPTY;
        } else {
            return this.caSubjectAltName;
        }
    }
    
    public void setCaSubjectAltNameTextField(final String subjectAltName) throws ParameterException {
        if (!caBean.checkSubjectAltName(subjectAltName)) {
            throw new ParameterException(getEjbcaWebBean().getText("INVALIDSUBJECTDN"));
        }
        
        if (cainfo != null) {
            if (catype == CAInfo.CATYPE_X509) {
                this.caSubjectAltName = subjectAltName;
            }
        }
    }
    
    public String getCertificatePolicyId() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;

            if (x509cainfo.getPolicies() == null || (x509cainfo.getPolicies().size() == 0)) {
                return getEjbcaWebBean().getText("NONE");

            } else {
                // Some special handling to handle the upgrade case after CertificatePolicy changed classname
                String policyId = null;
                Object o = x509cainfo.getPolicies().get(0);
                if (o instanceof CertificatePolicy) {
                    policyId = ((CertificatePolicy) o).getPolicyID();
                } else {
                    policyId = ((org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy) o).getPolicyID();
                }
                if (policyId == null) {
                    return getEjbcaWebBean().getText("NONE");
                } else {
                    return policyId;
                }

            }
        } else {
            return StringUtils.EMPTY;
        }
    }    
    
    public String getTextFieldPolicyId() {
        if (catype == CAInfo.CATYPE_X509) {

            X509CAInfo x509cainfo = (X509CAInfo) cainfo;

            String policies = "";

            if (isCaUninitialized) {
                List<CertificatePolicy> list = x509cainfo.getPolicies();
                CertificatePolicy cp = (list != null && list.size() >= 1) ? list.get(0) : null;
                if (cp != null) {
                    policies += cp.getPolicyID();
                    if (cp.getQualifier() != null) {
                        policies += " " + cp.getQualifier();
                    }
                }
            }
            return policies;
        } else {
            return this.policyId;
        }
    }
    
    public void setTextFieldPolicyId(final String policyId) {
        this.policyId = policyId;
    }
    
    public boolean isUseUtf8Policy() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return isEditCA && x509cainfo.getUseUTF8PolicyText();
        } else {
            return this.useUtf8Policy;
        }
    }
    
    public void setUseUtf8Policy(final boolean utf8Policy) {
        this.useUtf8Policy = utf8Policy;
    }
    
    public boolean isUsePrintableStringSubjectDN() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return isEditCA && x509cainfo.getUsePrintableStringSubjectDN();
        } else {
            return this.usePrintableStringSubjectDN;
        }   
    }
    
    public void setUsePrintableStringSubjectDN(final boolean usePrintableStringSubjectDN) {
        this.usePrintableStringSubjectDN = usePrintableStringSubjectDN;
    }
    
    public boolean isUseLdapDNOrder() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return (isEditCA && x509cainfo.getUseLdapDnOrder()) || (!isEditCA);
        } else {
            return this.useLdapDNOrder;
        }
    }
    
    public void setUseLdapDNOrder(final boolean useLdapDNOrder) {
        this.useLdapDNOrder = useLdapDNOrder;
    }
    
    public String getNameConstraintsPermittedString() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return !isEditCA ? ""
                    : NameConstraint.formatNameConstraintsList(x509cainfo.getNameConstraintsPermitted());
        } else {
            return this.nameConstraintsPermitted;
        }
    }
    
    public void setNameConstraintsPermittedString(final String nameConstraintsPermitted) {
        this.nameConstraintsPermitted = nameConstraintsPermitted;
    }

    public String getNameConstraintsExcludedString() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;

            return !isEditCA ? ""
                    : NameConstraint.formatNameConstraintsList(x509cainfo.getNameConstraintsExcluded());
        } else {
            return StringUtils.EMPTY;
        }
    }
    
    public void setNameConstraintsExcludedString(final String nameConstraintsExcluded) {
        this.nameConstraintsExcluded = nameConstraintsExcluded;
    }
    
    public boolean getWaitingResponse() {
        return this.waitingresponse;
    }
    
    public void setWaitingResponse(final boolean waitingResponse) {
        this.waitingresponse = waitingResponse;
    }
    
    public String getCrlCaCRLDPExternal() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return isEditCA ? x509cainfo.getExternalCdp() : StringUtils.EMPTY;
        } else {
            return StringUtils.EMPTY;
        }
    }
    
    public void setCrlCaCRLDPExternal(final String crlCaCRLDPExternal) {
        this.crlCaCRLDPExternal = crlCaCRLDPExternal;
    }
    
    public boolean getCheckboxAuthorityKeyIdentifier() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            if ((isEditCA && x509cainfo.getUseAuthorityKeyIdentifier()) || !isEditCA)
                return true;
        }
        return false;
    }
    
    public void setCheckboxAuthorityKeyIdentifier(final boolean useAuthorityKeyIdentifier) {
        this.useAuthorityKeyIdentifier = useAuthorityKeyIdentifier;
    }
    
    public boolean getCheckboxAuthorityKeyIdentifierCritical() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            if(isEditCA){
                if(!x509cainfo.getUseAuthorityKeyIdentifier() || isCaExternal())
                    return false;
                return x509cainfo.getAuthorityKeyIdentifierCritical();
              }
        }
        return false;
    }
    
    public void setCheckboxAuthorityKeyIdentifierCritical(final boolean authorityKeyIdentifierCritical) {
        this.authorityKeyIdentifierCritical = authorityKeyIdentifierCritical;
    }
    
    
    public boolean getCheckboxUseCrlNumber() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            if ((isEditCA && x509cainfo.getUseCRLNumber()) || !isEditCA) {
                return true;
            }
        }
        return this.useCrlNumber;
    }
    
    public void setCheckboxUseCrlNumber(final boolean useCrlNumber) {
        this.useCrlNumber = useCrlNumber;
    }
    
    public boolean getCheckboxCrlNumberCritical() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;

            if (isEditCA) {
                if (!x509cainfo.getUseCRLNumber() || isCaexternal)
                    return false;
                else
                    return x509cainfo.getCRLNumberCritical();
            }
        }
        return this.crlNumberCritical;
    }
    
    public void setCheckboxCrlNumberCritical(final boolean crlNumberCritical) {
        this.crlNumberCritical = crlNumberCritical;
    }
    
    public boolean getCheckboxUseCrlDistributiOnPointOnCrl() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return isEditCA && x509cainfo.getUseCrlDistributionPointOnCrl();
        }
        return this.useCrlDistributiOnPointOnCrl;
    }
    
    public void setCheckboxUseCrlDistributiOnPointOnCrl(final boolean useCrlDistributiOnPointOnCrl) {
        this.useCrlDistributiOnPointOnCrl = useCrlDistributiOnPointOnCrl;
    }
    
    public boolean getCheckboxCrlDistributionPointOnCrlCritical() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;

            if (isEditCA) {
                if (!x509cainfo.getUseCrlDistributionPointOnCrl() || isCaexternal)
                    return false;
                else if (x509cainfo.getCrlDistributionPointOnCrlCritical())
                    return true;
            }
        }
        return this.crlDistributionPointOnCrlCritical;
    }
    
    public void setCheckboxCrlDistributionPointOnCrlCritical(final boolean crlDistributionPointOnCrlCritical) {
        this.crlDistributionPointOnCrlCritical = crlDistributionPointOnCrlCritical;
    }
    
    public String getAuthorityInformationAccess() {
        String authorityInformationAccess = StringUtils.EMPTY;
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;

            if (x509cainfo != null) {
                final List<String> uris = x509cainfo.getAuthorityInformationAccess();
                authorityInformationAccess = null != uris ? StringUtils.join(uris, ";") : "";
            }
        }
        return authorityInformationAccess;
    }
    
    public void setAuthorityInformationAccess(final String authorityInformationAccess) {
        this.authorityInformationAccess = authorityInformationAccess;
    }
    
    public boolean getCheckboxKeepExpiredOnCrl() {
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            if (isEditCA && x509cainfo.getKeepExpiredCertsOnCRL()) {
                return true;
            }
        }
        return this.keepExpiredOnCrl;
    }
    
    public void setCheckboxKeepExpiredOnCrl(final boolean checkboxKeepExpiredOnCrl) {
        this.keepExpiredOnCrl = checkboxKeepExpiredOnCrl;
    }
    
    public String getCrlCaCrlPeriod() {
        if (isCaexternal) {
            return SimpleTime.getInstance(cainfo.getCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
          } else if (isEditCA) {
              return SimpleTime.getInstance(cainfo.getCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
          } else {
              return  "1" + SimpleTime.TYPE_DAYS;
          }
    }
    
    public void setCrlCaCrlPeriod(final String crlCaCrlPeriod) {
        this.crlCaCrlPeriod = crlCaCrlPeriod;
    }

    public String getCrlCaIssueInterval() {
        if (isCaexternal) {
            return SimpleTime.getInstance(cainfo.getCRLIssueInterval()).toString(SimpleTime.TYPE_MINUTES);
        } else if (isEditCA) {
            return SimpleTime.getInstance(cainfo.getCRLIssueInterval()).toString(SimpleTime.TYPE_MINUTES);
        } else {
            return "0" + SimpleTime.TYPE_MINUTES;
        }
    }
    
    public void setCrlCaIssueInterval(final String crlCaIssueInterval) {
        this.crlCaIssueInterval = crlCaIssueInterval;
    }   

    public String getCrlCaOverlapTime() {
        if (isCaexternal) {
            return SimpleTime.getInstance(cainfo.getCRLOverlapTime()).toString(SimpleTime.TYPE_MINUTES);
        } else if (isEditCA) {
            return SimpleTime.getInstance(cainfo.getCRLOverlapTime()).toString(SimpleTime.TYPE_MINUTES);
        } else {
            return "10" + SimpleTime.TYPE_MINUTES;
        }
    }

    public void setCrlCaOverlapTime(final String crlCaOverlapTime) {
        this.crlCaOverlapTime = crlCaOverlapTime;
    }       
    
    public String getCrlCaDeltaCrlPeriod() {
        if (isCaexternal) {
            return SimpleTime.getInstance(cainfo.getDeltaCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
        } else if (isEditCA) {
            return SimpleTime.getInstance(cainfo.getDeltaCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
        } else {
            return "0" + SimpleTime.TYPE_MINUTES;
        }
    }
    
    public void setCrlCaDeltaCrlPeriod(final String crlCaDeltaCrlPeriod) {
        this.crlCaDeltaCrlPeriod = crlCaDeltaCrlPeriod;
    }     
    
    public List<SelectItem> getAvailableCrlPublishers() {
        final List<SelectItem> ret = new ArrayList<>();
        Set<Integer> publishersIds = publisheridtonamemap.keySet(); 
        
        for(final int id: publishersIds){
            ret.add(new SelectItem(id, publisheridtonamemap.get(id), "", isHasEditRight() ? false : true));
        }
        return ret;
    }
    
    public List<String> getUsedCrlPublishers() {
        Collection<?> usedpublishers = null;
        final List<String> ret = new ArrayList<>();
        if (isEditCA)
            usedpublishers = cainfo.getCRLPublishers();
        Set<Integer> publishersIds = publisheridtonamemap.keySet();

        for (final int id : publishersIds) {
            if (isEditCA && usedpublishers.contains(id)) {
                ret.add(publisheridtonamemap.get(id));
            }
        }
        return ret;
    } 
    
    public void setUsedCrlPublishers(final List<String> publishers) {
        this.usedCrlPublishers = publishers;
    }
    
    public String getDefaultCRLDistPoint() {
        if (isEditCA && catype == CAInfo.CATYPE_X509 && cainfo != null) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return x509cainfo.getDefaultCRLDistPoint();
        }
        return this.defaultCRLDistPoint;
    }
    
    public void setDefaultCRLDistPoint(final String defaultCRLDistPoint) {
        this.defaultCRLDistPoint = defaultCRLDistPoint;
    }       
    
    public void genDefaultCrlDistPoint() {
        if (!isEditCA) {
            this.defaultCRLDistPoint = globalconfiguration.getStandardCRLDistributionPointURINoDN() + this.caSubjectDN; //TODO: this must be encoded!
        } else {
            this.defaultCRLDistPoint = globalconfiguration.getStandardCRLDistributionPointURINoDN() + cainfo.getSubjectDN();
        }
    }
    
    public String getDefaultCRLIssuer() {
        if (isEditCA && catype == CAInfo.CATYPE_X509 && cainfo != null) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return x509cainfo.getDefaultCRLIssuer();
        }
        return this.defaultCRLIssuer;
    }

    public void setDefaultCRLIssuer(final String defaultCRLIssuer) {
        this.defaultCRLIssuer = defaultCRLIssuer;
    }    

    public void genDefaultCrlIssuer() {
        if (!isEditCA) {
            this.defaultCRLIssuer = this.caSubjectDN;
        } else {
            this.defaultCRLIssuer = cainfo.getSubjectDN();
        }
    }    
    
    
    public String getCaDefinedFreshestCRL() {
        if (isEditCA && catype == CAInfo.CATYPE_X509 && cainfo != null) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return x509cainfo.getCADefinedFreshestCRL() == null ? x509cainfo.getCADefinedFreshestCRL() : StringUtils.EMPTY;
        }
        return this.caDefinedFreshestCRL;
    }
    
    public void setCaDefinedFreshestCRL(final String caDefinedFreshestCRL) {
        this.caDefinedFreshestCRL = caDefinedFreshestCRL;
    }
    
    public void genCaDefinedFreshestCrl() {
        if (!isEditCA) {
            this.caDefinedFreshestCRL = globalconfiguration.getStandardDeltaCRLDistributionPointURINoDN() + this.caSubjectDN; // TODO: encode this
        } else {
            this.caDefinedFreshestCRL = globalconfiguration.getStandardDeltaCRLDistributionPointURINoDN() + cainfo.getSubjectDN(); // TODO: encode this
        }
    }    

    public String getDefaultOCSPServiceLocator(){
        if (catype == CAInfo.CATYPE_X509 && cainfo != null) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return x509cainfo.getDefaultOCSPServiceLocator();
        }
        return StringUtils.EMPTY;
    }

    public void setDefaultOCSPServiceLocator(final String defaultOCSPServiceLocator) {
        this.defaultOCSPServiceLocator = defaultOCSPServiceLocator;
    }    
    
    public String getCertificateAiaDefaultCaIssuerUri() {
        String certificateAiaDefaultCaIssuerUri = "";
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            if (x509cainfo != null) {
                final List<String> uris = x509cainfo.getCertificateAiaDefaultCaIssuerUri();
                certificateAiaDefaultCaIssuerUri = null != uris ? StringUtils.join(uris, ";") : "";
            }
        }
        return certificateAiaDefaultCaIssuerUri;
    }
    
    public void setCertificateAiaDefaultCaIssuerUri(final String certificateAiaDefaultCaIssuerUri) {
        this.certificateAiaDefaultCaIssuerUri = certificateAiaDefaultCaIssuerUri;
    }     
    
    public List<ApprovalRequestItem> getApprovalRequestItems() {
        if (approvalRequestItems == null) {
            approvalRequestItems = new ArrayList<>();
            Map<ApprovalRequestType, Integer> approvals = getApprovals();
            for (ApprovalRequestType approvalRequestType : ApprovalRequestType.values()) {
                int approvalProfileId;
                if (approvals.containsKey(approvalRequestType)) {
                    approvalProfileId = approvals.get(approvalRequestType);
                } else {
                    approvalProfileId = -1;
                }
                approvalRequestItems.add(new ApprovalRequestItem(approvalRequestType, approvalProfileId));                    
            }
        }
        return approvalRequestItems;
    }
    
    private Map<ApprovalRequestType, Integer> getApprovals() {
        Map<ApprovalRequestType, Integer> approvals = new LinkedHashMap<>();
        for (int approvalProfileId : getEjbcaWebBean().getSortedApprovalProfileIds()) {
            approvals.put(ApprovalRequestType.getFromIntegerValue(approvalProfileId), approvalProfileId);
        }
        return approvals;
    }
    
    
    public List<SelectItem> getAvailableApprovalProfiles() {
        List<SelectItem> ret = new ArrayList<>();
        ApprovalProfileSession approvalProfileSession = getEjbcaWebBean().getEjb().getApprovalProfileSession();
        Map<Integer, String> approvalProfiles = approvalProfileSession.getApprovalProfileIdToNameMap();
        Set<Entry<Integer, String>> entries = approvalProfiles.entrySet();
        for(Entry<Integer, String> entry : entries) {
            ret.add(new SelectItem(entry.getKey(), entry.getValue()));
        }

        // Sort list by name
        Collections.sort(ret, new Comparator<SelectItem>() {
            @Override
            public int compare(final SelectItem a, final SelectItem b) {
                return a.getLabel().compareToIgnoreCase(b.getLabel());
            }
        });
        ret.add(0, new SelectItem(-1, EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("NONE")));
        return ret;
    }
    
    public List<SelectItem> getAvailableValidators() {
        final List<SelectItem> ret = new ArrayList<>();
        if (isEditCA) {
            Collection<?> usedKeyValidators = keyValidatorMap.values();
            for (Integer validatorId : keyValidatorMap.keySet()) {
                if (isEditCA && usedKeyValidators.contains(validatorId))
                    ret.add(new SelectItem(validatorId, keyValidatorMap.get(validatorId), "", isHasEditRight() ? false : true));
            }
        }
        return ret;
    }

    public List<String> getUsedValidators() {
        Collection<?> usedValidators = null;
        final List<String> ret = new ArrayList<>();
        if (isEditCA)
            usedValidators = cainfo.getValidators();
        for (final int id : keyValidatorMap.keySet()) {
            if (isEditCA && usedValidators.contains(id)) {
                ret.add(keyValidatorMap.get(id));
            }
        }
        return ret;
    } 
    
    public void setUsedValidators(final List<String> validators) {
        this.usedValidators = validators;
    }
    
    public boolean isRenderCmsInfo() {
        return catype == CAInfo.CATYPE_X509 && !isEditCA || (isEditCA && cmscainfo != null);
    }
    
    public boolean isCmsButtonDisabled() {
        return waitingresponse || (isEditCA && !isCaUninitialized && cmscainfo == null);
    }
    
    public boolean getCmsButtonStatus() {
        if (isEditCA) {
            return cmscainfo.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE;
        } else {
            return this.serviceCmsActive;
        }
    }
    
    public void setCmsButtonStatus(final boolean serviceCmsActive) {
        this.serviceCmsActive = serviceCmsActive;
    }
    
    public boolean isWaitingForResponse() {
        return this.waitingresponse;
    }
    
    public boolean renderViewCmsCert() {
        return isEditCA && !isCaUninitialized && cmscert != null;
    }
    
    public boolean getFinishUser() {
        return (isEditCA && cainfo.getFinishUser()) || !isEditCA;
    }
    
    public void setFinishUser(final boolean finishUser) {
        this.finishUser = finishUser;
    }
    
    public String getCmpRaAuthSecretValue() {
        if(isEditCA && cainfo != null) {
            return ((X509CAInfo)cainfo).getCmpRaAuthSecret();
        } else {
            return this.sharedCmpRaSecret;
        }
    }
    
    public void setCmpRaAuthSecretValue(final String cmpRaAuthSecretValue) {
        this.sharedCmpRaSecret = cmpRaAuthSecretValue;
    }
    
    public boolean getIncludeInHealthCheck() {
        return cainfo != null && cainfo.getIncludeInHealthCheck();
    }
    
    public void setIncludeInHealthCheck(final boolean includeInHealthCheck) {
        this.includeInHealthCheck = includeInHealthCheck;
    }
    
    public boolean isRenderCaLifeCycle() {
        return isEditCA && revokable && isHasEditRight();
    }
    
    public List<String> getRevokeReasonList() {
        List<String> result = new ArrayList<>();
        for (int i = 0; i < SecConst.reasontexts.length; i++) {
            if (i != 7) {
                result.add(getEjbcaWebBean().getText(SecConst.reasontexts[i]));
            }
        }
        return result;
    }

    public String getCaRevokeReason() {
        return caRevokeReason;
    }

    public void setCaRevokeReason(final String caRevokeReason) {
        this.caRevokeReason = caRevokeReason;
    }
    
    public List<String> getCertSignKeyReNewList() {
        final int cryptoTokenId = catoken==null ? getCurrentCryptoTokenId() : catoken.getCryptoTokenId();
        // Cache the lookup/iteration over all the keys in the CryptoToken
        List<String> availableCryptoTokenAliases = new ArrayList<>();
        availableCryptoTokenAliases.add(getEjbcaWebBean().getText("RENEWCA_USINGKEYSEQUENCE"));
        try {
            if (!isCaexternal && caBean.isCryptoTokenPresent(cryptoTokenId) && caBean.isCryptoTokenActive(cryptoTokenId)) {
                return availableCryptoTokenAliases = caBean.getAvailableCryptoTokenAliases(cryptoTokenId, signatureAlgorithmParam);
            }
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean for fetching token data!", e);
        }
        return availableCryptoTokenAliases;
    }

    public List<String> getCertSignKeyRecieveReqList() {
        final int cryptoTokenId = catoken==null ? getCurrentCryptoTokenId() : catoken.getCryptoTokenId();
        // Cache the lookup/iteration over all the keys in the CryptoToken
        List<String> availableCryptoTokenAliases = new ArrayList<>();
        try {
            if (!isCaexternal && caBean.isCryptoTokenPresent(cryptoTokenId) && caBean.isCryptoTokenActive(cryptoTokenId)) {
                return availableCryptoTokenAliases = caBean.getAvailableCryptoTokenAliases(cryptoTokenId, signatureAlgorithmParam);
            }
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean for fetching token data!", e);
        }
        return availableCryptoTokenAliases;
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
            return catype == CAInfo.CATYPE_X509 && cainfo.getSignedBy() == CAInfo.SELFSIGNED && globalconfiguration.getEnableIcaoCANameChange();
        }
        return false;
    }
    
    public String getNewSubjectDNValue() {
        if (cainfo != null) {
            return cainfo.getSubjectDN();
        } else {
            return StringUtils.EMPTY;
        }
    }
    
    public String getBinaryCaIdLink() {
        return "adminweb/ca/editcas/cacertreq?cmd=linkcert&format=binary&caid=" + currentCaId;
    }
    
    public String getCaIdLink() {
        return "adminweb/ca/editcas/cacertreq?cmd=linkcert&caid=" + currentCaId;
    }
    
    public boolean isRenderCaIdLink() {
        try {
            return isEditCA && !isCaexternal && !waitingresponse && caBean.isCryptoTokenPresent(getCurrentCryptoTokenId()) && caBean.isCryptoTokenActive(getCurrentCryptoTokenId()) && cainfo.getSignedBy()!= CAInfo.SIGNEDBYEXTERNALCA && !isCaRevoked();
        } catch (AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean!", e);
        }
        return false;
    }
    
    private boolean isCaRevoked() {
        // TODO Auto-generated method stub
        return false;
    }

    public boolean isRollOverDate() {
        Date rolloverDate = null;
        try {
            rolloverDate = caBean.getRolloverNotBefore(currentCaId);
        } catch (CADoesntExistsException e) {
            log.error("Error while getting roll over not before!", e);
        }
        return rolloverDate != null;
    }
    
    public String getCaRollOverNotAfter() {
        Date currentValidity = null;
        try {
            currentValidity = caBean.getRolloverNotAfter(currentCaId);
        } catch (CADoesntExistsException | AuthorizationDeniedException e) {
            log.error("Error while getting roll over not after!", e);
        }
        return getEjbcaWebBean().formatAsISO8601(currentValidity);
    }
    
    public String getCaRollOverNotBefore() {
        Date rolloverDate = null;
        try {
            rolloverDate = caBean.getRolloverNotBefore(currentCaId);
        } catch (CADoesntExistsException e) {
            log.error("Error while getting roll over not before!", e);
        }
        return rolloverDate != null ? getEjbcaWebBean().formatAsISO8601(rolloverDate) : StringUtils.EMPTY;
    }
    
    public String getConfirmRolloverDate() {
        Date rolloverDate = null;
        Date now = new Date();

        try {
            rolloverDate = caBean.getRolloverNotBefore(currentCaId);
        } catch (CADoesntExistsException e) {
            log.error("Error while getting roll over not before!", e);
        }
        
        if (rolloverDate != null) {
            return rolloverDate.after(now) ? " onclick=\"return confirm('Next certificate is not yet valid! Are you sure?')\"" : StringUtils.EMPTY;
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
        return catype == CAInfo.CATYPE_X509 && !isWaitingForResponse();
    }
    
    public boolean isRenderExportCA() {
        try {
            return caBean.isCaExportable(cainfo);
        } catch (AuthorizationDeniedException e) {
            log.error("Error while accessing ca bean!", e);
        }
        return false;
    }
    
    public boolean isEditCANotUninitializedNotExternal() {
        return isEditCA && !isCaUninitialized && !isCaexternal;
    }
    
    public List<SelectItem> getAvailableSigningAlgList() {
        List<SelectItem> resultList = new ArrayList<>();
        for (final String current : AlgorithmConstants.AVAILABLE_SIGALGS) {
            if (!AlgorithmTools.isSigAlgEnabled(current)) {
                continue; // e.g. GOST3410 if not configured
            }
            resultList.add(new SelectItem(current, current, ""));
        }
        return resultList;
    }

    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public void setSigningAlgorithm(final String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }
    

    public boolean isCryptoTokenSuitable() {
        List<Entry<String, String>> availableCryptoTokens = null;
        try {
            availableCryptoTokens = caBean.getAvailableCryptoTokens(signatureAlgorithmParam, isEditCA);
        } catch (AuthorizationDeniedException e) {
            log.error("Error while accessing ca bean!", e);
        }
        return availableCryptoTokens.size() > 0;
    }
    
    public List<SelectItem> getAvailableCryptoTokenList() {

        List<SelectItem> resultList = new ArrayList<>();

        List<Entry<String, String>> availableCryptoTokens = null;
        try {
            availableCryptoTokens = caBean.getAvailableCryptoTokens(signatureAlgorithmParam, isEditCA);
        } catch (AuthorizationDeniedException e) {
            log.error("Error while accessing ca bean!", e);
        }

        if (isEditCA && isCaUninitialized && (cryptoTokenIdParam == null || cryptoTokenIdParam.length() == 0)) {
            cryptoTokenIdParam = String.valueOf(catoken.getCryptoTokenId());
        }

        for (final Entry<String, String> entry : availableCryptoTokens) {
            resultList.add(new SelectItem(entry.getKey(), entry.getValue(), ""));
            if (cryptoTokenIdParam == null || cryptoTokenIdParam.length()==0) {
                cryptoTokenIdParam = entry.getKey();
            }
        }

        return resultList;
    }

    public String getSelectedCryptoToken() {
        return selectedCryptoToken;
    }

    public void setSelectedCryptoToken(final String selectedCryptoToken) {
        this.selectedCryptoToken = selectedCryptoToken;
        generateCryptoAlreadyInUseMap();        
    } 
    
    public List<SelectItem> getCryptotokenDefaultKeyList() {
        List<SelectItem> resultList = new ArrayList<>();
        try {
            for (final String alias : caBean.getAvailableCryptoTokenMixedAliases(getCurrentCryptoTokenId(), signatureAlgorithmParam)) {
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean!", e);
        }
        return resultList;
    }
    
    public List<SelectItem> getCryptotokenCertSignKeyList() {
        List<SelectItem> resultList = new ArrayList<>();
        try {
            for (final String alias : caBean.getAvailableCryptoTokenAliases(getCurrentCryptoTokenId(), signatureAlgorithmParam)) {
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean!", e);
        }
        return resultList;
    }

    public List<SelectItem> getCryptotokenkeyEncryptKeyList() {
        List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(getEjbcaWebBean().getText("CRYPTOTOKEN_DEFAULTKEY")));
        try {
            for (final String alias : caBean.getAvailableCryptoTokenEncryptionAliases(getCurrentCryptoTokenId(), signatureAlgorithmParam)) {
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean!", e);
        }
        return resultList;
    }

    public List<SelectItem> getCryptotokenHardTokenEncryptList() {
        List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(getEjbcaWebBean().getText("CRYPTOTOKEN_DEFAULTKEY")));
        try {
            for (final String alias : caBean.getAvailableCryptoTokenEncryptionAliases(getCurrentCryptoTokenId(), signatureAlgorithmParam)) {
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean!", e);
        }
        return resultList;
    }
    
    public List<SelectItem> getCryptotokenTestKeyList() {
        List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(getEjbcaWebBean().getText("CRYPTOTOKEN_DEFAULTKEY")));
        try {
            for (final String alias : caBean.getAvailableCryptoTokenAliases(getCurrentCryptoTokenId(), signatureAlgorithmParam)) {
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean!", e);
        }
        return resultList;
    }
    
    
    public List<SelectItem> getExTServicesKeySpecList() {
        List<SelectItem> resultList = new ArrayList<>();
        
        if (extendedServicesKeySpecParam == null) {
            extendedServicesKeySpecParam = "2048";
        }
        
        for (final Entry<String, String> entry : caBean.getAvailableKeySpecs()) {
            resultList.add(new SelectItem(entry.getKey(), entry.getValue(), ""));
        }
        return resultList;
    }
    
    public String getSelectedCryptoTokenDefaultKey() {
        return cryptoTokenDefaultKey;
    }

    public void setSelectedCryptoTokenDefaultKey(final String selectedCryptoTokenDefaultKey) {
        this.cryptoTokenDefaultKey = selectedCryptoTokenDefaultKey;
    }
    
    public boolean isRenderCreateCaTokenKeys() {
        if (!isEditCA || isCaUninitialized) {
            return (selectedCryptoToken != null && !selectedCryptoToken.isEmpty() && Integer.parseInt(selectedCryptoToken) != 0);
        }
        return false;
    }

    public String getSelectedCryptoTokenCertSignKey() {
        return cryptoTokenCertSignKey;
    }

    public void setSelectedCryptoTokenCertSignKey(final String selectedCryptoTokenCertSignKey) {
        this.cryptoTokenCertSignKey = selectedCryptoTokenCertSignKey;
    }

    public String getSelectedKeyEncryptKey() {
        return selectedKeyEncryptKey;
    }

    public void setSelectedKeyEncryptKey(final String selectedKeyEncryptKey) {
        this.selectedKeyEncryptKey = selectedKeyEncryptKey;
    }

    public String getSelectHardTokenEncrypt() {
        return hardTokenEncryptKey;
    }

    public void setSelectHardTokenEncrypt(final String selectHardTokenEncrypt) {
        this.hardTokenEncryptKey = selectHardTokenEncrypt;
    }
    
    public String getSelectTestKey() {
        return testKey;
    }
    
    public void setSelectTestKey(final String testKey) {
        this.testKey = testKey;
    }

    public String getCertificateValidityHelp() {
        return getEjbcaWebBean().getText("DATE_HELP") + "=" + getEjbcaWebBean().getDateExample() + "." + getEjbcaWebBean().getText("YEAR365DAYS") + ", " + getEjbcaWebBean().getText("MO30DAYS");
    }
    
    public boolean isCryptoTokenIdParamNotNull() {
        return cryptoTokenIdParam != null;
    }
    
    public boolean isRenderSaveExternalCa() {
        return catype == CAInfo.CATYPE_X509 && isHasEditRight();
    }
    
    public String cancel() {
        return "managecas";
    }
    
    public String cmsCertLink() throws UnsupportedEncodingException {
        if (cmscert != null) {
            return "adminweb/viewcertificate.jsp?"
                    + java.net.URLEncoder.encode(cmscert.getSerialNumber().toString(16) + "," + CertTools.getIssuerDN(cmscert), "UTF-8");
        } else {
            return StringUtils.EMPTY;
        }
    }
    
    public String caCertLink() {
        return viewCertLink + "?caid=" + currentCaId;
    }
    
    public String createCa() throws Exception {
        
        final long crlIssueInterval = SimpleTime.getInstance(crlCaIssueInterval, "0"+SimpleTime.TYPE_MINUTES).getLong();
        final long crlPeriod = SimpleTime.getInstance(crlCaCrlPeriod, "1"+SimpleTime.TYPE_DAYS).getLong();
        final long crlOverlapTime = SimpleTime.getInstance(crlCaOverlapTime, "10"+SimpleTime.TYPE_MINUTES).getLong();
        final long deltaCrlPeriod = SimpleTime.getInstance(crlCaDeltaCrlPeriod, "0"+SimpleTime.TYPE_MINUTES).getLong();              
        String availablePublisherValues = null;
        String availableKeyValidatorValues = null;
        
        if (usedValidators != null && !usedValidators.isEmpty()) {
             availableKeyValidatorValues = StringUtils.join(usedValidators.toArray(), ";");
        }
        
        if (getUsedCrlPublishers() != null && !getUsedCrlPublishers().isEmpty()) {
            availablePublisherValues = StringUtils.join(getUsedCrlPublishers().toArray(), ";");
        }
        
        log.info("Hi Amin we are in create ca page and the selected crypto token is " + selectedCryptoToken);
        
        
        log.info("Hi Amin selected ca name is " + createCaName);
        
        log.info("Hi Amin subject dn is " + caSubjectDN);
        
        log.info("Hi Amin signed by is " + signedBy);
        
        log.info("Hi Amin available publishers values is " + availablePublisherValues);
        
        log.info("Hi Amin available keyvalidator value is " + availableKeyValidatorValues);
        
        boolean illegaldnoraltname = false;
            illegaldnoraltname = caBean.actionCreateCaMakeRequest(createCaName, signatureAlgorithmParam,
                    signKeySpec, keySequenceFormat, keySequenceValue,
                    catype, caSubjectDN, currentCertProfile, defaultCertificateProfile, // TODO: this must be default certificate profile
                    useNoConflictCertificateData, signedBy, description, caEncodedValidity,  
                    getApprovals(), finishUser, doEnforceUniquePublickeys,
                    doEnforceUniqueDistinguishedName,
                    doEnforceUniqueSubjectDNSerialnumber, useCertReqHistory, useUserStorage, useCertificateStorage, acceptRevocationsNonExistingEntry,
                    caSubjectAltName, policyId, useAuthorityKeyIdentifier, authorityKeyIdentifierCritical,
                    crlPeriod, crlIssueInterval, crlOverlapTime, deltaCrlPeriod, availablePublisherValues, availableKeyValidatorValues,
                    useCrlNumber, crlNumberCritical, defaultCRLDistPoint, defaultCRLIssuer, defaultOCSPServiceLocator,
                    authorityInformationAccess, 
                    certificateAiaDefaultCaIssuerUri,
                    nameConstraintsPermitted, nameConstraintsExcluded,
                    caDefinedFreshestCRL, useUtf8Policy, usePrintableStringSubjectDN, useLdapDNOrder,
                    useCrlDistributiOnPointOnCrl, crlDistributionPointOnCrlCritical, includeInHealthCheck, false,
                    serviceCmsActive, sharedCmpRaSecret, keepExpiredOnCrl, true, false,
                    selectedCryptoToken, cryptoTokenCertSignKey, cryptoTokenCertSignKey, cryptoTokenDefaultKey,
                    hardTokenEncryptKey, selectedKeyEncryptKey, testKey,
                    fileBuffer);
        
        return illegaldnoraltname ? "error" : "managecas";    
    }
    
    private Object getTrimmedName(final String name) {
        if (name != null && !name.isEmpty()) {
            return name.replaceAll("\\([^()]*\\)", StringUtils.EMPTY).replaceAll(", ", StringUtils.EMPTY);
        } else {
            return StringUtils.EMPTY;
        }
    }
}
