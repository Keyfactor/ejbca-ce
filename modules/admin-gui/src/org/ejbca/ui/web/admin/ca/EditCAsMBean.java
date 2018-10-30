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

import java.beans.Beans;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
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

    private CAInterfaceBean caBean;
    private TreeMap<String, Integer> canames = getEjbcaWebBean().getCANames();
    private String editCaName;
    private int currentCaId;
    private int currentCaStatus;
    private String currentCaType;
    private String currentCaSigningAlgorithm;
    private String keySequenceFormat;
    private String keySequenceValue = CAToken.DEFAULT_KEYSEQUENCE;
    private boolean doEnforceUniquePublickeys = true;
    private boolean doEnforceUniqueDN = true;
    private boolean doEnforceUniqueSubjectDNSerialnumber;
    private boolean useCertReqHistory;
    private boolean useUserStorage = true;
    private boolean useCertificateStorage = true;
    private boolean isEditCA;
    private String caSubjectDN;
    private String currentCertProfile;
    private String defaultCertificateProfile;
    private int caRevokeReason;
    private String certSignKeyReNewValue;
    private String certExtrSignKeyReNewValue;
    private String certSignKeyRequestValue;
    private boolean checkBoxFutureRollOver;
    private String createCaName;
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
    private String signatureAlgorithmParam = StringUtils.EMPTY;
    private String cryptoTokenIdParam = StringUtils.EMPTY;
    private String extendedServicesKeySpecParam = null;

    private int currentCryptoTokenId = 0;

    private final Map<String, String> aliasUsedMap = new HashMap<String, String>();
    private String policyId;
    private boolean useUtf8Policy;
    
    GlobalConfiguration globalconfiguration;
    CADataHandler cadatahandler;
    Map<Integer, String> caidtonamemap;
    Map<String,Integer> casigners = getEjbcaWebBean().getActiveCANames();
    Map<Integer,String> publisheridtonamemap = getEjbcaWebBean().getPublisherIdToNameMapByValue();
    private boolean usePrintableStringSubjectDN;
    private boolean useLdapDNOrder = true; // Default in create ca page
    private String nameConstraintsPermitted = StringUtils.EMPTY; // Default everywhere except editca page
    private String nameConstraintsExcluded = StringUtils.EMPTY; // Default everywhere except editca page
    private String crlCaCRLDPExternal;
    private boolean useAuthorityKeyIdentifier = true; // Default in create ca page
    private boolean authorityKeyIdentifierCritical;
    private boolean useCrlNumber = true; // Default
    private boolean crlNumberCritical;
    private boolean useCrlDistributiOnPointOnCrl;
    private boolean crlDistributionPointOnCrlCritical;
    private String authorityInformationAccess = StringUtils.EMPTY; // Default
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
    private boolean finishUser = true; // Default
    private String sharedCmpRaSecret = StringUtils.EMPTY;
    private boolean includeInHealthCheck;
    private String signedBy;
    private String caEncodedValidity;
    private String caSubjectAltName;
    private String caCryptoTokenKeyEncryptKey;
    private String caCryptoTokenTestKey;
    private String signKeySpec = "2048"; // Default is 2048
    private String importCaName;

    private byte[] fileBuffer;
    private final Map<String, String> requestMap = new HashMap<String, String>();

    private String viewCertLink;
    private String throwAwayDefaultProfile;


    public boolean isAcceptRevocationsNonExistingEntry() {
        return acceptRevocationsNonExistingEntry;
    }

    public void setAcceptRevocationsNonExistingEntry(final boolean acceptRevocationsNonExistingEntry) {
        this.acceptRevocationsNonExistingEntry = acceptRevocationsNonExistingEntry;
    }    

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
        
        try {
            cainfo = caBean.getCAInfo(getCurrentCaId()).getCAInfo();
        } catch (AuthorizationDeniedException e) {
            log.error("Error while trying to get the ca info!", e);
        }
        
        CRYPTO_TOKEN_LINK = getEjbcaWebBean().getBaseUrl() + globalconfiguration.getAdminWebPath() 
        + "cryptotoken/cryptotoken.jsf?cryptoTokenId=";
        
        // Init include health check
        includeInHealthCheck =  cainfo != null && cainfo.getIncludeInHealthCheck();
        
        if (isEditCA) {
            initEditCaPage();
        } else {
            initCreateCaPage();
        }
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
        if (isCaexternal) {
            description = cainfo.getDescription();
        }
        
        if (cryptoTokenIdParam != null && cryptoTokenIdParam.length()>0 && Integer.parseInt(cryptoTokenIdParam)!=0) {
            currentCryptoTokenId = Integer.parseInt(cryptoTokenIdParam);
        }
        
        caSubjectDN = "CN=" + createCaName;
        
        
        if (isCaUninitialized && catype == CAInfo.CATYPE_X509) {
            String policies = "";
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            List<CertificatePolicy> list = x509cainfo.getPolicies();
            CertificatePolicy cp = (list != null && list.size() >= 1) ? list.get(0) : null;
            if (cp != null) {
                policies += cp.getPolicyID();
                if (cp.getQualifier() != null) {
                    policies += " "+cp.getQualifier();
                }
            }
            this.policyId = policies;
            caSubjectAltName = x509cainfo.getSubjectAltName();
        }
        
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            if(x509cainfo != null) {
                final List<String> uris = x509cainfo.getAuthorityInformationAccess();
                authorityInformationAccess = null != uris ? StringUtils.join(uris, ";") : "";
            }
        }
        
        if (isCaexternal) {
            crlCaCrlPeriod = SimpleTime.getInstance(cainfo.getCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
            crlCaIssueInterval = SimpleTime.getInstance(cainfo.getCRLIssueInterval()).toString(SimpleTime.TYPE_MINUTES);
            crlCaOverlapTime = SimpleTime.getInstance(cainfo.getCRLOverlapTime()).toString(SimpleTime.TYPE_MINUTES);
            crlCaDeltaCrlPeriod = SimpleTime.getInstance(cainfo.getDeltaCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
        } else {
            crlCaCrlPeriod = "1" + SimpleTime.TYPE_DAYS;
            crlCaIssueInterval = "0" + SimpleTime.TYPE_MINUTES;
            crlCaOverlapTime = "10" + SimpleTime.TYPE_MINUTES;
            crlCaDeltaCrlPeriod = "0" + SimpleTime.TYPE_MINUTES;
        } 
    }
    
    private void generateCryptoAlreadyInUseMap() {
        if (cryptoTokenIdParam != null && cryptoTokenIdParam.length() > 0 && Integer.parseInt(cryptoTokenIdParam) != 0) {
            currentCryptoTokenId = Integer.parseInt(cryptoTokenIdParam);

            // Create already in use key map
            try {
                for (final String alias : caBean.getAvailableCryptoTokenMixedAliases(currentCryptoTokenId, signatureAlgorithmParam)) {
                    final String alreadyInUse = caBean.isKeyInUse(caBean.getAuthorizedCAs(), alias, currentCryptoTokenId) ? " (Already in use)"
                            : StringUtils.EMPTY;
                    aliasUsedMap.put(alias, alreadyInUse);
                }
            } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
                log.error("Error while accessing ca bean!", e);
            }
        }
    }
    
    private void initEditCaPage() {
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
        
        description = cainfo.getDescription();
        
        doEnforceUniquePublickeys = cainfo.isDoEnforceUniquePublicKeys();
        doEnforceUniqueDN = cainfo.isDoEnforceUniqueDistinguishedName();
        doEnforceUniqueSubjectDNSerialnumber = cainfo.isDoEnforceUniqueSubjectDNSerialnumber();
        useCertificateStorage = cainfo.isUseCertificateStorage();
        useNoConflictCertificateData = cainfo.isUseNoConflictCertificateData();
        
        if (isCaUninitialized) {
            currentCertProfile = String.valueOf(cainfo.getCertificateProfileId());
        } else {
            if (cainfo.getCertificateProfileId() != 0) {
                currentCertProfile = getEjbcaWebBean().getCertificateProfileName(cainfo.getCertificateProfileId());
            } else {
                currentCertProfile = getEjbcaWebBean().getText("NOTUSED");
            }
        }
        
        if (isCaUninitialized && (cryptoTokenIdParam == null || cryptoTokenIdParam.length()==0)) {
            cryptoTokenIdParam = String.valueOf(catoken.getCryptoTokenId());
        }
        
        if (isCaUninitialized) {
            if (cryptoTokenIdParam != null && cryptoTokenIdParam.length() > 0 && Integer.parseInt(cryptoTokenIdParam) != 0) {
                currentCryptoTokenId = Integer.parseInt(cryptoTokenIdParam);
            }
        }      
        
        if (isCaexternal || !isCaUninitialized && signbyexternal) {
            if (StringUtils.isNotBlank(cainfo.getEncodedValidity())) {
                this.caEncodedValidity = cainfo.getEncodedValidity();
            } else {
                this.caEncodedValidity = getEjbcaWebBean().getText("NOTUSED");
            }
        }
        
        if (!isCaUninitialized) {
            if (cainfo.getSignedBy() >= 0 && cainfo.getSignedBy() <= CAInfo.SPECIALCAIDBORDER) {
                if (cainfo.getSignedBy() == CAInfo.SELFSIGNED) {
                    this.signedBy = getEjbcaWebBean().getText("SELFSIGNED");
                }
                if (cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
                    this.signedBy = getEjbcaWebBean().getText("SIGNEDBYEXTERNALCA");
                }
            } else {
                this.signedBy = (String) caidtonamemap.get(Integer.valueOf(cainfo.getSignedBy()));
            }
        }
        
        
        caEncodedValidity = cainfo.getEncodedValidity();
       
        useCertReqHistory = cainfo.isUseCertReqHistory();
        useUserStorage = cainfo.isUseUserStorage();
        
        
        if (catype == CAInfo.CATYPE_X509 && cainfo != null) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            defaultCRLDistPoint = x509cainfo.getDefaultCRLDistPoint();
            defaultCRLIssuer = x509cainfo.getDefaultCRLIssuer();
            caDefinedFreshestCRL = x509cainfo.getCADefinedFreshestCRL();
            defaultOCSPServiceLocator = x509cainfo.getDefaultOCSPServiceLocator();
            
            if(x509cainfo.getPolicies() == null || (x509cainfo.getPolicies().size() == 0)) {
                policyId = getEjbcaWebBean().getText("NONE");
             } else {
               // Some special handling to handle the upgrade case after CertificatePolicy changed classname
               String policyId = null;
               Object o = x509cainfo.getPolicies().get(0);
               if (o instanceof CertificatePolicy) {
                 policyId = ((CertificatePolicy)o).getPolicyID(); 
               } else {
                 policyId = ((org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy)o).getPolicyID();
               }
               if (policyId == null) {
                   this.policyId = getEjbcaWebBean().getText("NONE");
               } else {
                   this.policyId = policyId;
               }
             }
            useUtf8Policy = x509cainfo.getUseUTF8PolicyText();
            usePrintableStringSubjectDN = x509cainfo.getUsePrintableStringSubjectDN();
            useLdapDNOrder = x509cainfo.getUseLdapDnOrder();
            nameConstraintsExcluded = NameConstraint.formatNameConstraintsList(x509cainfo.getNameConstraintsExcluded());
            nameConstraintsPermitted = NameConstraint.formatNameConstraintsList(x509cainfo.getNameConstraintsPermitted());
            crlCaCRLDPExternal = x509cainfo.getExternalCdp();
            useAuthorityKeyIdentifier = x509cainfo.getUseAuthorityKeyIdentifier();
            authorityKeyIdentifierCritical = x509cainfo.getAuthorityKeyIdentifierCritical();
            useCrlNumber = x509cainfo.getUseCRLNumber();
            crlNumberCritical = x509cainfo.getCRLNumberCritical();
            useCrlDistributiOnPointOnCrl = x509cainfo.getUseCrlDistributionPointOnCrl();
            crlDistributionPointOnCrlCritical = x509cainfo.getCrlDistributionPointOnCrlCritical();

            if (x509cainfo != null) {
                final List<String> urisAuthorityInformationAccess = x509cainfo.getAuthorityInformationAccess();
                final List<String> urisCertificateAiaDefaultCaIssuerUri = x509cainfo.getCertificateAiaDefaultCaIssuerUri();
                authorityInformationAccess = null != urisAuthorityInformationAccess ? StringUtils.join(urisAuthorityInformationAccess, ";") : "";
                certificateAiaDefaultCaIssuerUri = null != urisCertificateAiaDefaultCaIssuerUri ? StringUtils.join(urisCertificateAiaDefaultCaIssuerUri, ";") : "";
            }
            
            keepExpiredOnCrl = x509cainfo.getKeepExpiredCertsOnCRL();
            
            if (isCaexternal) {
                crlCaCrlPeriod = SimpleTime.getInstance(cainfo.getCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
                crlCaIssueInterval = SimpleTime.getInstance(cainfo.getCRLIssueInterval()).toString(SimpleTime.TYPE_MINUTES);
                crlCaOverlapTime = SimpleTime.getInstance(cainfo.getCRLOverlapTime()).toString(SimpleTime.TYPE_MINUTES);
                crlCaDeltaCrlPeriod = SimpleTime.getInstance(cainfo.getDeltaCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);

              } else {
                crlCaCrlPeriod = SimpleTime.getInstance(cainfo.getCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
                crlCaIssueInterval = SimpleTime.getInstance(cainfo.getCRLIssueInterval()).toString(SimpleTime.TYPE_MINUTES);
                crlCaOverlapTime = SimpleTime.getInstance(cainfo.getCRLOverlapTime()).toString(SimpleTime.TYPE_MINUTES);
                crlCaDeltaCrlPeriod =  SimpleTime.getInstance(cainfo.getDeltaCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
              } 
            


        }
        
        serviceCmsActive = cmscainfo.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE;
        finishUser = cainfo.getFinishUser();
        
        if (cainfo != null) {
            sharedCmpRaSecret = ((X509CAInfo) cainfo).getCmpRaAuthSecret();
        }
        
        if (isCaUninitialized && catype == CAInfo.CATYPE_X509) {
            String policies = "";
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            List<CertificatePolicy> list = x509cainfo.getPolicies();
            CertificatePolicy cp = (list != null && list.size() >= 1) ? list.get(0) : null;
            if (cp != null) {
                policies += cp.getPolicyID();
                if (cp.getQualifier() != null) {
                    policies += " "+cp.getQualifier();
                }
            }
            this.policyId = policies;
        }
        
        if (catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            if (!isCaUninitialized) {
                if (x509cainfo.getSubjectAltName() == null || x509cainfo.getSubjectAltName().trim().equals("")) {
                    this.caSubjectAltName = getEjbcaWebBean().getText("NONE");
                } else {
                    this.caSubjectAltName = x509cainfo.getSubjectAltName();
                }
            } else {
                this.caSubjectAltName = x509cainfo.getSubjectAltName();
            }
        }
        
        caSubjectDN = cainfo.getSubjectDN();
    }
    
    public int getCaType() {
        return catype;
    }

    public void setCaType(final int catype) {
        this.catype = catype;
    }
    
    public void setCaTypeX509() {
        this.catype = CAInfo.CATYPE_X509;
    }

    public void setCaTypeCVC() {
        this.catype = CAInfo.CATYPE_CVC;
    }

    public int getCurrentCaId() {
        Integer caId = canames.get(EditCaUtil.getTrimmedName(this.editCaName));
        if (caId != null) {
            this.currentCaId = caId.intValue();
        }
        return this.currentCaId;
    }

    public int getCurrentCaStatus() {
        return currentCaStatus;
    }
    
    public String getCurrentCaType() {
        Integer caId = canames.get(EditCaUtil.getTrimmedName(this.editCaName));
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
    
    public String getSignatureAlgorithmParam() {
        return signatureAlgorithmParam;
    }

    public void setSignatureAlgorithmParam(final String signatureAlgorithmParam) {
        this.signatureAlgorithmParam = signatureAlgorithmParam;
    }    
    
    public String getCurrentCaCryptoTokenLink() {
        try {
            return CRYPTO_TOKEN_LINK + caBean.getCAInfo(getCurrentCaId()).getCAInfo().getCAToken().getCryptoTokenId();
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
        return " : " + EditCaUtil.getTrimmedName(this.editCaName); 
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
    
    public String getDescription() {
        return this.description;
    }
    
    public void setDescription(final String description) {
        this.description = description;
    }
    
    public boolean isDoEnforceUniquePublickeys() {
        return this.doEnforceUniquePublickeys;
    }

    public void setDoEnforceUniquePublickeys(final boolean doEnforceUniquePublickeys) {
        this.doEnforceUniquePublickeys = doEnforceUniquePublickeys;
    }
   
    public boolean isDoEnforceUniqueDN() {
        return this.doEnforceUniqueDN;
    }
    
    public void setDoEnforceUniqueDN(final boolean doEnforceUniqueDN) {
        this.doEnforceUniqueDN = doEnforceUniqueDN;
    }
    
    public boolean isDoEnforceUniqueSubjectDNSerialnumber() {
        return this.doEnforceUniqueSubjectDNSerialnumber;
    }
    
    public void setDoEnforceUniqueSubjectDNSerialnumber(final boolean doEnforceUniqueSubjectDNSerialnumber) {
        this.doEnforceUniqueSubjectDNSerialnumber = doEnforceUniqueSubjectDNSerialnumber;
    }
    
    public boolean isUseCertReqHistory() {
        return this.useCertReqHistory;
    }
    
    public void setUseCertReqHistory(final boolean useCertReqHistory) {
        this.useCertReqHistory = useCertReqHistory;
    }
    
    public boolean isUseUserStorage() {
        return this.useUserStorage;
    }
    
    public void setUseUserStorage(final boolean useUserStorage) {
        this.useUserStorage = useUserStorage;
    }
    
    public boolean isUseCertificateStorage() {
        return this.useCertificateStorage; 
    }
    
    public void setUseCertificateStorage(final boolean useCertificateStorage) {
        this.useCertificateStorage = useCertificateStorage;
    }
    
    public String getCheckboxUseCertificateStorageText() {
        return getEjbcaWebBean().getText("USE") + "...";
    }
    
    public String getCaSubjectDN() {
        return this.caSubjectDN;
    }

    public void setCaSubjectDN(final String subjectDn) {
        this.caSubjectDN = subjectDn;
    }
    
    public String getCaIssuerDN() {
        String issuerDN = "unknown";
        try {
            Collection<Certificate> cachain = cainfo.getCertificateChain();
            if (cachain != null) {
                Iterator<Certificate> iter = cachain.iterator();
                Certificate cacert = (Certificate) iter.next();
                issuerDN = CertTools.getIssuerDN(cacert);
            }
        } catch (Exception e) {
            // En error happended
            issuerDN = e.getMessage();
        }
        return issuerDN;
    }
    
    public String getSignedByEditCaNotUninitialized() {
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
        return StringUtils.EMPTY;
    }
    
    public String getSignedBy() {
        return this.signedBy;
    }
    
    public void setSignedBy(final String signedBy) {
        this.signedBy = signedBy;
    }
    
    public List<SelectItem> getSignedByListUninitialized() {
        List<SelectItem> signedByList = new ArrayList<>();
        for (final Object nameOfCa : casigners.keySet()) {
            int entryId = casigners.get(nameOfCa.toString());
            if (entryId == cainfo.getCAId()) {
                continue;
            }

            if (cainfo.getSignedBy() == entryId) {
                signedByList.add(new SelectItem(entryId, nameOfCa.toString(), ""));
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
            resultList.add(new SelectItem(entry.getKey(), (String) EditCaUtil.getTrimmedName(entry.getValue()), ""));
        }
        return resultList;
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
        return this.caSubjectAltName;

    }
    
    public void setCaSubjectAltName(final String subjectAltName) throws ParameterException {
        if (!caBean.checkSubjectAltName(subjectAltName)) {
            throw new ParameterException(getEjbcaWebBean().getText("INVALIDSUBJECTDN"));
        }
        this.caSubjectAltName = subjectAltName;
    }
    
    public String getPolicyId() {
        return this.policyId;
    }
    
    public void setPolicyId(final String policyId) {
        this.policyId = policyId;
    }
    
    public boolean isUseUtf8Policy() {
        return this.useUtf8Policy;
    }
    
    public void setUseUtf8Policy(final boolean utf8Policy) {
        this.useUtf8Policy = utf8Policy;
    }
    
    public boolean isUsePrintableStringSubjectDN() {
        return this.usePrintableStringSubjectDN;
    }
    
    public void setUsePrintableStringSubjectDN(final boolean usePrintableStringSubjectDN) {
        this.usePrintableStringSubjectDN = usePrintableStringSubjectDN;
    }
    
    public boolean isUseLdapDNOrder() {
        return this.useLdapDNOrder;
    }
    
    public void setUseLdapDNOrder(final boolean useLdapDNOrder) {
        this.useLdapDNOrder = useLdapDNOrder;
    }
    
    public String getNameConstraintsPermittedString() {
        return this.nameConstraintsPermitted;
    }
    
    public void setNameConstraintsPermittedString(final String nameConstraintsPermitted) {
        this.nameConstraintsPermitted = nameConstraintsPermitted;
    }

    public String getNameConstraintsExcludedString() {
        return this.nameConstraintsExcluded;
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
        return this.crlCaCRLDPExternal;
    }
    
    public void setCrlCaCRLDPExternal(final String crlCaCRLDPExternal) {
        this.crlCaCRLDPExternal = crlCaCRLDPExternal;
    }
    
    public boolean getCheckboxAuthorityKeyIdentifier() {
        return this.useAuthorityKeyIdentifier;
    }
    
    public void setCheckboxAuthorityKeyIdentifier(final boolean useAuthorityKeyIdentifier) {
        this.useAuthorityKeyIdentifier = useAuthorityKeyIdentifier;
    }
    
    public boolean getCheckboxAuthorityKeyIdentifierCritical() {
        return this.authorityKeyIdentifierCritical;
    }
    
    public void setCheckboxAuthorityKeyIdentifierCritical(final boolean authorityKeyIdentifierCritical) {
        this.authorityKeyIdentifierCritical = authorityKeyIdentifierCritical;
    }
    
    public boolean isCheckboxAuthorityKeyIdentifierCriticalDisabled() {
        if (isEditCA && catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return !x509cainfo.getUseAuthorityKeyIdentifier() || isCaexternal;
        }
        return false;
    }   
    
    public boolean getCheckboxUseCrlNumber() {
        return this.useCrlNumber;
    }
    
    public void setCheckboxUseCrlNumber(final boolean useCrlNumber) {
        this.useCrlNumber = useCrlNumber;
    }
    
    public boolean getCheckboxCrlNumberCritical() {
        return this.crlNumberCritical;
    }
    
    public void setCheckboxCrlNumberCritical(final boolean crlNumberCritical) {
        this.crlNumberCritical = crlNumberCritical;
    }
    
    public boolean isCheckboxCrlNumberCriticalDisabled() {
        if (isEditCA && catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return !x509cainfo.getUseCRLNumber() || isCaexternal;
        }
        return false;
    }
    
    public boolean getCheckboxUseCrlDistributiOnPointOnCrl() {
        return this.useCrlDistributiOnPointOnCrl;
    }
    
    public void setCheckboxUseCrlDistributiOnPointOnCrl(final boolean useCrlDistributiOnPointOnCrl) {
        this.useCrlDistributiOnPointOnCrl = useCrlDistributiOnPointOnCrl;
    }
    
    public boolean getCheckboxCrlDistributionPointOnCrlCritical() {
        return this.crlDistributionPointOnCrlCritical;
    }
    
    public void setCheckboxCrlDistributionPointOnCrlCritical(final boolean crlDistributionPointOnCrlCritical) {
        this.crlDistributionPointOnCrlCritical = crlDistributionPointOnCrlCritical;
    }
    
    public boolean isCheckboxCrlDistributionPointOnCrlCriticalDisabled() {
        if (isEditCA && catype == CAInfo.CATYPE_X509) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            return !x509cainfo.getUseCrlDistributionPointOnCrl() || isCaexternal;
        }
        return false;
    }
    
    public String getAuthorityInformationAccess() {
        return this.authorityInformationAccess;

    }
    
    public void setAuthorityInformationAccess(final String authorityInformationAccess) {
        this.authorityInformationAccess = authorityInformationAccess;
    }
    
    public boolean getCheckboxKeepExpiredOnCrl() {
        return this.keepExpiredOnCrl;
    }
    
    public void setCheckboxKeepExpiredOnCrl(final boolean checkboxKeepExpiredOnCrl) {
        this.keepExpiredOnCrl = checkboxKeepExpiredOnCrl;
    }
    
    public String getCrlCaCrlPeriod() {
        return this.crlCaCrlPeriod;

    }
    
    public void setCrlCaCrlPeriod(final String crlCaCrlPeriod) {
        this.crlCaCrlPeriod = crlCaCrlPeriod;
    }

    public String getCrlCaIssueInterval() {
        return this.crlCaIssueInterval;
    }
    
    public void setCrlCaIssueInterval(final String crlCaIssueInterval) {
        this.crlCaIssueInterval = crlCaIssueInterval;
    }   

    public String getCrlCaOverlapTime() {
        return this.crlCaOverlapTime;
    }

    public void setCrlCaOverlapTime(final String crlCaOverlapTime) {
        this.crlCaOverlapTime = crlCaOverlapTime;
    }       
    
    public String getCrlCaDeltaCrlPeriod() {
        return this.crlCaDeltaCrlPeriod;
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
    
    public List<Integer> getUsedCrlPublishers() {
        Collection<?> usedpublishers = null;
        final List<Integer> ret = new ArrayList<>();
        if (isEditCA) {
            usedpublishers = cainfo.getCRLPublishers();
        }
        Set<Integer> publishersIds = publisheridtonamemap.keySet();

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
    
    public String getDefaultCRLDistPoint() {
        return this.defaultCRLDistPoint;
    }
    
    public void setDefaultCRLDistPoint(final String defaultCRLDistPoint) {
        this.defaultCRLDistPoint = defaultCRLDistPoint;
    }       
    
    public void genDefaultCrlDistPoint() {
        if (!isEditCA) {
            this.defaultCRLDistPoint = globalconfiguration.getStandardCRLDistributionPointURINoDN() + encode(this.caSubjectDN); 
        } else {
            this.defaultCRLDistPoint = globalconfiguration.getStandardCRLDistributionPointURINoDN() + encode(cainfo.getSubjectDN());
        }
    }
    
    private String encode(final String text) {
        try {
            return URLEncoder.encode(text, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            log.error("Error while encoding text " + text, e);
        } 
        return StringUtils.EMPTY;
    }

    public String getDefaultCRLIssuer() {
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
        return this.caDefinedFreshestCRL;
    }
    
    public void setCaDefinedFreshestCRL(final String caDefinedFreshestCRL) {
        this.caDefinedFreshestCRL = caDefinedFreshestCRL;
    }
    
    public void genCaDefinedFreshestCrl() {
        if (!isEditCA) {
            this.caDefinedFreshestCRL = globalconfiguration.getStandardDeltaCRLDistributionPointURINoDN() + encode(this.caSubjectDN); 
        } else {
            this.caDefinedFreshestCRL = globalconfiguration.getStandardDeltaCRLDistributionPointURINoDN() + encode(cainfo.getSubjectDN());
        }
    } 
    
    public void genDefaultOcspLocator() {
        this.defaultOCSPServiceLocator = globalconfiguration.getStandardOCSPServiceLocatorURI();
    }
    

    public String getDefaultOCSPServiceLocator(){
        return this.defaultOCSPServiceLocator;
    }

    public void setDefaultOCSPServiceLocator(final String defaultOCSPServiceLocator) {
        this.defaultOCSPServiceLocator = defaultOCSPServiceLocator;
    }    
    
    public String getCertificateAiaDefaultCaIssuerUri() {
        return this.certificateAiaDefaultCaIssuerUri;

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
        for (int validatorId : keyValidatorMap.keySet()) {
                ret.add(new SelectItem(validatorId, keyValidatorMap.get(validatorId), "", isHasEditRight() ? false : true));
        }
        return ret;
    }

    public List<Integer> getUsedValidators() {
        Collection<?> usedValidators = null;
        final List<Integer> ret = new ArrayList<>();
        if (isEditCA) {
            usedValidators = cainfo.getValidators();
        }
        for (final int id : keyValidatorMap.keySet()) {
            if (isEditCA && usedValidators.contains(id)) {
                ret.add(id);
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
        return this.serviceCmsActive;
    }
    
    public void setCmsButtonStatus(final boolean serviceCmsActive) {
        this.serviceCmsActive = serviceCmsActive;
    }
    
    public boolean isWaitingForResponse() {
        return this.waitingresponse;
    }
    
    public boolean isRenderViewCmsCert() {
        return isEditCA && !isCaUninitialized && cmscert != null;
    }
    
    public boolean getFinishUser() {
        return this.finishUser;
    }
    
    public void setFinishUser(final boolean finishUser) {
        this.finishUser = finishUser;
    }
    
    public String getCmpRaAuthSecretValue() {
        return this.sharedCmpRaSecret;
    }
    
    public void setCmpRaAuthSecretValue(final String cmpRaAuthSecretValue) {
        this.sharedCmpRaSecret = cmpRaAuthSecretValue;
    }
    
    public boolean getIncludeInHealthCheck() {
        return this.includeInHealthCheck;
        
    }
    
    public void setIncludeInHealthCheck(final boolean includeInHealthCheck) {
        this.includeInHealthCheck = includeInHealthCheck;
    }
    
    public boolean isRenderCaLifeCycle() {
        return isEditCA && revokable && isHasEditRight();
    }
    
    public List<SelectItem> getRevokeReasonList() {
        List<SelectItem> result = new ArrayList<>();
        for (int i = 0; i < SecConst.reasontexts.length; i++) {
            if (i != 7) {
                result.add(new SelectItem(i, getEjbcaWebBean().getText(SecConst.reasontexts[i]), ""));
            }
        }
        return result;
    }

    public int getCaRevokeReason() {
        return caRevokeReason;
    }

    public void setCaRevokeReason(final int caRevokeReason) {
        this.caRevokeReason = caRevokeReason;
    }
    
    public List<String> getCertSignKeyReNewList() {
        final int cryptoTokenId = catoken==null ? currentCryptoTokenId : catoken.getCryptoTokenId();
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
        final int cryptoTokenId = catoken==null ? currentCryptoTokenId : catoken.getCryptoTokenId();
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
            return isEditCA && !isCaexternal && !waitingresponse && caBean.isCryptoTokenPresent(currentCryptoTokenId) && caBean.isCryptoTokenActive(currentCryptoTokenId) && cainfo.getSignedBy()!= CAInfo.SIGNEDBYEXTERNALCA && !isCaRevoked();
        } catch (AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean!", e);
        }
        return false;
    }
    
    private boolean isCaRevoked() {
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
    
    public boolean isCaExportable() {
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
        int numSelected = 0; // should be 1 after the loop

        List<Entry<String, String>> availableCryptoTokens = null;
        try {
            availableCryptoTokens = caBean.getAvailableCryptoTokens(signatureAlgorithmParam, isEditCA);
        } catch (AuthorizationDeniedException e) {
            log.error("Error while accessing ca bean!", e);
        }

        for (final Entry<String, String> entry : availableCryptoTokens) {
            // Ensure that we have a default for the next section
            if (cryptoTokenIdParam == null || cryptoTokenIdParam.length() == 0) {
                cryptoTokenIdParam = entry.getKey();
            }

            final boolean selectCurrent = entry.getKey().equals(cryptoTokenIdParam);
            numSelected += selectCurrent ? 1 : 0;
            if (currentCryptoTokenId == 0 || selectCurrent) {
                currentCryptoTokenId = Integer.parseInt(entry.getKey());
            }
            resultList.add(new SelectItem(entry.getKey(), entry.getValue(), ""));
        }

        if (numSelected == 0) {
            resultList.add(new SelectItem(getEjbcaWebBean().getText("CRYPTOTOKEN_MISSING_OR_EMPTY"), cryptoTokenIdParam));
            cryptoTokenIdParam = null;
            currentCryptoTokenId = 0;
        }
        return resultList;
    }

    public boolean isCryptoTokenNeedExistingOrGen() {
        return (cryptoTokenIdParam == null && !isCaUninitialized);
    }
    
    public boolean isCryptoTokenIdParamNull() {
        return cryptoTokenIdParam == null;
    }
    
    public boolean isFailedCryptoTokenExist() {
        List<Entry<String, String>> failedCryptoTokens = null;
        try {
            failedCryptoTokens = caBean.getFailedCryptoTokens(signatureAlgorithmParam);
        } catch (AuthorizationDeniedException e) {
            log.error("Error while calling ca bean!", e);
        }
        
        return failedCryptoTokens.size() != 0; 
    }
    
    public Map<String, String> failedCryptoTokenLinkMap() {
        Map<String, String> result = new HashMap<>();
        List<Entry<String, String>> failedCryptoTokens = null;
        try {
            failedCryptoTokens = caBean.getFailedCryptoTokens(signatureAlgorithmParam);
        } catch (AuthorizationDeniedException e) {
            log.error("Error while calling ca bean!", e);
        }
        
        for (final Entry<String, String> entry : failedCryptoTokens) {
            result.put(entry.getKey(), entry.getValue());
        }

        return result;
    }
    
    
    public String getCryptoTokenIdParam() {
        return cryptoTokenIdParam;
    }

    public void setCryptoTokenIdParam(final String cryptoTokenIdParam) {
        this.cryptoTokenIdParam = cryptoTokenIdParam;
        // Create already in use key map
        if (!isEditCA || isCaUninitialized) {
            generateCryptoAlreadyInUseMap();
        }
    } 
    
    public List<SelectItem> getCryptotokenDefaultKeyList() {
        List<SelectItem> resultList = new ArrayList<>();
        try {
            for (final String alias : caBean.getAvailableCryptoTokenMixedAliases(currentCryptoTokenId, signatureAlgorithmParam)) {
                final boolean isDefault;
                if (!isEditCA) {
                    isDefault = CAToken.SOFTPRIVATEDECKEYALIAS.equals(alias) || alias.contains("default") || alias.contains("Default");
                } else {
                    isDefault = alias.equals(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_DEFAULT));
                }
                if (isDefault) {
                    cryptoTokenDefaultKey = alias;
                }
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean!", e);
        }
        return resultList;
    }
    
    public List<SelectItem> getCryptotokenCertSignKeyList() {
        List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(StringUtils.EMPTY, getEjbcaWebBean().getText("CRYPTOTOKEN_DEFAULTKEY")));
        try {
            for (final String alias : caBean.getAvailableCryptoTokenAliases(currentCryptoTokenId, signatureAlgorithmParam)) {
                final boolean isDefault;
                if (!isEditCA) {
                    isDefault = CAToken.SOFTPRIVATESIGNKEYALIAS.equals(alias) || alias.contains("sign") || alias.contains("Sign");
                } else {
                    isDefault = alias.equals(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
                }
                
                if (isDefault) {
                    cryptoTokenCertSignKey = alias;
                }
                
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean!", e);
        }
        return resultList;
    }

    public List<SelectItem> getCryptotokenkeyEncryptKeyList() {
        List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(StringUtils.EMPTY, getEjbcaWebBean().getText("CRYPTOTOKEN_DEFAULTKEY")));
        try {
            for (final String alias : caBean.getAvailableCryptoTokenEncryptionAliases(currentCryptoTokenId, signatureAlgorithmParam)) {
                if (isEditCA && alias.equals(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT))) {
                    selectedKeyEncryptKey = alias;
                }
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean!", e);
        }
        return resultList;
    }

    public List<SelectItem> getCryptotokenHardTokenEncryptList() {
        List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(StringUtils.EMPTY, getEjbcaWebBean().getText("CRYPTOTOKEN_DEFAULTKEY")));
        try {
            for (final String alias : caBean.getAvailableCryptoTokenEncryptionAliases(currentCryptoTokenId, signatureAlgorithmParam)) {
                if (isEditCA && alias.equals(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT))) {
                    hardTokenEncryptKey = alias;
                }
                
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean!", e);
        }
        return resultList;
    }
    
    public List<SelectItem> getCryptotokenTestKeyList() {
        List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(StringUtils.EMPTY, getEjbcaWebBean().getText("CRYPTOTOKEN_DEFAULTKEY")));
        try {
            for (final String alias : caBean.getAvailableCryptoTokenAliases(currentCryptoTokenId, signatureAlgorithmParam)) {
                
                final boolean isDefault;
                if (!isEditCA) {
                    isDefault = alias.contains("test") || alias.contains("Test");
                } else {
                    isDefault = alias.equals(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYTEST));
                }
                
                if (isDefault) {
                    testKey = alias;
                }
                
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            log.error("Error while accessing the ca bean!", e);
        }
        return resultList;
    }
    
    
    public List<SelectItem> getExTServicesKeySpecList() {
        List<SelectItem> resultList = new ArrayList<>();
        
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
            return (cryptoTokenIdParam != null && !cryptoTokenIdParam.isEmpty() && Integer.parseInt(cryptoTokenIdParam) != 0);
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
    
    public boolean isRenderRenewCA() {
        final int cryptoTokenId = catoken == null ? currentCryptoTokenId : catoken.getCryptoTokenId();
        try {
            return isEditCA && !isCaexternal && !waitingresponse && caBean.isCryptoTokenPresent(cryptoTokenId) && 
                    caBean.isCryptoTokenActive(cryptoTokenId) && cainfo.getSignedBy()!=CAInfo.SIGNEDBYEXTERNALCA && !isCaRevoked;
        } catch (AuthorizationDeniedException e) {
            log.error("Error while accessing ca bean!", e);
        }
        return false;
    }
    
    public String caCertLink() {
        return viewCertLink + "?caid=" + currentCaId;
    }
    
    public boolean isEditCaUninitializedHasEditRights() {
        return isEditCA && isCaUninitialized && isHasEditRight();
    }
    
    public boolean isEditCaNotUninitializedHasEditRights() {
        return isEditCA && !isCaUninitialized && isHasEditRight();
    }
    
    public boolean isUseNoConflictCertificateData() {
        return this.useNoConflictCertificateData;
    }
    
    public void setUseNoConflictCertificateData(final boolean useNoConflictCertificateData) {
        this.useNoConflictCertificateData = useNoConflictCertificateData;
    }
    
    public boolean isCheckboxAcceptRevocationsNonExistingEntryDisabled() {
        return (!isHasEditRight() || useCertificateStorage);
    }
    
    public boolean isCertificateProfileForNonExistingDisabled(){
        return (!isHasEditRight() || useCertificateStorage || !acceptRevocationsNonExistingEntry);
    }
    
    public List<SelectItem> getThrowAwayDefaultProfileList() {
        TreeMap<String, Integer> allp = getEjbcaWebBean().getAuthorizedEndEntityCertificateProfileNames();
        Iterator<String> iter = allp.keySet().iterator();
        List<SelectItem> resultList = new ArrayList<>();
        while(iter.hasNext()){
            String nextprofilename = (String) iter.next();
            int certprofid = ((Integer) allp.get(nextprofilename)).intValue();
            resultList.add(new SelectItem(certprofid, nextprofilename, "", isCertificateProfileForNonExistingDisabled() ? true : false));
        }
        return resultList;
    }
    
    public void setThrowAwayDefaultProfile(final String throwAwayDefaultProfile) {
        this.throwAwayDefaultProfile = throwAwayDefaultProfile;
    }
    
    public String getThrowAwayDefaultProfile() {
        return this.throwAwayDefaultProfile;
    }
    
    public boolean isRenderCVCAvailalble() {
        return (catype == CAInfo.CATYPE_CVC) && (!caBean.isCVCAvailable() || caBean.isUniqueIssuerDNSerialNoIndexPresent());
    }
    
    public boolean isCVCAvailable() {
        return caBean.isCVCAvailable();
    }

    public String createCa() {
        boolean illegaldnoraltname = false;
        try {
            illegaldnoraltname = caBean.actionCreateCaMakeRequest(createCaName, signatureAlgorithmParam, signKeySpec, keySequenceFormat,
                    keySequenceValue, catype, caSubjectDN, currentCertProfile, defaultCertificateProfile, // TODO: this must be default certificate profile
                    useNoConflictCertificateData, signedBy, description, caEncodedValidity, getApprovals(), finishUser, doEnforceUniquePublickeys,
                    doEnforceUniqueDN, doEnforceUniqueSubjectDNSerialnumber, useCertReqHistory, useUserStorage, useCertificateStorage,
                    acceptRevocationsNonExistingEntry, caSubjectAltName, policyId, useAuthorityKeyIdentifier, authorityKeyIdentifierCritical,
                    getCrlPeriod(), getCrlIssueInterval(), getcrlOverlapTime(), getDeltaCrlPeriod(), getAvailablePublisherValues(),
                    getAvailableKeyValidatorValues(), useCrlNumber, crlNumberCritical, defaultCRLDistPoint, defaultCRLIssuer, defaultOCSPServiceLocator,
                    authorityInformationAccess, certificateAiaDefaultCaIssuerUri, nameConstraintsPermitted, nameConstraintsExcluded,
                    caDefinedFreshestCRL, useUtf8Policy, usePrintableStringSubjectDN, useLdapDNOrder, useCrlDistributiOnPointOnCrl,
                    crlDistributionPointOnCrlCritical, includeInHealthCheck, false, serviceCmsActive, sharedCmpRaSecret, keepExpiredOnCrl, true,
                    false, cryptoTokenIdParam, cryptoTokenCertSignKey, cryptoTokenCertSignKey, cryptoTokenDefaultKey, hardTokenEncryptKey,
                    selectedKeyEncryptKey, testKey, fileBuffer);
        } catch (Exception e) {
            addErrorMessage(e.getMessage());
        }

        return illegaldnoraltname ? "error" : EditCaUtil.MANAGE_CA_NAV;
    }
    
    public String saveExternalCA() {
        try {
            if (cadatahandler.getCAInfo(currentCaId).getCAInfo().getCAType()==CAInfo.CATYPE_X509) {
                X509CAInfo x509caInfo = (X509CAInfo)cadatahandler.getCAInfo(currentCaId).getCAInfo();
                x509caInfo.setExternalCdp(crlCaCRLDPExternal.trim());
                cadatahandler.editCA(x509caInfo);
            }
        } catch (CADoesntExistsException | AuthorizationDeniedException e) {
            log.error("Error happened while saving external CA!", e);
        }
        
        return EditCaUtil.MANAGE_CA_NAV;
    }
    
    public String saveCa() {
        String subjectdn = null;
        String signedByString = null;
        CAInfo cainfo = null;
        
        try {
            if (cadatahandler.getCAInfo(currentCaId).getCAInfo().getStatus() == CAConstants.CA_UNINITIALIZED) {
                subjectdn = caSubjectDN;
                signedByString = signedBy;
            } else {
                subjectdn = cadatahandler.getCAInfo(currentCaId).getCAInfo().getSubjectDN();
                signedByString = String.valueOf(cadatahandler.getCAInfo(currentCaId).getCAInfo().getSignedBy());
            }
        } catch (AuthorizationDeniedException e) {
            log.error("Error while accessing the ca data handler!", e);
        } 
        
        int defaultCertprofileId = (defaultCertificateProfile == null ? 0 : Integer.parseInt(defaultCertificateProfile));
        
        try {
            cainfo = caBean.createCaInfo(currentCaId, editCaName, subjectdn, catype,
                    keySequenceFormat, keySequenceValue, signedByString, description, caEncodedValidity,
                    getCrlPeriod(), getCrlIssueInterval(), getcrlOverlapTime(), getDeltaCrlPeriod(), finishUser,
                    doEnforceUniquePublickeys, doEnforceUniqueDN, doEnforceUniqueSubjectDNSerialnumber,
                    useCertReqHistory, useUserStorage, useCertificateStorage, acceptRevocationsNonExistingEntry,
                    defaultCertprofileId, useNoConflictCertificateData, getApprovals(),
                    getAvailablePublisherValues(), getAvailableKeyValidatorValues(), useAuthorityKeyIdentifier, authorityKeyIdentifierCritical, useCrlNumber,
                    crlNumberCritical, defaultCRLDistPoint, defaultCRLIssuer, defaultOCSPServiceLocator, 
                    authorityInformationAccess,
                    certificateAiaDefaultCaIssuerUri,
                    nameConstraintsPermitted, nameConstraintsExcluded,
                    caDefinedFreshestCRL, useUtf8Policy, usePrintableStringSubjectDN, useLdapDNOrder, useCrlDistributiOnPointOnCrl,
                    crlDistributionPointOnCrlCritical, includeInHealthCheck, false, serviceCmsActive, sharedCmpRaSecret, keepExpiredOnCrl
                    );
        } catch (Exception e) {
            addErrorMessage(e.getMessage());
        }

        try {
            cadatahandler.editCA(cainfo);
        } catch (CADoesntExistsException | AuthorizationDeniedException e) {
            addErrorMessage(e.getMessage());
        }
        
        return EditCaUtil.MANAGE_CA_NAV;
    }

    public String revokeCa() {
        try {
            cadatahandler.revokeCA(currentCaId, caRevokeReason);
        } catch (CADoesntExistsException | AuthorizationDeniedException e) {
            addErrorMessage(e.getMessage());
        }
        return EditCaUtil.MANAGE_CA_NAV;
    }

    private long getCrlIssueInterval() {
        return SimpleTime.getInstance(crlCaIssueInterval, "0" + SimpleTime.TYPE_MINUTES).getLong();
    }
    
    private long getCrlPeriod() {
        return SimpleTime.getInstance(crlCaCrlPeriod, "1" + SimpleTime.TYPE_DAYS).getLong();
    }
    
    private long getcrlOverlapTime() {
        return SimpleTime.getInstance(crlCaOverlapTime, "10" + SimpleTime.TYPE_MINUTES).getLong();
    }
    
    private long getDeltaCrlPeriod() {
        return SimpleTime.getInstance(crlCaDeltaCrlPeriod, "0" + SimpleTime.TYPE_MINUTES).getLong();
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
}
