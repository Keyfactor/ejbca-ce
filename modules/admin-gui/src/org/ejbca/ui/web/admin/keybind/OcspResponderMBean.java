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
package org.ejbca.ui.web.admin.keybind;

import java.io.Serializable;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.extension.OCSPExtension;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.PatternLogger;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding.ResponderIdType;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.core.ejb.ocsp.OcspResponseGeneratorSessionLocal;

/**
 *
 */
public class OcspResponderMBean extends InternalKeyBindingMBeanBase {

    private static final long serialVersionUID = 1L;

    private static final String OCSP_KEY_BINDING = "OcspKeyBinding";

    private final AuthenticationToken authenticationToken = getAdmin();

    private String defaultResponderTarget;
    private Boolean nonceEnabled;
    private OcspKeyBinding.ResponderIdType responderIdType;
    private Boolean ocspSigningCacheUpdate;
    private Boolean cacheHeaderUnauthorizedResponses;
    private String auditLogMessage = "";
    private String transactionLogMessage = "";
    private boolean isOcspTransactionLoggingEnabled;
    private String ocspTransactionLogPattern;
    private String ocspTransactionLogValues;
    private boolean isOcspAuditLoggingEnabled;
    private String ocspAuditLogPattern;
    private String ocspAuditLogValues;
    private String ocspLoggingDateFormat;


    private String currentOcspExtension = null;
    private ListDataModel<InternalKeyBindingTrustEntry> signOcspResponseForCas = null;
    private ListDataModel<String> ocspExtensions = null;
    private Map<String, String> ocspExtensionOidNameMap = new HashMap<>();
    private Boolean useIssuerNotBeforeAsArchiveCutoff;
    private SimpleTime retentionPeriod;

    private Integer currentCertificateAuthorityOcspRespToSign = null;
    private String currentTrustEntryDescriptionOcspRespToSign = null;

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private InternalKeyBindingMgmtSessionLocal internalKeyBindingSession;
    @EJB(description = "Used to reload ocsp signing cache when user disables the internal ocsp key binding.")
    private OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession;

    @PostConstruct
    public void loadOcspLoggingSettings() {
        final GlobalOcspConfiguration globalConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        isOcspTransactionLoggingEnabled = globalConfiguration.getIsOcspTransactionLoggingEnabled();
        ocspTransactionLogPattern = globalConfiguration.getOcspTransactionLogPattern();
        ocspTransactionLogValues = globalConfiguration.getOcspTransactionLogValues();
        isOcspAuditLoggingEnabled = globalConfiguration.getIsOcspAuditLoggingEnabled();
        ocspAuditLogPattern = globalConfiguration.getOcspAuditLogPattern();
        ocspAuditLogValues = globalConfiguration.getOcspAuditLogValues();
        ocspLoggingDateFormat = globalConfiguration.getOcspLoggingDateFormat();
    }

    @Override
    public String getSelectedInternalKeyBindingType() {
        return OCSP_KEY_BINDING;
    }
    
    @Override
    protected String getKeybindingTypeName() {
        return "OCSP Responder";
    }

    @Override
    protected void flushSingleViewCache() {
        super.flushSingleViewCache();
        signOcspResponseForCas = null;
        ocspExtensions = null;
        retentionPeriod = null;
        useIssuerNotBeforeAsArchiveCutoff = null;
        currentTrustEntryDescriptionOcspRespToSign = null;
    }

    @Override
    protected void flushCurrentCache() {
        super.flushCurrentCache();
        if (NumberUtils.isNumber(getCurrentInternalKeyBindingId()) && !("0".equals(getCurrentInternalKeyBindingId()))) {     
            signOcspResponseForCas = null;
            retentionPeriod = null;
            useIssuerNotBeforeAsArchiveCutoff = null;
            currentTrustEntryDescriptionOcspRespToSign = null;
        }
    }

    public void saveDefaultResponder() {
        GlobalOcspConfiguration globalConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        if (StringUtils.isEmpty(defaultResponderTarget) && StringUtils.isNotEmpty(globalConfiguration.getOcspDefaultResponderReference())) {
            globalConfiguration.setOcspDefaultResponderReference("");
            try {
                globalConfigurationSession.saveConfiguration(authenticationToken, globalConfiguration);
            } catch (AuthorizationDeniedException e) {
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
            }
        } else if (!StringUtils.equals(defaultResponderTarget, globalConfiguration.getOcspDefaultResponderReference())) {
            globalConfiguration.setOcspDefaultResponderReference(defaultResponderTarget);
            try {
                globalConfigurationSession.saveConfiguration(authenticationToken, globalConfiguration);
            } catch (AuthorizationDeniedException e) {
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
            }
        }
    }

    public void saveNonceEnabled() {
        GlobalOcspConfiguration globalConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        if (!nonceEnabled.equals(globalConfiguration.getNonceEnabled())) {
            globalConfiguration.setNonceEnabled(nonceEnabled);
            try {
                globalConfigurationSession.saveConfiguration(authenticationToken, globalConfiguration);
            } catch (AuthorizationDeniedException e) {
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
            }
        }
    }

    public void saveResponderIdType() {
        GlobalOcspConfiguration globalConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        if (!responderIdType.equals(globalConfiguration.getOcspResponderIdType())) {
            globalConfiguration.setOcspResponderIdType(responderIdType);
            try {
                globalConfigurationSession.saveConfiguration(authenticationToken, globalConfiguration);
            } catch (AuthorizationDeniedException e) {
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
            }
        }
    }

    public void saveEnableOcspSigningCacheUpdate() {
        GlobalOcspConfiguration globalConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        if (!ocspSigningCacheUpdate.equals(globalConfiguration.getOcspSigningCacheUpdateEnabled())) {
            globalConfiguration.setOcspSigningCacheUpdateEnabled(ocspSigningCacheUpdate);
            try {
                globalConfigurationSession.saveConfiguration(authenticationToken, globalConfiguration);
            } catch (AuthorizationDeniedException e) {
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
            }
        }
    }

    public void saveEnableExplicitNoCacheUnauthorizedResponses() {
        GlobalOcspConfiguration globalConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        if (!cacheHeaderUnauthorizedResponses.equals(globalConfiguration.getExplicitNoCacheUnauthorizedResponsesEnabled())) {
            globalConfiguration.setExplicitNoCacheUnauthorizedResponsesEnabled(cacheHeaderUnauthorizedResponses);
            try {
                globalConfigurationSession.saveConfiguration(authenticationToken, globalConfiguration);
            } catch (AuthorizationDeniedException e) {
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
            }
        }
    }

    public boolean getGloballyEnableNonce() {
        GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        return configuration.getNonceEnabled();
    }

    public void setGloballyEnableNonce(boolean nonceEnabled) {
        this.nonceEnabled = nonceEnabled;
    }

    public boolean getGloballyEnableOcspSigningCacheUpdate() {
        GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        return configuration.getOcspSigningCacheUpdateEnabled();
    }

    public void setGloballyEnableOcspSigningCacheUpdate(final boolean ocspSigningCacheUpdateEnabled) {
        this.ocspSigningCacheUpdate = ocspSigningCacheUpdateEnabled;
    }

    public boolean getCacheHeaderUnauthorizedResponses() {
        GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        return configuration.getExplicitNoCacheUnauthorizedResponsesEnabled();
    }

    public void setCacheHeaderUnauthorizedResponses(final boolean cacheHeaderUnauthorizedResponses) {
        this.cacheHeaderUnauthorizedResponses = cacheHeaderUnauthorizedResponses;
    }

    public void saveOcspLoggingConfiguration() throws AuthorizationDeniedException {
        final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        configuration.setIsOcspAuditLoggingEnabled(isOcspAuditLoggingEnabled);
        configuration.setIsOcspTransactionLoggingEnabled(isOcspTransactionLoggingEnabled);
        configuration.setOcspAuditLogPattern(ocspAuditLogPattern);
        configuration.setOcspTransactionLogPattern(ocspTransactionLogPattern);
        configuration.setOcspAuditLogValues(ocspAuditLogValues);
        configuration.setOcspTransactionLogValues(ocspTransactionLogValues);
        configuration.setOcspLoggingDateFormat(ocspLoggingDateFormat);
        globalConfigurationSession.saveConfiguration(getAdmin(), configuration);
    }

    public String getDefaultResponderTarget() {
        GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        String reference = configuration.getOcspDefaultResponderReference();
        if (reference == null) {
            this.defaultResponderTarget = "";
        } else {

            this.defaultResponderTarget = reference;
        }

        return this.defaultResponderTarget;
    }

    public void setDefaultResponderTarget(String defaultResponderTarget) {
        this.defaultResponderTarget = defaultResponderTarget;
    }

    public OcspKeyBinding.ResponderIdType getResponderIdType() {
        GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        responderIdType = configuration.getOcspResponderIdType();
        return responderIdType;
    }

    public void setResponderIdType(final OcspKeyBinding.ResponderIdType responderIdType) {
        this.responderIdType = responderIdType;
    }

    @SuppressWarnings("unchecked")
    public List<SelectItem/*<String,String>*/> getDefaultResponderTargets() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem("", super.getEjbcaWebBean().getText("INTERNALKEYBINDING_OCSPKEYBINDING_NODEFAULTRESPONDER")));
        //Create a map so that we can exclude bounded CAs.
        String currentValue = getDefaultResponderTarget();
        boolean currentValueMatched = false;
        Set<String> internalkeybindingSet = new HashSet<>();
        for (final GuiInfo guiInfo : (List<GuiInfo>) getInternalKeyBindingGuiList().getWrappedData()) {
            if (guiInfo.getStatus().equalsIgnoreCase(GuiInfo.TEXTKEY_PREFIX + InternalKeyBindingStatus.ACTIVE.name())) {
                internalkeybindingSet.add(guiInfo.getCertificateIssuerDn());
                ret.add(new SelectItem(guiInfo.getCertificateIssuerDn(), "OCSPKeyBinding: " + guiInfo.getName()));
                if (currentValue.equals(guiInfo.getCertificateIssuerDn())) {
                    currentValueMatched = true;
                }
            }
        }
        for (CAInfo caInfo : caSession.getAuthorizedAndEnabledCaInfos(authenticationToken)) {
            if (caInfo.getCAType() == CAInfo.CATYPE_X509 && caInfo.getStatus() == CAConstants.CA_ACTIVE) {
                //Checking actual certificate, because CA subject DN does not have to be CA certificate subject DN
                final String caSubjectDn = CertTools.getSubjectDN(new ArrayList<>(caInfo.getCertificateChain()).get(0));
                if (!internalkeybindingSet.contains(caSubjectDn)) {
                    //Skip CAs already represented by an internal keybinding
                    ret.add(new SelectItem(caSubjectDn, "CA: " + caInfo.getName()));
                    if (currentValue.equals(caSubjectDn)) {
                        currentValueMatched = true;
                    }
                }
            }
        }
        if (currentValueMatched == false && !StringUtils.isEmpty(currentValue)) {
            ret.add(new SelectItem(currentValue, "Unmatched DN: " + currentValue));
        }

        return ret;
    }

    public List<SelectItem> getResponderIdTargets() {
        List<SelectItem> selectItemList = new ArrayList<>();
        for (ResponderIdType responderIdType : ResponderIdType.values()) {
            selectItemList.add(new SelectItem(responderIdType, responderIdType.getLabel()));
        }
        return selectItemList;
    }

    @Override
    /** Invoked when the user wants to disable an InternalKeyBinding */
    public void commandDisable() {
        super.commandDisable();
        ocspResponseGeneratorSession.reloadOcspSigningCache(); // Force a reload of OcspSigningCache to make disable take effect immediately.
    }

    public String commandTestOcspAuditLogging() {
        try {
            final GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            ocspConfiguration.setIsOcspAuditLoggingEnabled(true);
            ocspConfiguration.setOcspAuditLogValues(ocspAuditLogValues);
            ocspConfiguration.setOcspAuditLogPattern(ocspAuditLogPattern);
            final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            final X509Certificate dummyCertificate = CertTools.genSelfCert("CN=Dummy Certificate", 10L, "1.1.1.1", keys.getPrivate(),
                    keys.getPublic(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, true, BouncyCastleProvider.PROVIDER_NAME);
            final byte[] requestBytes = new OCSPReqBuilder()
                    .addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), dummyCertificate, dummyCertificate.getSerialNumber()))
                    .build().getEncoded();
            final AuditLogger auditLogger = new AuditLogger(Hex.toHexString(requestBytes), 2, GuidHolder.INSTANCE.getGlobalUid(), "127.0.0.1",
                    ocspConfiguration);
            auditLogger.paramPut(AuditLogger.OCSPRESPONSE, "(OCSP-Response -> Bytes)");
            auditLogger.paramPut(PatternLogger.STATUS, "(Ocsp-Request-Status -> Int)");
            auditLogger.paramPut(PatternLogger.PROCESS_TIME, "(Process-Time -> Int)");
            auditLogMessage = auditLogger.interpolate();
            return "";
        } catch (Exception e) {
            auditLogMessage = e.getMessage();
            return "";
        }
    }

    public String commandTestOcspTransactionLogging() {
        try {
            final GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            ocspConfiguration.setIsOcspTransactionLoggingEnabled(true);
            ocspConfiguration.setOcspTransactionLogValues(ocspTransactionLogValues);
            ocspConfiguration.setOcspTransactionLogPattern(ocspTransactionLogPattern);
            final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            final X509Certificate dummyCertificate = CertTools.genSelfCert("CN=Dummy Certificate", 10L, "1.1.1.1", keys.getPrivate(),
                    keys.getPublic(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, true, BouncyCastleProvider.PROVIDER_NAME);
            new OCSPReqBuilder()
                    .addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), dummyCertificate, dummyCertificate.getSerialNumber()))
                    .build().getEncoded();
            final TransactionLogger transactionLogger = new TransactionLogger(1, GuidHolder.INSTANCE.getGlobalUid(), "127.0.0.1", ocspConfiguration);
            transactionLogger.paramPut(PatternLogger.STATUS, "(Ocsp-Request-Status -> Int)");
            transactionLogger.paramPut(TransactionLogger.REQ_NAME, "(Requestor-Name -> String)");
            transactionLogger.paramPut(TransactionLogger.REQ_NAME_RAW, "(Requestor-Name-Raw -> String)");
            transactionLogger.paramPut(TransactionLogger.SIGN_ISSUER_NAME_DN, "(Ocsp-Signer-Issuer-Dn -> String)");
            transactionLogger.paramPut(TransactionLogger.SIGN_SUBJECT_NAME, "(Ocsp-Signer-Subject-Name -> String)");
            transactionLogger.paramPut(TransactionLogger.SIGN_SERIAL_NO, "(Ocsp-Signer-Serial-No -> Int)");
            transactionLogger.paramPut(TransactionLogger.NUM_CERT_ID, "(Cert-ID -> Int");
            transactionLogger.paramPut(TransactionLogger.ISSUER_NAME_DN, "(Issuer-Name-Dn -> String");
            transactionLogger.paramPut(TransactionLogger.ISSUER_NAME_DN_RAW, "(Issuer-Name-Dn-Raw) -> String");
            transactionLogger.paramPut(PatternLogger.ISSUER_NAME_HASH, "(Issuer-Name-Hash -> String)");
            transactionLogger.paramPut(TransactionLogger.OCSP_CERT_ISSUER_NAME_DN, "(OCSP-Issuer-Name-Dn -> String");
            transactionLogger.paramPut(TransactionLogger.OCSP_CERT_ISSUER_NAME_DN_RAW, "(OCSP-Issuer-Name-Dn-Raw) -> String");
            transactionLogger.paramPut(PatternLogger.ISSUER_KEY, "(Issuer-Key -> String)");
            transactionLogger.paramPut(TransactionLogger.DIGEST_ALGOR, "(Digest-Algorithm -> String)");
            transactionLogger.paramPut(PatternLogger.SERIAL_NOHEX, "(Certificate-Serial-No -> String)");
            transactionLogger.paramPut(TransactionLogger.CERT_STATUS, "(Cert-Status -> Int)");
            transactionLogger.paramPut(PatternLogger.PROCESS_TIME, "(Process-Time -> Int)");
            transactionLogger.paramPut(TransactionLogger.CERT_PROFILE_ID, "(Cert-Profile-Id -> Int)");
            transactionLogger.paramPut(TransactionLogger.FORWARDED_FOR, "(X-Forwarded-For -> String)");
            transactionLogger.paramPut(TransactionLogger.REV_REASON, "(Revocation-Reason -> String)");
            transactionLogMessage = transactionLogger.interpolate();
            return "";
        } catch (Exception e) {
            transactionLogMessage = e.getMessage();
            return "";
        }
    }

    public void setIsOcspTransactionLoggingEnabled(final boolean isOcspTransactionLoggingEnabled) {
        this.isOcspTransactionLoggingEnabled = isOcspTransactionLoggingEnabled;
    }

    public boolean getIsOcspTransactionLoggingEnabled() {
        return isOcspTransactionLoggingEnabled;
    }

    public void setOcspTransactionLogPattern(final String ocspTransactionLogPattern) {
        this.ocspTransactionLogPattern = StringUtils.strip(ocspTransactionLogPattern);
    }

    public String getOcspTransactionLogPattern() {
        return ocspTransactionLogPattern;
    }

    public void setOcspTransactionLogValues(final String ocspTransactionLogValues) {
        this.ocspTransactionLogValues = StringUtils.strip(ocspTransactionLogValues);
    }

    public String getOcspTransactionLogValues() {
        return ocspTransactionLogValues;
    }

    public void setIsOcspAuditLoggingEnabled(final boolean isOcspAuditLoggingEnabled) {
        this.isOcspAuditLoggingEnabled = isOcspAuditLoggingEnabled;
    }

    public boolean getIsOcspAuditLoggingEnabled() {
        return isOcspAuditLoggingEnabled;
    }

    public void setOcspAuditLogPattern(final String ocspAuditLogPattern) {
        this.ocspAuditLogPattern = StringUtils.strip(ocspAuditLogPattern);
    }

    public String getOcspAuditLogPattern() {
        return ocspAuditLogPattern;
    }

    public void setOcspAuditLogValues(final String ocspAuditLogValues) {
        this.ocspAuditLogValues = StringUtils.strip(ocspAuditLogValues);
    }

    public String getOcspAuditLogValues() {
        return ocspAuditLogValues;
    }

    public void setOcspLoggingDateFormat(final String ocspLoggingDateFormat) {
        this.ocspLoggingDateFormat = StringUtils.strip(ocspLoggingDateFormat);
    }

    public String getOcspLoggingDateFormat() {
        return ocspLoggingDateFormat;
    }

    public String getOcspTransactionLogMessage() {
        return transactionLogMessage;
    }

    public String getOcspAuditLogMessage() {
        return auditLogMessage;
    }

    public String getTransactionLogMessage() {
        return transactionLogMessage;
    }

    public String getAuditLogMessage() {
        return auditLogMessage;
    }

    public Integer getCurrentCertificateAuthorityOcspRespToSign() {
        return currentCertificateAuthorityOcspRespToSign;
    }

    public void setCurrentCertificateAuthorityOcspRespToSign(Integer currentCertificateAuthorityOcspRespToSign) {
        this.currentCertificateAuthorityOcspRespToSign = currentCertificateAuthorityOcspRespToSign;
    }

    public String getCurrentOcspExtension() {
        return currentOcspExtension;
    }

    public void setCurrentOcspExtension(String currentOcspExtension) {
        this.currentOcspExtension = currentOcspExtension;
    }

    public boolean getUseIssuerNotBeforeAsArchiveCutoff() {
        try {
            if (useIssuerNotBeforeAsArchiveCutoff == null) {
                final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingSession.getInternalKeyBinding(authenticationToken,
                        Integer.parseInt(getCurrentInternalKeyBindingId()));
                useIssuerNotBeforeAsArchiveCutoff = ocspKeyBinding != null && ocspKeyBinding.getUseIssuerNotBeforeAsArchiveCutoff();
            }
            return useIssuerNotBeforeAsArchiveCutoff;
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return false;
        }
    }

    public void setUseIssuerNotBeforeAsArchiveCutoff(final boolean useIssuerNotBeforeAsArchiveCutoff) {
        this.useIssuerNotBeforeAsArchiveCutoff = useIssuerNotBeforeAsArchiveCutoff;
    }

    public String getRetentionPeriod() {
        try {
            if (retentionPeriod == null) {
                final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingSession.getInternalKeyBinding(authenticationToken,
                        Integer.parseInt(getCurrentInternalKeyBindingId()));
                retentionPeriod = ocspKeyBinding == null ? SimpleTime.getInstance("1y") : ocspKeyBinding.getRetentionPeriod();
            }
            return retentionPeriod.toString();
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    public void setRetentionPeriod(final String retentionPeriod) {
        this.retentionPeriod = SimpleTime.getInstance(retentionPeriod);
    }

    /** @return a list of all CAs without (active and inactive) OCSP key binding */
    public List<SelectItem/*<Integer,String>*/> getAvailableCertificateAuthoritiesForOcspSign() {
        
        final Map<Integer, String> caIdToNameMap = 
                                    internalKeyBindingSession.getAllCaWithoutOcspKeyBinding();
        final List<SelectItem> availableCertificateAuthorities = new ArrayList<>();
                                
        for (final Entry<Integer, String> caIdToNameMapEntry : caIdToNameMap.entrySet()) {
                availableCertificateAuthorities.add(new SelectItem(caIdToNameMapEntry.getKey(), 
                                                                        caIdToNameMapEntry.getValue()));
        }
        if (currentCertificateAuthorityOcspRespToSign == null && !availableCertificateAuthorities.isEmpty()) {
            currentCertificateAuthorityOcspRespToSign = (Integer) availableCertificateAuthorities.get(0).getValue();
        }
        availableCertificateAuthorities.sort((o1, o2) -> o1.getLabel().compareToIgnoreCase(o2.getLabel()));
        return availableCertificateAuthorities;
    }

    public List<SelectItem> getAvailableOcspExtensions() {
        final List<SelectItem> ocspExtensionItems = new ArrayList<>();
        ServiceLoader<OCSPExtension> serviceLoader = ServiceLoader.load(OCSPExtension.class);
        for (OCSPExtension extension : serviceLoader) {
            ocspExtensionItems.add(new SelectItem(extension.getOid(), extension.getName()));
            ocspExtensionOidNameMap.put(extension.getOid(), extension.getName());
        }
        if (currentOcspExtension == null && !ocspExtensionItems.isEmpty()) {
            currentOcspExtension = (String) ocspExtensionItems.get(0).getValue();
        }
        return ocspExtensionItems;
    }

    public ListDataModel<String> getOcspExtensions() {
        if (ocspExtensions == null) {
            final int internalKeyBindingId = Integer.parseInt(getCurrentInternalKeyBindingId());
            if (internalKeyBindingId == 0) {
                ocspExtensions = new ListDataModel<>(new ArrayList<String>());
            } else {
                try {
                    final InternalKeyBinding internalKeyBinding = internalKeyBindingSession.getInternalKeyBindingReference(
                            authenticationToken, internalKeyBindingId);
                    ocspExtensions = new ListDataModel<>(internalKeyBinding.getOcspExtensions());
                } catch (AuthorizationDeniedException e) {
                    FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(e.getMessage()));
                }
            }
        }
        return ocspExtensions;
    }

    @SuppressWarnings("unchecked")
    public void addOcspExtension() {
        final List<String> ocspExtensionsCurrent = (List<String>) getOcspExtensions().getWrappedData();
        if (!ocspExtensionsCurrent.contains(getCurrentOcspExtension())) {
            ocspExtensionsCurrent.add(getCurrentOcspExtension());
        } else {
            FacesContext.getCurrentInstance().addMessage(null,
                new FacesMessage(FacesMessage.SEVERITY_ERROR, ocspExtensionOidNameMap.get(getCurrentOcspExtension()) + " is already selected", null));
        }
        ocspExtensions.setWrappedData(ocspExtensionsCurrent);
    }

    @SuppressWarnings("unchecked")
    public void removeOcspExtension() {
        final List<String> ocspExtensionsCurrent = (List<String>) getOcspExtensions().getWrappedData();
        ocspExtensionsCurrent.remove(ocspExtensions.getRowData());
        ocspExtensions.setWrappedData(ocspExtensionsCurrent);
    }

    private String getOcspExtensionNameFromOid(String oid) {
        return ocspExtensionOidNameMap.get(oid) == null ? "" : ocspExtensionOidNameMap.get(oid);
    }
    
    public String getOcspExtensionDisplayName() {
        return getOcspExtensionNameFromOid(getOcspExtensionOid());
    }
    
    public String getOcspExtensionOid() {
        return ocspExtensions.getRowData();
    }
    
    public String getCurrentTrustEntryDescriptionOcspRespToSign() {
        return currentTrustEntryDescriptionOcspRespToSign;
    }
    
    public void setCurrentTrustEntryDescriptionOcspRespToSign(String description) {
        this.currentTrustEntryDescriptionOcspRespToSign = description;
    }
    
    public String getSignOcspResponseForCasCaName() {
        return caSession.getCAIdToNameMap().get(signOcspResponseForCas.getRowData().getCaId());
    }
    

    public ListDataModel<InternalKeyBindingTrustEntry> getSignOcspResponseForCas() {
        if (signOcspResponseForCas == null) {
            final int internalKeyBindingId = Integer.parseInt(getCurrentInternalKeyBindingId());
            if (internalKeyBindingId == 0) {
                signOcspResponseForCas = new ListDataModel<>(new ArrayList<InternalKeyBindingTrustEntry>());
            } else {
                try {
                    final InternalKeyBinding internalKeyBinding = internalKeyBindingSession.getInternalKeyBindingReference(
                            authenticationToken, internalKeyBindingId);
                    signOcspResponseForCas = new ListDataModel<>(internalKeyBinding.getSignOcspResponseOnBehalf());
                } catch (AuthorizationDeniedException e) {
                    FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(e.getMessage()));
                }
            }
        }
        return signOcspResponseForCas;
    }
    
    public boolean isOcspArchiveCutoffExtensionEnabled() {
        @SuppressWarnings("unchecked")
        final List<String> enabledOcspExtensions = (List<String>) getOcspExtensions().getWrappedData();
        return enabledOcspExtensions.stream().anyMatch(enabledOcspExtension -> OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId().equals(enabledOcspExtension));
    }
    
    /** Invoked when the user wants to a new entry to the list of OCSP signed recipient certificate references */
    @SuppressWarnings("unchecked")
    public void addCaToSignOcspResponse() {
        final List<InternalKeyBindingTrustEntry> caIssuedCertsToSign = 
                (List<InternalKeyBindingTrustEntry>) getSignOcspResponseForCas().getWrappedData();
        caIssuedCertsToSign.add(new InternalKeyBindingTrustEntry(getCurrentCertificateAuthorityOcspRespToSign(), 
                                                  null, currentTrustEntryDescriptionOcspRespToSign));
        signOcspResponseForCas.setWrappedData(caIssuedCertsToSign);
        currentTrustEntryDescriptionOcspRespToSign="";
    }

    /** Invoked when the user wants to remove an entry to the list of OCSP signed recipient certificate references */
    @SuppressWarnings("unchecked")
    public void removeCaToSignOcspResponse() {
        final InternalKeyBindingTrustEntry trustEntry = (signOcspResponseForCas.getRowData());
        final List<InternalKeyBindingTrustEntry> caIssuedCertsToSign = 
                (List<InternalKeyBindingTrustEntry>) getSignOcspResponseForCas().getWrappedData();
        caIssuedCertsToSign.remove(trustEntry);
        signOcspResponseForCas.setWrappedData(caIssuedCertsToSign);
    }

    
    /** Invoked when the user is done configuring a new InternalKeyBinding and wants to persist it */
    @SuppressWarnings("unchecked")
    @Override
    public void createNew() {
        if (getCurrentCryptoToken() == null) {
            // Should not happen
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,
                    "No Crypto Token exists when trying to create a new Key Binding with name " + getCurrentName(), null));
        } else {
            //Make sure that the crypto token actually has keys
            CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(getCurrentCryptoToken());
            try {
                if (cryptoToken.getAliases().isEmpty()) {
                    // Should not happen
                    FacesContext.getCurrentInstance().addMessage(null,
                            new FacesMessage(FacesMessage.SEVERITY_ERROR, "Selected crypto token contains no keys", null));
                    return;
                }
            } catch (KeyStoreException e) {
                FacesContext.getCurrentInstance().addMessage(null,
                        new FacesMessage(FacesMessage.SEVERITY_ERROR, "Selected crypto token has not been initialized.", null));
                return;
            } catch (CryptoTokenOfflineException e1) {
                FacesContext.getCurrentInstance().addMessage(null,
                        new FacesMessage(FacesMessage.SEVERITY_ERROR, "Selected crypto token is offline.", null));
                return;
            }

            try {
                final Map<String, Serializable> dataMap = new HashMap<>();
                final List<DynamicUiProperty<? extends Serializable>> internalKeyBindingProperties = (List<DynamicUiProperty<? extends Serializable>>) getInternalKeyBindingPropertyList()
                        .getWrappedData();
                for (final DynamicUiProperty<? extends Serializable> property : internalKeyBindingProperties) {
                    dataMap.put(property.getName(), property.getValue());
                }
                setCurrentInternalKeybindingId(String.valueOf(internalKeyBindingSession.createInternalKeyBinding(authenticationToken,
                        getSelectedInternalKeyBindingType(), getCurrentName(), InternalKeyBindingStatus.DISABLED, null,
                        getCurrentCryptoToken().intValue(), getCurrentKeyPairAlias(), getCurrentSignatureAlgorithm(), dataMap,
                        (List<InternalKeyBindingTrustEntry>) getTrustedCertificates().getWrappedData())));

                List<String> exts = (List<String>) ocspExtensions.getWrappedData();
                final InternalKeyBinding internalKeyBinding = internalKeyBindingSession.getInternalKeyBinding(authenticationToken,
                        Integer.parseInt(getCurrentInternalKeyBindingId()));

                if (exts != null && !exts.isEmpty()) {
                    // If we have some OCSP extensions, these are not created above, so we have to merge again
                    internalKeyBinding.setOcspExtensions(exts);
                }

                List<InternalKeyBindingTrustEntry> signOcspResponseForCas = null;
                if (!Objects.isNull(this.signOcspResponseForCas.getWrappedData())) {
                    signOcspResponseForCas = (List<InternalKeyBindingTrustEntry>) this.signOcspResponseForCas.getWrappedData();
                } else {
                    signOcspResponseForCas = new ArrayList<InternalKeyBindingTrustEntry>();
                }
                internalKeyBinding.setSignOcspResponseOnBehalf(signOcspResponseForCas);
                // we save an empty list for sign on behalf of CAs
                setCurrentInternalKeybindingId(
                        String.valueOf(internalKeyBindingSession.persistInternalKeyBinding(authenticationToken, internalKeyBinding)));

                FacesContext.getCurrentInstance().addMessage(null,
                        new FacesMessage(getCurrentName() + " created with ID " + getCurrentInternalKeyBindingId()));
                setInEditMode(false);
            } catch (
                    AuthorizationDeniedException | InternalKeyBindingNameInUseException | CryptoTokenOfflineException | InvalidAlgorithmException
                    | InternalKeyBindingNonceConflictException e) {
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
            }
        }
    }
    
    @SuppressWarnings("unchecked")
    public void saveCurrent() throws InternalKeyBindingNonceConflictException {
        try {
            final InternalKeyBinding internalKeyBinding = internalKeyBindingSession.getInternalKeyBinding(authenticationToken,
                    Integer.parseInt(getCurrentInternalKeyBindingId()));
            internalKeyBinding.setName(getCurrentName());
            if (isCryptoTokenActive()) {
                final int loadedCryptoTokenId = internalKeyBinding.getCryptoTokenId();
                final String loadedKeyPairAlias = internalKeyBinding.getKeyPairAlias();
                if (loadedCryptoTokenId != getCurrentCryptoToken().intValue() || !loadedKeyPairAlias.equals(getCurrentKeyPairAlias())) {
                    // Since we have changed the referenced key, the referenced certificate (if any) is no longer valid
                    internalKeyBinding.setCertificateId(null);
                }
                internalKeyBinding.setCryptoTokenId(getCurrentCryptoToken().intValue());
                internalKeyBinding.setKeyPairAlias(getCurrentKeyPairAlias());
                internalKeyBinding.setSignatureAlgorithm(getCurrentSignatureAlgorithm());
                if (getCurrentKeyPairAlias() == null || getCurrentKeyPairAlias().length() == 0) {
                    internalKeyBinding.setNextKeyPairAlias(null);
                } else {
                    internalKeyBinding.setNextKeyPairAlias(getCurrentKeyPairAlias());
                }
            }
            internalKeyBinding.setTrustedCertificateReferences((List<InternalKeyBindingTrustEntry>) getTrustedCertificates().getWrappedData());
                final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBinding;
                ocspKeyBinding.setOcspExtensions((List<String>) ocspExtensions.getWrappedData());
                if (retentionPeriod != null) {
                    ocspKeyBinding.setRetentionPeriod(retentionPeriod);
                }
                if (useIssuerNotBeforeAsArchiveCutoff != null) {
                    ocspKeyBinding.setUseIssuerNotBeforeAsArchiveCutoff(useIssuerNotBeforeAsArchiveCutoff);
                }
                List<InternalKeyBindingTrustEntry> signOcspResponseForCas = null;
                if (!Objects.isNull(this.signOcspResponseForCas.getWrappedData())) {
                    signOcspResponseForCas = (List<InternalKeyBindingTrustEntry>) this.signOcspResponseForCas.getWrappedData();
                } else {
                    signOcspResponseForCas = new ArrayList<InternalKeyBindingTrustEntry>();
                }
                ocspKeyBinding.setSignOcspResponseOnBehalf(signOcspResponseForCas);
            
            final List<DynamicUiProperty<? extends Serializable>> internalKeyBindingProperties = (List<DynamicUiProperty<? extends Serializable>>) getInternalKeyBindingPropertyList()
                    .getWrappedData();
            for (final DynamicUiProperty<? extends Serializable> property : internalKeyBindingProperties) {
                if ( "enableNonce".equals(property.getName()) && "true".equals(property.getValue().toString())
                        && internalKeyBinding.getCertificateId() != null) {
                    CertificateDataWrapper certificateDataWrapper = certificateStoreSession.getCertificateData(internalKeyBinding.getCertificateId());
                    if (certificateDataWrapper == null) {
                        continue;
                    }
                    CertificateData certificateData = certificateDataWrapper.getCertificateData();
                    String caFingerprint = certificateData.getCaFingerprint();
                    CertificateDataWrapper caCertificateDataWrapper = certificateStoreSession.getCertificateData(caFingerprint);
                    if (caCertificateDataWrapper == null) {
                        continue;
                    }
                    Certificate caCertificate = caCertificateDataWrapper.getCertificate();

                    List<CAInfo> caInfos = caSession.getAuthorizedCaInfos(authenticationToken);
                    for (CAInfo caInfo : caInfos) {
                        if (CAInfo.CATYPE_X509 == caInfo.getCAType() && caInfo.getCertificateChain() != null
                                && !caInfo.getCertificateChain().isEmpty()) {
                            Certificate caCert = caInfo.getCertificateChain().get(0);
                            if (caCert.equals(caCertificate) && ((X509CAInfo) caInfo).isDoPreProduceOcspResponses()) {
                                throw new InternalKeyBindingNonceConflictException("Can not save OCSP Key Binding with nonce enabled in response when"
                                        + " the associated CA has pre-production of OCSP responses enabled.");
                            }
                        }
                    }
                }

                internalKeyBinding.setProperty(property.getName(), property.getValue());
            }
            setCurrentInternalKeybindingId(
                    String.valueOf(internalKeyBindingSession.persistInternalKeyBinding(authenticationToken, internalKeyBinding)));
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(getCurrentName() + " saved"));
        } catch (AuthorizationDeniedException | InternalKeyBindingNameInUseException | InternalKeyBindingNonceConflictException
                | IllegalArgumentException e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
        }
    }

}
