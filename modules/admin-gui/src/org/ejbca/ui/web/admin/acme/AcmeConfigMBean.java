/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.admin.acme;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.component.html.HtmlPanelGrid;
import javax.faces.component.html.HtmlSelectOneMenu;
import javax.faces.context.FacesContext;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.accounts.AccountBindingException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiModelAware;
import org.cesecore.util.ui.DynamicUiModelException;
import org.cesecore.util.ui.PropertyValidationException;
import org.ejbca.config.AcmeConfiguration;
import org.ejbca.config.GlobalAcmeConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.protocol.acme.eab.AcmeExternalAccountBinding;
import org.ejbca.core.protocol.acme.eab.AcmeExternalAccountBindingBase;
import org.ejbca.core.protocol.acme.eab.AcmeExternalAccountBindingFactory;
import org.ejbca.ui.psm.jsf.JsfDynamicUiPsmFactory;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JavaServer Faces Managed Bean for managing ACME configuration.
 */
@ManagedBean
@ViewScoped
public class AcmeConfigMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(AcmeConfigMBean.class);
    private ListDataModel<AcmeAliasGuiInfo> aliasGuiList = null;

    private GlobalAcmeConfiguration globalAcmeConfigurationConfig;
    private AcmeAliasGuiInfo currentAlias = null;
    private AcmeGlobalGuiInfo globalInfo = null;
    private boolean currentAliasEditMode = false;
    private String currentAliasStr;
    private String newAlias = "";


    private final GlobalConfigurationSessionLocal globalConfigSession = getEjbcaWebBean().getEjb().getGlobalConfigurationSession();
    private final AuthorizationSessionLocal authorizationSession = getEjbcaWebBean().getEjb().getAuthorizationSession();
    private final EndEntityProfileSessionLocal endentityProfileSession = getEjbcaWebBean().getEjb().getEndEntityProfileSession();
    private final AuthenticationToken authenticationToken = getAdmin();
    
    
    public AcmeConfigMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
        globalAcmeConfigurationConfig = (GlobalAcmeConfiguration) globalConfigSession.getCachedConfiguration(GlobalAcmeConfiguration.ACME_CONFIGURATION_ID);
    }

    /** Force reload from underlying (cache) layer for the current ACME configuration alias */
    private void flushCache() {
        currentAlias = null;
        aliasGuiList = null;
        currentAliasEditMode = false;
        globalAcmeConfigurationConfig = (GlobalAcmeConfiguration) globalConfigSession.getCachedConfiguration(GlobalAcmeConfiguration.ACME_CONFIGURATION_ID);
        globalInfo = new AcmeGlobalGuiInfo(globalAcmeConfigurationConfig);
        uiModel = null;

    }
    /** Build a list sorted by name from the existing ACME configuration aliases */
    public ListDataModel<AcmeAliasGuiInfo> getAliasGuiList() {
        flushCache();
        final List<AcmeAliasGuiInfo> list = new ArrayList<>();
        for (String alias : globalAcmeConfigurationConfig.getAcmeConfigurationIds()) {
            list.add(new AcmeAliasGuiInfo(globalAcmeConfigurationConfig, alias));
            Collections.sort(list, (alias1, alias2) -> alias1.getAlias().compareToIgnoreCase(alias2.getAlias()));
            aliasGuiList = new ListDataModel<>(list);
        }
        // If show the list, then we are on the main page and want to flush the cache
        currentAlias = null;
        return aliasGuiList;
    }

    public void addAlias() {
        if (StringUtils.isNotEmpty(newAlias) && !globalAcmeConfigurationConfig.aliasExists(newAlias)) {
            AcmeConfiguration newConfig = new AcmeConfiguration();
            newConfig.setConfigurationId(newAlias);
            newConfig.initialize(newAlias);
            globalAcmeConfigurationConfig.updateAcmeConfiguration(newConfig);
            try {
                globalConfigSession.saveConfiguration(authenticationToken, globalAcmeConfigurationConfig);
            } catch (AuthorizationDeniedException e) {
                String msg = "Failed to add alias: " + e.getLocalizedMessage();
                log.info(msg, e);
                super.addNonTranslatedErrorMessage(msg);
            }
        } else {
            String msg = "Cannot add alias. Alias '" + newAlias + "' already exists.";
            log.info(msg);
            super.addNonTranslatedErrorMessage(msg);
        }
        flushCache();
    }

    public void renameAlias() {
        if (StringUtils.isNotEmpty(newAlias) && !globalAcmeConfigurationConfig.aliasExists(newAlias)) {
            globalAcmeConfigurationConfig.renameConfigId(newAlias, currentAliasStr);
            try {
                globalConfigSession.saveConfiguration(authenticationToken, globalAcmeConfigurationConfig);
            } catch (AuthorizationDeniedException e) {
                String msg = "Failed to rename alias: " + e.getLocalizedMessage();
                log.info(msg, e);
                super.addNonTranslatedErrorMessage(msg);
            }
        } else {
            String msg = "Cannot rename alias. Either the new alias is empty or it already exists.";
            log.info(msg);
            super.addNonTranslatedErrorMessage(msg);
        }
        flushCache();
    }

    public void deleteAlias() {
        if (globalAcmeConfigurationConfig.aliasExists(currentAliasStr)) {
            globalAcmeConfigurationConfig.removeConfigId(currentAliasStr);
            try {
                globalConfigSession.saveConfiguration(authenticationToken, globalAcmeConfigurationConfig);
            } catch (AuthorizationDeniedException e) {
                String msg = "Failed to remove alias: " + e.getLocalizedMessage();
                log.info(msg, e);
                super.addNonTranslatedErrorMessage(msg);
            }
        } else {
            String msg = "Cannot remove alias. It does not exist.";
            log.info(msg);
            super.addNonTranslatedErrorMessage(msg);
        }
        flushCache();
    }

    /** @return cached or populate a new ACME alias GUI representation for view or edit */
    public AcmeAliasGuiInfo getCurrentAlias() {
        if (this.currentAlias == null) {
            final String alias = getCurrentAliasStr();
            this.currentAlias = new AcmeAliasGuiInfo(globalAcmeConfigurationConfig, alias);
        }

        return this.currentAlias;
    }
    public String getNewAlias() {
        return newAlias;
    }

    public void setNewAlias(String newAlias) {
        this.newAlias = newAlias;
    }

    /** @return the name of the ACME alias that is subject to view or edit */
    public String getCurrentAliasStr() {
        // Get the HTTP GET/POST parameter named "alias"
        final String inputAlias = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get("alias");
        if (inputAlias != null && inputAlias.length() > 0 && !inputAlias.equals(currentAliasStr)) {
            flushCache();
            this.currentAliasStr = inputAlias;
        }
        return currentAliasStr;
    }

    /** @return a list of EndEntity profiles that this admin is authorized to, and that are usable for ACME */
    public List<SelectItem> getUsableEEProfileNames() {
        Collection<Integer> endEntityProfileIds = endentityProfileSession.getAuthorizedEndEntityProfileIds(getAdmin(), AccessRulesConstants.CREATE_END_ENTITY);
        Map<Integer, String> nameMap = endentityProfileSession.getEndEntityProfileIdToNameMap();
        final List<SelectItem> ret = new ArrayList<>();
        for (Integer id : endEntityProfileIds) {
            if (id != EndEntityConstants.EMPTY_END_ENTITY_PROFILE) {
                String name = nameMap.get(id);
                ret.add(new SelectItem(id, name));
            }
        }
        sortSelectItemsByLabel(ret);
        return ret;
    }
    
    /** Returns an information text to show below the End Entity Profile selection. */
    public String getDefaultCaText() {
        if (getUsableEEProfileNames().isEmpty()) {
            return getEjbcaWebBean().getText("ACME_MUST_HAVE_ONE_PROFILE");
        } else {
            return getEjbcaWebBean().getText("ACME_DEFAULT_CA_WILL_BE_USED");
        }
    }

    public List<SelectItem> getAliasSeletItemList() {
        final List<SelectItem> ret = new ArrayList<>();
        for (String alias : globalAcmeConfigurationConfig.getAcmeConfigurationIds()) {
            ret.add(new SelectItem(alias, alias));
        }
        return ret;
    }

    /** Invoked when admin cancels a ACME alias create or edit. */
    public void cancelCurrentAlias() {
        flushCache();
    }

    /** Invoked when admin saves the ACME alias configurations 
     * @throws EjbcaException */
    public void saveCurrentAlias() throws EjbcaException {
        if (currentAlias != null) {
            AcmeConfiguration acmeConfig = globalAcmeConfigurationConfig.getAcmeConfiguration(currentAliasStr);
            acmeConfig.setEndEntityProfileId(Integer.valueOf(currentAlias.endEntityProfileId));
            acmeConfig.setPreAuthorizationAllowed(currentAlias.isPreAuthorizationAllowed());
            acmeConfig.setWildcardCertificateIssuanceAllowed(currentAlias.isWildcardCertificateIssuanceAllowed());
            acmeConfig.setWildcardWithHttp01ChallengeAllowed(currentAlias.isWildcardWithHttp01ChallengeAllowed());
            acmeConfig.setWebSiteUrl(currentAlias.getUrlTemplate());
            acmeConfig.setDnsResolver(currentAlias.getDnsResolver());
            acmeConfig.setDnsPort(currentAlias.getDnsPort());
            acmeConfig.setDnssecTrustAnchor(currentAlias.getDnssecTrustAnchor());
            acmeConfig.setUseDnsSecValidation(currentAlias.isUseDnsSecValidation());
            acmeConfig.setTermsOfServiceRequireNewApproval(currentAlias.getTermsOfServiceApproval());
            acmeConfig.setAgreeToNewTermsOfServiceAllowed(currentAlias.getAgreeToNewTermsOfServiceAllowed());
            acmeConfig.setTermsOfServiceUrl(currentAlias.getTermsOfServiceUrl());
            acmeConfig.setTermsOfServiceChangeUrl(currentAlias.getTermsOfServiceChangeUrl());
            acmeConfig.setOrderValidity(SimpleTime.parseMillies(currentAlias.getOrderValidity()));
            acmeConfig.setRetryAfter(currentAlias.getRetryAfter());
            
            if (StringUtils.isEmpty(acmeConfig.getTermsOfServiceUrl())) {
                // Usually not invoked because the required attribute is set in facelet.
                throw new EjbcaException("Please enter Terms of Service URL");
            }
            
            acmeConfig.setRequireExternalAccountBinding(currentAlias.isRequireExternalAccountBinding());
            boolean validated = false;
            if (uiModel != null) {
                try {
                    // Copy data from dynamic UI properties.
                    // Here upload file data validation and processing is invoked.
                    uiModel.writeProperties(((AcmeExternalAccountBindingBase) currentAlias.getEab()).getRawData());
                } catch (CesecoreException e) {
                    if (e.getErrorCode().equals(ErrorCode.ACME_EAB_PARSING_FAILED)) {
                        super.addNonTranslatedErrorMessage("Failed to save uploaded file. " + e.getMessage());
                    } else {
                        super.addNonTranslatedErrorMessage("An exception occured: " + e.getMessage());
                    }
                    return;
                }
                try {
                    if (acmeConfig.isRequireExternalAccountBinding()) {
                        log.debug("Validate ACME EAB data: " + currentAlias.getEab().getDataMap());
                        uiModel.validate();
                        acmeConfig.setExternalAccountBinding(currentAlias.getEab());
                    }
                    validated = true;
                } catch (PropertyValidationException e) {
                    super.addNonTranslatedErrorMessage(e.getMessage());
                    return;
                }
            } else {
                validated = true;
            }
            
            if (validated) {
                globalAcmeConfigurationConfig.updateAcmeConfiguration(acmeConfig);
                try {
                    globalConfigSession.saveConfiguration(authenticationToken, globalAcmeConfigurationConfig);
                } catch (AuthorizationDeniedException e) {
                    String msg = "Cannot save alias. Administrator is not authorized.";
                    log.info(msg + e.getLocalizedMessage());
                    super.addNonTranslatedErrorMessage(msg);
                }
            }
        }
        flushCache();
    }
    
    public boolean isSaveCurrentAliasDisabled() {
        return getUsableEEProfileNames().isEmpty(); 
    }

    public void saveGlobalConfigs(){
        globalAcmeConfigurationConfig.setDefaultAcmeConfigurationId(globalInfo.getDefaultAcmeConfiguration());
        globalAcmeConfigurationConfig.setReplayNonceValidity(Long.valueOf(globalInfo.getReplayNonceValidity()));
        try {
            globalConfigSession.saveConfiguration(authenticationToken, globalAcmeConfigurationConfig);
        } catch (AuthorizationDeniedException e) {
            String msg = "Cannot save ACME configurations. Administrator is not authorized.";
            log.info(msg + e.getLocalizedMessage());
            super.addNonTranslatedErrorMessage(msg);
        }
    }

    public void setCurrentAliasStr(String currentAliasStr) {
        this.currentAliasStr = currentAliasStr;
    }

    public boolean isCurrentAliasEditMode() {
        return currentAliasEditMode;
    }

    public void setCurrentAliasEditMode(boolean currentAliasEditMode) {
        this.currentAliasEditMode = currentAliasEditMode && isAllowedToEdit();
    }

    public void toggleCurrentAliasEditMode() {
        currentAliasEditMode ^= true;
        currentAliasEditMode = currentAliasEditMode && isAllowedToEdit();
        // Somehow uiModel.setDisabled(false); is not effective for the first UI component, 
        // equal what component it is (textfield, textarea, etc.). So reinitialize the HTML 
        // data grid. This is related to ECA-9545.
        if (uiModel != null) {
            uiModel = null;
        }
    }
    public boolean isAllowedToEdit() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
    }

    public AcmeGlobalGuiInfo getGlobalInfo() {
        return globalInfo;
    }

    public void setGlobalInfo(AcmeGlobalGuiInfo globalInfo) {
        this.globalInfo = globalInfo;
    }

    public class AcmeAliasGuiInfo {
        private String alias;
        private String endEntityProfileId;
        private boolean preAuthorizationAllowed;
        private boolean requireExternalAccountBinding;
        private AcmeExternalAccountBinding eab;
        private String urlTemplate;
        private boolean wildcardCertificateIssuanceAllowed;
        private boolean wildcardWithHttp01ChallengeAllowed;
        private String dnsResolver;
        private int dnsPort;
        private String dnssecTrustAnchor;
        private String termsOfServiceUrl;
        private boolean termsOfServiceApproval;
        private boolean agreeToNewTermsOfServiceAllowed;
        private String termsOfServiceChangeUrl;
        private boolean useDnsSecValidation;
        private String orderValidity;
        private int retryAfter;

        public AcmeAliasGuiInfo(GlobalAcmeConfiguration globalAcmeConfigurationConfig, String alias) {
            if (alias != null) {
                this.alias = alias;
                AcmeConfiguration acmeConfiguration = globalAcmeConfigurationConfig.getAcmeConfiguration(alias);
                if(acmeConfiguration != null) {
                    this.endEntityProfileId = String.valueOf(acmeConfiguration.getEndEntityProfileId());
                    this.preAuthorizationAllowed = acmeConfiguration.isPreAuthorizationAllowed();
                    this.requireExternalAccountBinding = acmeConfiguration.isRequireExternalAccountBinding();
                    try {
                        this.eab = acmeConfiguration.getExternalAccountBinding();
                    } catch (AccountBindingException e) {
                        log.warn("Failed to initialize ACME external account binding.");
                    }
                    this.urlTemplate = acmeConfiguration.getWebSiteUrl();
                    this.wildcardCertificateIssuanceAllowed = acmeConfiguration.isWildcardCertificateIssuanceAllowed();
                    this.wildcardWithHttp01ChallengeAllowed = acmeConfiguration.isWildcardWithHttp01ChallengeAllowed();
                    this.dnsResolver = acmeConfiguration.getDnsResolver();
                    this.dnsPort = acmeConfiguration.getDnsPort();
                    this.dnssecTrustAnchor = acmeConfiguration.getDnssecTrustAnchor();
                    this.useDnsSecValidation = acmeConfiguration.isUseDnsSecValidation();
                    this.termsOfServiceUrl = String.valueOf(acmeConfiguration.getTermsOfServiceUrl());
                    this.termsOfServiceChangeUrl = String.valueOf(acmeConfiguration.getTermsOfServiceChangeUrl());
                    this.termsOfServiceApproval = acmeConfiguration.isTermsOfServiceRequireNewApproval();
                    this.agreeToNewTermsOfServiceAllowed = acmeConfiguration.isAgreeToNewTermsOfServiceAllowed();
                    this.orderValidity = SimpleTime.getInstance(acmeConfiguration.getOrderValidity()).toString();
                    this.retryAfter = acmeConfiguration.getRetryAfter();
                }
            }
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = alias;
        }

        public String getEndEntityProfileId() {
            return endEntityProfileId;
        }

        public void setEndEntityProfileId(String endEntityProfileId) {
            this.endEntityProfileId = endEntityProfileId;
        }

        public boolean isPreAuthorizationAllowed() {
            return preAuthorizationAllowed;
        }

        public void setPreAuthorizationAllowed(boolean preAuthorizationAllowed) {
            this.preAuthorizationAllowed = preAuthorizationAllowed;
        }

        public boolean isRequireExternalAccountBinding() {
            return requireExternalAccountBinding;
        }

        public void setRequireExternalAccountBinding(boolean requireExternalAccountBinding) {
            this.requireExternalAccountBinding = requireExternalAccountBinding;
        }
        
        public AcmeExternalAccountBinding getEab() {
            return eab;
        }
        
        public void setEab(AcmeExternalAccountBinding eab) {
            this.eab = eab;
        }

        public String getUrlTemplate() {
            return urlTemplate;
        }

        public void setUrlTemplate(String urlTemplate) {
            this.urlTemplate = urlTemplate;
        }

        public boolean isWildcardCertificateIssuanceAllowed() {
            return wildcardCertificateIssuanceAllowed;
        }

        public void setWildcardCertificateIssuanceAllowed(boolean wildcardCertificateIssuanceAllowed) {
            this.wildcardCertificateIssuanceAllowed = wildcardCertificateIssuanceAllowed;
        }
        
        public boolean isWildcardWithHttp01ChallengeAllowed() {
            return wildcardWithHttp01ChallengeAllowed;
        }

        public void setWildcardWithHttp01ChallengeAllowed(boolean allowed) {
            this.wildcardWithHttp01ChallengeAllowed = allowed;
        }
        
        public String getDnssecTrustAnchor() {
            return dnssecTrustAnchor;
        }

        public void setDnssecTrustAnchor(String dnssecTrustAnchor) {
            this.dnssecTrustAnchor = dnssecTrustAnchor;
        }

        public String getDnsResolver() {
            return dnsResolver;
        }

        public void setDnsResolver(String dnsResolver) {
            this.dnsResolver = dnsResolver;
        }
        
        public int getDnsPort() {
            return dnsPort;
        }

        public void setDnsPort(final int dnsPort) {
            this.dnsPort = dnsPort;
        }
        
        public String getOrderValidity() {
            return orderValidity;
        }

        public void setOrderValidity(String orderValidity) {
            this.orderValidity = orderValidity;
        }

        public int getRetryAfter() {
            return retryAfter;
        }

        public void setRetryAfter(final int retryAfter) {
            this.retryAfter = retryAfter;
        }

        public String getTermsOfServiceUrl() {
            return termsOfServiceUrl;
        }

        public void setTermsOfServiceUrl(String termsOfServiceUrl) {
            this.termsOfServiceUrl = termsOfServiceUrl;
        }
        
        public String getTermsOfServiceChangeUrl() {
            return termsOfServiceChangeUrl;
        }

        public void setTermsOfServiceChangeUrl(String url) {
            this.termsOfServiceChangeUrl = url;
        }

        public boolean getTermsOfServiceApproval() {
            return termsOfServiceApproval;
        }

        public void setTermsOfServiceApproval(final boolean termsOfServiceApproval) {
            this.termsOfServiceApproval = termsOfServiceApproval;
        }
        
        public boolean getAgreeToNewTermsOfServiceAllowed() {
            return agreeToNewTermsOfServiceAllowed;
        }

        public void setAgreeToNewTermsOfServiceAllowed(final boolean allowed) {
            this.agreeToNewTermsOfServiceAllowed = allowed;
        }
        
        public boolean isUseDnsSecValidation() {
            return useDnsSecValidation;
        }
        
        public void setUseDnsSecValidation (final boolean useDnsSecValidation) {
            this.useDnsSecValidation = useDnsSecValidation;
        }
        
    }
    public class AcmeGlobalGuiInfo {
        private String defaultAcmeConfiguration;
        private String replayNonceValidity;

        public AcmeGlobalGuiInfo(GlobalAcmeConfiguration globalAcmeConfigurationConfig) {
            this.defaultAcmeConfiguration = globalAcmeConfigurationConfig.getDefaultAcmeConfigurationId();
            this.replayNonceValidity = String.valueOf(globalAcmeConfigurationConfig.getReplayNonceValidity());
        }

        public String getDefaultAcmeConfiguration() {
            return defaultAcmeConfiguration;
        }

        public void setDefaultAcmeConfiguration(String defaultAcmeConfiguration) {
            this.defaultAcmeConfiguration = defaultAcmeConfiguration;
        }

        public String getReplayNonceValidity() {
            return replayNonceValidity;
        }

        public void setReplayNonceValidity(String replayNonceValidity) {
            this.replayNonceValidity = replayNonceValidity;
        }
    }
    
    // ACME external account binding (EAB)
    
    /** Dynamic UI PIM component. */
    private DynamicUiModel uiModel;

    /** Dynamic UI PSM component. */
    private HtmlPanelGrid dataGrid;
    
    /**
     * Gets the selected EAB.
     * @return the EAB or null if no EAB is selected.
     */
    public AcmeExternalAccountBinding getEab() {
        // (Re-)initialize dynamic UI PSM.        
        final AcmeExternalAccountBinding eab = currentAlias.eab;
        if (eab instanceof DynamicUiModelAware) {
            if (uiModel == null || !uiModel.equals(((DynamicUiModelAware) eab).getDynamicUiModel())) {
                ((DynamicUiModelAware) eab).initDynamicUiModel();
                uiModel = ((DynamicUiModelAware) eab).getDynamicUiModel();
                if (log.isDebugEnabled()) {
                    log.debug("Request dynamic UI properties for ACME EAB with (id=" + eab.getProfileId() + ") with properties " + eab.getFilteredDataMapForLogging());
                }
                try {
                    initGrid(uiModel, eab.getClass().getSimpleName());
                } catch (DynamicUiModelException e) {
                    log.warn("Could not initialize dynamic UI PSM: " + e.getMessage(), e);
                }
            }
        }
        return eab;
     }
    
    /**
     * Sets the current external account binding EAB.
     * @param eab the EAB.
     */
    public void setEab(final AcmeExternalAccountBinding eab) {
        currentAlias.eab = eab;
    }

   /**
    * Gets the dynamic UI properties PSM component as HTML data grid.
    * @return the data grid.
    */
   public HtmlPanelGrid getDataGrid() {
       return dataGrid;
   }

   /**
    * Sets the dynamic UI properties PSM component as HTML data grid.
    * @param dataGrid the data grid.
    */
   public void setDataGrid(final HtmlPanelGrid dataGrid) {
       this.dataGrid = dataGrid;
   }
   
   /**
    * Initializes the dynamic UI model grid panel.
    * @param pim the PIM.
    * @param prefix the HTML components ID prefix.
    * @throws DynamicUiModelException if the PSM could not be created.
    */
   private void initGrid(final DynamicUiModel pim, final String prefix) throws DynamicUiModelException {
       if (dataGrid == null) {
           dataGrid = new HtmlPanelGrid();
           dataGrid.setId(getClass().getSimpleName()+"-dataGrid");
       }
       uiModel.setDisabled(!this.isAllowedToEdit() || !currentAliasEditMode || !currentAlias.requireExternalAccountBinding);
       JsfDynamicUiPsmFactory.initGridInstance(dataGrid, pim, prefix);
   }
   
   /**
    * Gets the available ACME EAB types.
    *
    * @return List of the available EAB types.
    */
   public List<SelectItem> getAvailableEabs() {
       final List<Class<?>> excludeClasses = new ArrayList<>();
       final List<SelectItem> result = new ArrayList<>();
       for (final AcmeExternalAccountBinding eab : AcmeExternalAccountBindingFactory.INSTANCE.getAllImplementations(excludeClasses)) {
           result.add(new SelectItem(eab.getAccountBindingTypeIdentifier(), eab.getLabel()));
       }
       Collections.sort(result, new Comparator<SelectItem>() {
           @Override
           public int compare(SelectItem o1, SelectItem o2) {
               return o1.getLabel().compareToIgnoreCase(o2.getLabel());
           }
       });
       return result;
   }
   
   /**
    * Processes the EAB type changed event and renders the concrete EAB implementation view. 
    * 
    * @param e the event.
    * @throws DynamicUiModelException if the PSM could not be initialized.
    */
   public void eabTypeChanged(final AjaxBehaviorEvent e) throws DynamicUiModelException {
       setEabType((String) ((HtmlSelectOneMenu) e.getComponent()).getValue());
       FacesContext.getCurrentInstance().renderResponse();
   }
   
   public String getEabType() {
       final AcmeExternalAccountBinding eab = getEab();
       return eab == null ? null : eab.getAccountBindingTypeIdentifier();
   }
   
   public void setEabType(final String type) {
       if (type != null && currentAlias != null && currentAlias.eab != null) {
           String oldType = currentAlias.eab.getAccountBindingTypeIdentifier();
           if (!type.equals(oldType)) {
               try {
                   currentAlias.eab = AcmeExternalAccountBindingFactory.INSTANCE.getArcheType(type);
                   currentAlias.eab.init();
                   if (log.isDebugEnabled()) {
                       log.debug("Changed EAB type from '" + oldType + "' to '" + type + "'.");
                   }
               } catch (AccountBindingException e) {
                   log.warn("Failed to initialize ACME external account binding.");
               }
           }
       }
   }
   
   public void toggleCurrentEabEditMode(AjaxBehaviorEvent e) {
       FacesContext.getCurrentInstance().renderResponse();
   }
   
}
