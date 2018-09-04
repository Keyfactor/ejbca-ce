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

import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.AcmeConfiguration;
import org.ejbca.config.GlobalAcmeConfiguration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JavaServer Faces Managed Bean for managing ACME configuration.
 *
 * @version $Id: AcmeConfigMBean.java 28125 2018-01-29 16:41:28Z bastianf $
 */
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
        super();
        globalAcmeConfigurationConfig = (GlobalAcmeConfiguration) globalConfigSession.getCachedConfiguration(GlobalAcmeConfiguration.ACME_CONFIGURATION_ID);
    }

    /** Force reload from underlying (cache) layer for the current ACME configuration alias */
    private void flushCache() {
        currentAlias = null;
        aliasGuiList = null;
        currentAliasEditMode = false;
        globalAcmeConfigurationConfig = (GlobalAcmeConfiguration) globalConfigSession.getCachedConfiguration(GlobalAcmeConfiguration.ACME_CONFIGURATION_ID);
        globalInfo = new AcmeGlobalGuiInfo(globalAcmeConfigurationConfig);

    }
    /** Build a list sorted by name from the existing ACME configuration aliases */
    public ListDataModel<AcmeAliasGuiInfo> getAliasGuiList() {
        flushCache();
        final List<AcmeAliasGuiInfo> list = new ArrayList<>();
        for (String alias : globalAcmeConfigurationConfig.getAcmeConfigurationIds()) {
            list.add(new AcmeAliasGuiInfo(globalAcmeConfigurationConfig, alias));
            Collections.sort(list, new Comparator<AcmeAliasGuiInfo>() {
                @Override
                public int compare(AcmeAliasGuiInfo alias1, AcmeAliasGuiInfo alias2) {
                    return alias1.getAlias().compareToIgnoreCase(alias2.getAlias());
                }
            });
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
        if (inputAlias != null && inputAlias.length() > 0) {
            if (!inputAlias.equals(currentAliasStr)) {
                flushCache();
                this.currentAliasStr = inputAlias;
            }
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

    /** Invoked when admin saves the ACME alias configurations */
    public void saveCurrentAlias() {
        if (currentAlias != null) {
            AcmeConfiguration acmeConfig = globalAcmeConfigurationConfig.getAcmeConfiguration(currentAliasStr);
            acmeConfig.setEndEntityProfileId(Integer.valueOf(currentAlias.endEntityProfileId));
            acmeConfig.setPreAuthorizationAllowed(currentAlias.isPreAuthorizationAllowed());
            acmeConfig.setRequireExternalAccountBinding(currentAlias.isRequireExternalAccountBinding());
            acmeConfig.setWildcardCertificateIssuanceAllowed(currentAlias.isWildcardCertificateIssuanceAllowed());
            acmeConfig.setWebSiteUrl(currentAlias.getUrlTemplate());
            acmeConfig.setDnsResolver(currentAlias.getDnsResolver());
            acmeConfig.setDnsPort(currentAlias.getDnsPort());
            acmeConfig.setDnssecTrustAnchor(currentAlias.getDnssecTrustAnchor());
            acmeConfig.setUseDnsSecValidation(currentAlias.isUseDnsSecValidation());
            acmeConfig.setTermsOfServiceRequireNewApproval(currentAlias.getTermsOfServiceApproval());
            
            if (StringUtils.isNotEmpty(currentAlias.getTermsOfServiceUrl())) {
                acmeConfig.setTermsOfServiceUrl(currentAlias.getTermsOfServiceUrl());
            }
            globalAcmeConfigurationConfig.updateAcmeConfiguration(acmeConfig);
            try {
                globalConfigSession.saveConfiguration(authenticationToken, globalAcmeConfigurationConfig);
            } catch (AuthorizationDeniedException e) {
                String msg = "Cannot save alias. Administrator is not authorized.";
                log.info(msg + e.getLocalizedMessage());
                super.addNonTranslatedErrorMessage(msg);
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
        private String urlTemplate;
        private boolean wildcardCertificateIssuanceAllowed;
        private String dnsResolver;
        private int dnsPort;
        private String dnssecTrustAnchor;
        private String termsOfServiceUrl;
        private boolean termsOfServiceApproval;
        private boolean useDnsSecValidation;

        public AcmeAliasGuiInfo(GlobalAcmeConfiguration globalAcmeConfigurationConfig, String alias) {
            if (alias != null) {
                this.alias = alias;
                AcmeConfiguration acmeConfiguration = globalAcmeConfigurationConfig.getAcmeConfiguration(alias);
                if(acmeConfiguration != null) {
                    this.endEntityProfileId = String.valueOf(acmeConfiguration.getEndEntityProfileId());
                    this.preAuthorizationAllowed = acmeConfiguration.isPreAuthorizationAllowed();
                    this.requireExternalAccountBinding = acmeConfiguration.isRequireExternalAccountBinding();
                    this.urlTemplate = acmeConfiguration.getWebSiteUrl();
                    this.wildcardCertificateIssuanceAllowed = acmeConfiguration.isWildcardCertificateIssuanceAllowed();
                    this.dnsResolver = acmeConfiguration.getDnsResolver();
                    this.dnsPort = acmeConfiguration.getDnsPort();
                    this.dnssecTrustAnchor = acmeConfiguration.getDnssecTrustAnchor();
                    this.termsOfServiceUrl = String.valueOf(acmeConfiguration.getTermsOfServiceUrl());
                    this.useDnsSecValidation = acmeConfiguration.isUseDnsSecValidation();
                    this.termsOfServiceApproval = acmeConfiguration.isTermsOfServiceRequireNewApproval();
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

        public String getTermsOfServiceUrl() {
            return termsOfServiceUrl;
        }

        public void setTermsOfServiceUrl(String termsOfServiceUrl) {
            this.termsOfServiceUrl = termsOfServiceUrl;
        }

        public boolean getTermsOfServiceApproval() {
            return termsOfServiceApproval;
        }

        public void setTermsOfServiceApproval(final boolean termsOfServiceApproval) {
            this.termsOfServiceApproval = termsOfServiceApproval;
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
}
