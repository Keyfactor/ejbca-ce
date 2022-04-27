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
package org.ejbca.ui.web.admin.configuration;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.util.SelectItemComparator;

/**
 * JavaServer Faces Managed Bean for managing SCEP configuration.
 * 
 */
@ManagedBean
@SessionScoped
public class ScepConfigMBean extends BaseManagedBean implements Serializable {

    private static final String HIDDEN_PWD = "**********";

    /** GUI table representation of a SCEP alias that can be interacted with. */
    public class ScepAliasGuiInfo {
        private String alias;
        private String mode;
        private boolean includeCA;
        private boolean returnCaChainInGetCaCert;
        private boolean allowLegacyDigestAlgorithm;
        private String raCertProfile;
        private String raEEProfile;
        private String raAuthPassword;
        private String raDefaultCA;
        private String raNameGenScheme;
        private String raNameGenParameters;
        private String raNameGenPrefix;
        private String raNameGenPostfix;
        private boolean clientCertificateRenewal;
        private boolean allowClientCertificateRenewaWithOldKey;
        
        private boolean useIntune;
        private String intuneAuthority;
        private String intuneAadAppId;
        private boolean intuneAadUseKeyBinding;
        private String intuneAadAppKey;
        private String intuneAadAppKeyBinding;
        private String intuneTenant;
        private String intuneResourceUrl;
        private String intuneGraphApiVersion;
        private String intuneGraphResourceUrl;
        private String intuneProxyHost;
        private String intuneProxyPort;
        private String intuneProxyUser;
        private String intuneProxyPass;

        private ScepAliasGuiInfo(ScepConfiguration scepConfig, String alias) {
            if (alias != null) {
                this.alias = alias;
                if (scepConfig.aliasExists(alias)) {
                    this.mode = (scepConfig.getRAMode(alias) ? ScepConfiguration.Mode.RA.getResource() : ScepConfiguration.Mode.CA.getResource());
                    this.includeCA = scepConfig.getIncludeCA(alias);
                    this.returnCaChainInGetCaCert = scepConfig.getReturnCaChainInGetCaCert(alias);
                    this.allowLegacyDigestAlgorithm = scepConfig.getAllowLegacyDigestAlgorithm(alias);
                    this.raCertProfile = scepConfig.getRACertProfile(alias);
                    this.raEEProfile = scepConfig.getRAEndEntityProfile(alias);
                    this.raAuthPassword = ScepConfigMBean.HIDDEN_PWD;
                    this.raDefaultCA = scepConfig.getRADefaultCA(alias);
                    this.raNameGenScheme = scepConfig.getRANameGenerationScheme(alias);
                    this.raNameGenParameters = scepConfig.getRANameGenerationParameters(alias);
                    this.raNameGenPrefix = scepConfig.getRANameGenerationPrefix(alias);
                    this.raNameGenPostfix = scepConfig.getRANameGenerationPostfix(alias);
                    this.clientCertificateRenewal = scepConfig.getClientCertificateRenewal(alias);
                    this.allowClientCertificateRenewaWithOldKey = scepConfig.getAllowClientCertificateRenewalWithOldKey(alias);
                    this.setUseIntune(scepConfig.getUseIntune(alias));
                    this.intuneAadUseKeyBinding = scepConfig.getIntuneAadUseKeyBinding(alias);
                    this.intuneAadAppKeyBinding = scepConfig.getIntuneAadAppKeyBinding(alias);
                    this.intuneAuthority = scepConfig.getIntuneAuthority(alias);
                    this.intuneAadAppId = scepConfig.getIntuneAadAppId(alias);
                    this.intuneAadAppKey = ScepConfigMBean.HIDDEN_PWD;
                    this.intuneTenant = scepConfig.getIntuneTenant(alias);
                    this.intuneResourceUrl = scepConfig.getIntuneResourceUrl(alias);
                    this.intuneGraphApiVersion = scepConfig.getIntuneGraphApiVersion(alias);
                    this.intuneGraphResourceUrl = scepConfig.getIntuneGraphResourceUrl(alias);
                    this.intuneProxyHost = scepConfig.getIntuneProxyHost(alias);
                    this.intuneProxyPort = scepConfig.getIntuneProxyPort(alias);
                    this.intuneProxyUser = scepConfig.getIntuneProxyUser(alias);
                    this.intuneProxyPass = ScepConfigMBean.HIDDEN_PWD;
                } else {
                    this.mode = ScepConfiguration.DEFAULT_OPERATION_MODE.toUpperCase();
                    this.includeCA = Boolean.valueOf(ScepConfiguration.DEFAULT_INCLUDE_CA);
                    this.returnCaChainInGetCaCert = Boolean.valueOf(ScepConfiguration.DEFAULT_RETURN_CA_CHAIN_IN_GETCACERT);
                    this.allowLegacyDigestAlgorithm = Boolean.valueOf(ScepConfiguration.DEFAULT_ALLOW_LEGACY_DIGEST_ALGORITHM);
                    this.raCertProfile = ScepConfiguration.DEFAULT_RA_CERTPROFILE;
                    this.raEEProfile = ScepConfiguration.DEFAULT_RA_ENTITYPROFILE;
                    this.raAuthPassword = ScepConfiguration.DEFAULT_RA_AUTHPWD;
                    this.raDefaultCA = ScepConfiguration.DEFAULT_RA_DEFAULTCA;
                    this.raNameGenScheme = ScepConfiguration.DEFAULT_RA_NAME_GENERATION_SCHEME;
                    this.raNameGenParameters = ScepConfiguration.DEFAULT_RA_NAME_GENERATION_PARAMETERS;
                    this.raNameGenPrefix = ScepConfiguration.DEFAULT_RA_NAME_GENERATION_PREFIX;
                    this.raNameGenPostfix = ScepConfiguration.DEFAULT_RA_NAME_GENERATION_POSTFIX;
                    this.clientCertificateRenewal = Boolean.valueOf(ScepConfiguration.DEFAULT_CLIENT_CERTIFICATE_RENEWAL);
                    this.allowClientCertificateRenewaWithOldKey = Boolean
                            .valueOf(ScepConfiguration.DEFAULT_ALLOW_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY);
                    this.setUseIntune(false);
                    this.intuneAuthority = "";
                    this.intuneAadAppId = "";
                    this.intuneAadAppKey = "";
                    this.intuneAadAppKeyBinding = "";
                    this.intuneAadUseKeyBinding = false;
                    this.intuneTenant = "";
                    this.intuneResourceUrl = "";
                    this.intuneGraphApiVersion = "";
                    this.intuneGraphResourceUrl = "";
                    this.intuneProxyHost = "";
                    this.intuneProxyPort = "";
                    this.intuneProxyUser = "";
                    this.intuneProxyPass = "";
                }
            }
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = alias;
        }

        public String getMode() {
            return mode;
        }

        public void setMode(String mode) {
            this.mode = mode;
        }
        
        public boolean isModeRa() {
            return ScepConfiguration.Mode.RA.getResource().equals(mode);
        }
        public boolean isModeCa() {
            return ScepConfiguration.Mode.CA.getResource().equals(mode);
        }

        public boolean isIncludeCA() {
            return includeCA;
        }

        public void setIncludeCA(boolean includeca) {
            this.includeCA = includeca;
        }
        
        public boolean isAllowLegacyDigestAlgorithm() {
            return allowLegacyDigestAlgorithm;
        }
        
        public void setAllowLegacyDigestAlgorithm(boolean allowLegacyDigestAlgorithm) {
            this.allowLegacyDigestAlgorithm = allowLegacyDigestAlgorithm;
        }
        
        public String getRaCertProfile() {
            return raCertProfile;
        }

        public void setRaCertProfile(String cp) {
            this.raCertProfile = cp;
        }

        public String getRaEEProfile() {
            return raEEProfile;
        }

        public void setRaEEProfile(String eep) {
            this.raEEProfile = eep;
        }

        public String getRaDefaultCA() {
            return raDefaultCA;
        }

        public void setRaDefaultCA(String caname) {
            this.raDefaultCA = caname;
        }

        public String getRaAuthPassword() {
            return this.raAuthPassword;
        }

        public void setRaAuthPassword(String raAuthPwd) {
            this.raAuthPassword = raAuthPwd;
        }

        public String getRaNameGenScheme() {
            return raNameGenScheme;
        }

        public void setRaNameGenScheme(String scheme) {
            this.raNameGenScheme = scheme;
        }

        public boolean isRaNameGenSchemeFixed() {
            return "FIXED".equals(raNameGenScheme);
        }

        public boolean isRaNameGenSchemeDn() {
            return "DN".equals(raNameGenScheme);
        }

        public String getRaNameGenParams() {
            return raNameGenParameters;
        }

        public void setRaNameGenParams(String params) {
            this.raNameGenParameters = params;
        }

        public String getRaNameGenPrefix() {
            return raNameGenPrefix;
        }

        public void setRaNameGenPrefix(String prefix) {
            this.raNameGenPrefix = prefix;
        }

        public String getRaNameGenPostfix() {
            return raNameGenPostfix;
        }

        public void setRaNameGenPostfix(String postfix) {
            this.raNameGenPostfix = postfix;
        }

        public boolean getClientCertificateRenewal() {
            return this.clientCertificateRenewal;
        }

        public void setClientCertificateRenewal(boolean clientCertificateRenewal) {
            this.clientCertificateRenewal = clientCertificateRenewal;
        }

        public boolean getAllowClientCertificateRenewaWithOldKey() {
            return this.allowClientCertificateRenewaWithOldKey;
        }

        public void setAllowClientCertificateRenewaWithOldKey(boolean allowClientCertificateRenewaWithOldKey) {
            this.allowClientCertificateRenewaWithOldKey = allowClientCertificateRenewaWithOldKey;
        }

        public boolean isUseIntune() {
            return useIntune;
        }

        public void setUseIntune(boolean useIntune) {
            this.useIntune = useIntune;
        }
        
        public String getIntuneAuthority() {
            return intuneAuthority;
        }

        public void setIntuneAuthority(String intuneAuthority) {
            this.intuneAuthority = intuneAuthority;
        }
        
        public String getIntuneAadAppId() {
            return intuneAadAppId;
        }

        public void setIntuneAadAppId(String intuneAadAppId) {
            this.intuneAadAppId = intuneAadAppId;
        }

        public String getIntuneAadAppKey() {
            return intuneAadAppKey;
        }

        public void setIntuneAadAppKey(String intuneAadAppKey) {
            this.intuneAadAppKey = intuneAadAppKey;
        }

        public String getIntuneTenant() {
            return intuneTenant;
        }

        public void setIntuneTenant(String intuneTenant) {
            this.intuneTenant = intuneTenant;
        }
       
        public String getIntuneResourceUrl() {
            return intuneResourceUrl;
        }

        public void setIntuneResourceUrl(String intuneResourceUrl) {
            this.intuneResourceUrl = intuneResourceUrl;
        }

        public String getIntuneGraphApiVersion() {
            return intuneGraphApiVersion;
        }

        public void setIntuneGraphApiVersion(String intuneGraphApiVersion) {
            this.intuneGraphApiVersion = intuneGraphApiVersion;
        }

        public String getIntuneGraphResourceUrl() {
            return intuneGraphResourceUrl;
        }

        public void setIntuneGraphResourceUrl(String intuneGraphResourceUrl) {
            this.intuneGraphResourceUrl = intuneGraphResourceUrl;
        }
            
        public String getIntuneProxyHost() {
            return intuneProxyHost;
        }

        public void setIntuneProxyHost(String intuneProxyHost) {
            this.intuneProxyHost = intuneProxyHost;
        }

        public String getIntuneProxyPort() {
            return intuneProxyPort;
        }

        public void setIntuneProxyPort(String intuneProxyPort) {
            this.intuneProxyPort = intuneProxyPort;
        }

        public String getIntuneProxyUser() {
            return intuneProxyUser;
        }

        public void setIntuneProxyUser(String intuneProxyUser) {
            this.intuneProxyUser = intuneProxyUser;
        }

        public String getIntuneProxyPass() {
            return intuneProxyPass;
        }

        public void setIntuneProxyPass(String intuneProxyPass) {
            this.intuneProxyPass = intuneProxyPass;
        }

        public String getIntuneAadAppKeyBinding() {
            return intuneAadAppKeyBinding;
        }

        public void setIntuneAadAppKeyBinding(String intuneAadKeyBinding) {
            this.intuneAadAppKeyBinding = intuneAadKeyBinding;
        }

        public boolean isIntuneAadUseKeyBinding() {
            return intuneAadUseKeyBinding;
        }

        public void setIntuneAadUseKeyBinding(boolean intuneAadUseKeyBinding) {
            this.intuneAadUseKeyBinding = intuneAadUseKeyBinding;
        }

        public boolean isReturnCaChainInGetCaCert() {
            return returnCaChainInGetCaCert;
        }

        public void setReturnCaChainInGetCaCert(boolean returnCaChainInGetCaCert) {
            this.returnCaChainInGetCaCert = returnCaChainInGetCaCert;
        }
    }

    private static final long serialVersionUID = 2L;
    private static final Logger log = Logger.getLogger(ScepConfigMBean.class);

    private ListDataModel<ScepAliasGuiInfo> aliasGuiList = null;
    private String currentAliasStr;
    private ScepAliasGuiInfo currentAlias = null;
    private String newAlias = "";
    private ScepConfiguration scepConfig;
    private boolean currentAliasEditMode = false;

    private final GlobalConfigurationSessionLocal globalConfigSession = getEjbcaWebBean().getEjb().getGlobalConfigurationSession();
    private final AuthorizationSessionLocal authorizationSession = getEjbcaWebBean().getEjb().getAuthorizationSession();
    private final AuthenticationToken authenticationToken = getAdmin();
    private final CaSessionLocal caSession = getEjbcaWebBean().getEjb().getCaSession();
    private final CertificateProfileSessionLocal certProfileSession = getEjbcaWebBean().getEjb().getCertificateProfileSession();
    private final EndEntityProfileSessionLocal endentityProfileSession = getEjbcaWebBean().getEjb().getEndEntityProfileSession();
    private final EnterpriseEditionEjbBridgeSessionLocal editionEjbBridgeSession = (EnterpriseEditionEjbBridgeSessionLocal)getEjbcaWebBean().getEnterpriseEjb();
    
    public ScepConfigMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
        scepConfig = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
    }

    /** Force reload from underlying (cache) layer for the current SCEP configuration alias */
    private void flushCache() {
        currentAlias = null;
        aliasGuiList = null;
        currentAliasEditMode = false;
        scepConfig = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
    }

    public String getNewAlias() {
        return newAlias;
    }

    public void setNewAlias(String na) {
        newAlias = na;
    }

    public boolean isCurrentAliasEditMode() {
        return currentAliasEditMode;
    }

    public boolean isAllowedToEdit() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
    }
    
    public void setCurrentAliasEditMode(boolean currentAliasEditMode) {
        this.currentAliasEditMode = currentAliasEditMode && isAllowedToEdit();
    }

    public void toggleCurrentAliasEditMode() {
        currentAliasEditMode ^= true;
        currentAliasEditMode = currentAliasEditMode && isAllowedToEdit();
    }

    /** Build a list sorted by name from the existing SCEP configuration aliases */
    public ListDataModel<ScepAliasGuiInfo> getAliasGuiList() {
        flushCache();
        final List<ScepAliasGuiInfo> list = new ArrayList<>();
        for (String alias : scepConfig.getAliasList()) {
            list.add(new ScepAliasGuiInfo(scepConfig, alias));
            Collections.sort(list, new Comparator<ScepAliasGuiInfo>() {
                @Override
                public int compare(ScepAliasGuiInfo alias1, ScepAliasGuiInfo alias2) {
                    return alias1.getAlias().compareToIgnoreCase(alias2.getAlias());
                }
            });
            aliasGuiList = new ListDataModel<>(list);
        }
        // If show the list, then we are on the main page and want to flush the cache
        currentAlias = null;
        return aliasGuiList;
    }

    public void setCurrentAliasStr(String as) {
        currentAliasStr = as;
    }

    /** @return the name of the Scep alias that is subject to view or edit */
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

    /** @return cached or populate a new SCEP alias GUI representation for view or edit */
    public ScepAliasGuiInfo getCurrentAlias() {
        if (this.currentAlias == null) {
            final String alias = getCurrentAliasStr();
            this.currentAlias = new ScepAliasGuiInfo(scepConfig, alias);
        }

        return this.currentAlias;
    }

    /** Invoked when admin saves the SCEP alias configurations */
    public void saveCurrentAlias() {
        if (currentAlias != null) {
            String alias = currentAlias.getAlias();
            scepConfig.setRAMode(alias, "ra".equalsIgnoreCase(currentAlias.getMode()));
            scepConfig.setIncludeCA(alias, currentAlias.isIncludeCA());
            scepConfig.setReturnCaChainInGetCaCert(alias, currentAlias.isReturnCaChainInGetCaCert());
            scepConfig.setAllowLegacyDigestAlgorithm(alias, currentAlias.allowLegacyDigestAlgorithm);
            scepConfig.setRACertProfile(alias, currentAlias.getRaCertProfile());
            scepConfig.setRAEndEntityProfile(alias, currentAlias.getRaEEProfile());
            scepConfig.setRADefaultCA(alias, currentAlias.getRaDefaultCA());
            // If the client secret was not changed from the placeholder value in the UI, set the old value, i.e. no change
            if (!currentAlias.getRaAuthPassword().equals(ScepConfigMBean.HIDDEN_PWD)) {
                scepConfig.setRAAuthpassword(alias, currentAlias.getRaAuthPassword());
            }
            scepConfig.setRANameGenerationScheme(alias, currentAlias.getRaNameGenScheme());
            scepConfig.setRANameGenerationParameters(alias, currentAlias.getRaNameGenParams());
            scepConfig.setRANameGenerationPrefix(alias, currentAlias.getRaNameGenPrefix());
            scepConfig.setRANameGenerationPostfix(alias, currentAlias.getRaNameGenPostfix());
            scepConfig.setClientCertificateRenewal(alias, currentAlias.getClientCertificateRenewal());
            scepConfig.setAllowClientCertificateRenewalWithOldKey(alias, currentAlias.getAllowClientCertificateRenewaWithOldKey());
            scepConfig.setUseIntune(alias, currentAlias.isUseIntune());
            scepConfig.setIntuneAuthority(alias, currentAlias.getIntuneAuthority());
            scepConfig.setIntuneAadAppId(alias, currentAlias.getIntuneAadAppId());
            scepConfig.setIntuneAadUseKeyBinding(alias, currentAlias.isIntuneAadUseKeyBinding());
            // If the client secret was not changed from the placeholder value in the UI, set the old value, i.e. no change
            if (!currentAlias.getIntuneAadAppKey().equals(ScepConfigMBean.HIDDEN_PWD)) {
                scepConfig.setIntuneAadAppKey(alias, currentAlias.getIntuneAadAppKey());
            }
            scepConfig.setIntuneAadAppKeyBinding(alias, currentAlias.getIntuneAadAppKeyBinding());
            scepConfig.setIntuneTenant(alias, currentAlias.getIntuneTenant());
            scepConfig.setIntuneResourceUrl(alias, currentAlias.getIntuneResourceUrl());
            scepConfig.setIntuneGraphApiVersion(alias, currentAlias.getIntuneGraphApiVersion());
            scepConfig.setIntuneGraphResourceUrl(alias, currentAlias.getIntuneGraphResourceUrl());
            scepConfig.setIntuneProxyHost(alias, currentAlias.getIntuneProxyHost());
            scepConfig.setIntuneProxyPort(alias, currentAlias.getIntuneProxyPort());
            scepConfig.setIntuneProxyUser(alias, currentAlias.getIntuneProxyUser());
            // If the client secret was not changed from the placeholder value in the UI, set the old value, i.e. no change
            if (!currentAlias.getIntuneProxyPass().equals(ScepConfigMBean.HIDDEN_PWD)) {
                scepConfig.setIntuneProxyPass(alias, currentAlias.getIntuneProxyPass());
            }

            try {
                globalConfigSession.saveConfiguration(authenticationToken, scepConfig);
            } catch (AuthorizationDeniedException e) {
                String msg = "Cannot save alias. Administrator is not authorized.";
                log.info(msg + e.getLocalizedMessage());
                super.addNonTranslatedErrorMessage(msg);
            }
        }
        flushCache();
    }

    public void deleteAlias() {
        if (scepConfig.aliasExists(currentAliasStr)) {
            scepConfig.removeAlias(currentAliasStr);
            try {
                globalConfigSession.saveConfiguration(authenticationToken, scepConfig);
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

    public void renameAlias() {
        if (StringUtils.isNotEmpty(newAlias) && !scepConfig.aliasExists(newAlias)) {
            scepConfig.renameAlias(currentAliasStr, newAlias);
            try {
                globalConfigSession.saveConfiguration(authenticationToken, scepConfig);
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

    public void addAlias() {
        if (StringUtils.isNotEmpty(newAlias) && !scepConfig.aliasExists(newAlias)) {
            scepConfig.addAlias(newAlias);
            try {
                globalConfigSession.saveConfiguration(authenticationToken, scepConfig);
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

    /** Invoked when admin cancels a SCEP alias create or edit. */
    public void cancelCurrentAlias() {
        flushCache();
    }

    /** @return a list of usable operational modes */
    public List<SelectItem> getAvailableModes() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem(ScepConfiguration.Mode.RA.getResource(), ScepConfiguration.Mode.RA.getResource()));
        ret.add(new SelectItem(ScepConfiguration.Mode.CA.getResource(), ScepConfiguration.Mode.CA.getResource()));
        return ret;
    }

    /** @return a list of all CA names */
    public List<SelectItem> getAvailableCAs() {
        final List<SelectItem> ret = new ArrayList<>();
        final Collection<String> cas = caSession.getAuthorizedCaNames(authenticationToken);
        for (String caname : cas) {
            ret.add(new SelectItem(caname, caname));
        }
        ret.sort(new SelectItemComparator());
        return ret;
    }

    /** @return a list of EndEntity profiles that this admin is authorized to */
    public List<SelectItem> getAuthorizedEEProfileNames() {
        Collection<Integer> endEntityProfileIds = endentityProfileSession.getAuthorizedEndEntityProfileIds(getAdmin(), AccessRulesConstants.CREATE_END_ENTITY);
        Map<Integer, String> nameMap = endentityProfileSession.getEndEntityProfileIdToNameMap();
        final List<SelectItem> ret = new ArrayList<>();
        for (Integer id: endEntityProfileIds) {
            String name = nameMap.get(id);
            ret.add(new SelectItem(name, name));
        }
        ret.sort(new SelectItemComparator());
        return ret;
    }

    /** @return a list of certificate profiles that are available for the current end entity profile */
    public List<SelectItem> getAvailableCertProfilesOfEEProfile() {
        String eep = currentAlias.getRaEEProfile();
        if ((eep == null) || (eep.length() <= 0)) {
            eep = ScepConfiguration.DEFAULT_RA_ENTITYPROFILE;
        }
        final EndEntityProfile p = endentityProfileSession.getEndEntityProfile(eep);
        final List<SelectItem> ret = new ArrayList<>();
        if (p != null) {
            final Collection<Integer> cpids = p.getAvailableCertificateProfileIds();
            for(final int cpid : cpids) {
                String cpname = certProfileSession.getCertificateProfileName(cpid);
                ret.add(new SelectItem(cpname, cpname));
            }            
        }
        ret.sort(new SelectItemComparator());
        return ret;
    }

    /** @return a list of CAs that are available for the current end entity profile */
    public List<SelectItem> getAvailableCAsOfEEProfile() {
        String eep = currentAlias.getRaEEProfile();
        if ((eep == null) || (eep.length() <= 0)) {
            eep = ScepConfiguration.DEFAULT_RA_ENTITYPROFILE;
        }
        final EndEntityProfile p = endentityProfileSession.getEndEntityProfile(eep);
        final List<SelectItem> ret = new ArrayList<>();
        if (p != null) {
            Map<Integer, String> caidname = getEjbcaWebBean().getCAIdToNameMap();
            for (int caid : p.getAvailableCAs()) {
                if (caid == CAConstants.ALLCAS) {
                    return getAvailableCAs();
                }
                String caname = caidname.get(caid);
                ret.add(new SelectItem(caname, caname));
            }            
        }
        ret.sort(new SelectItemComparator());
        return ret;
    }

    public List<SelectItem> getAvailableSchemes() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem("DN", "DN Part"));
        ret.add(new SelectItem("RANDOM", "RANDOM (Generates a 12 characters long random username)"));
        ret.add(new SelectItem("FIXED", "FIXED"));
        ret.add(new SelectItem("USERNAME", "Use entire request DN as username"));
        return ret;
    }

    public List<SelectItem> getDnParts() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem("CN", "CN"));
        ret.add(new SelectItem("UID", "UID"));
        ret.add(new SelectItem("OU", "OU"));
        ret.add(new SelectItem("O", "O"));
        ret.add(new SelectItem("L", "L"));
        ret.add(new SelectItem("ST", "ST"));
        ret.add(new SelectItem("DC", "DC"));
        ret.add(new SelectItem("C", "C"));
        ret.add(new SelectItem("emailAddress", "emailAddress"));
        ret.add(new SelectItem("SN", "serialNumber"));
        ret.add(new SelectItem("givenName", "givenName"));
        ret.add(new SelectItem("initials", "initials"));
        ret.add(new SelectItem("surname", "surname"));
        ret.add(new SelectItem("title", "title"));
        ret.add(new SelectItem("unstructuredAddress", "unstructuredAddress"));
        ret.add(new SelectItem("unstructuredName", "unstructuredName"));
        ret.add(new SelectItem("postalCode", "postalCode"));
        ret.add(new SelectItem("businessCategory", "businessCategory"));
        ret.add(new SelectItem("dnQualifier", "dnQualifier"));
        ret.add(new SelectItem("postalAddress", "postalAddress"));
        ret.add(new SelectItem("telephoneNumber", "telephoneNumber"));
        ret.add(new SelectItem("pseudonym", "pseudonym"));
        ret.add(new SelectItem("streetAddress", "streetAddress"));
        ret.add(new SelectItem("name", "name"));
        ret.add(new SelectItem("role", "role"));
        ret.add(new SelectItem("CIF", "CIF"));
        ret.add(new SelectItem("NIF", "NIF"));
        return ret;
    }

    public boolean isExistsClientCertificateRenewalExtension() {
        return editionEjbBridgeSession.isRunningEnterprise();
    }

}
