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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.protocol.acme.storage.AcmeConfiguration;
import org.ejbca.ui.web.protocol.acme.storage.GlobalAcmeConfiguration;

import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

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
    private boolean currentAliasEditMode = false;
    private String currentAliasStr;
    private String newAlias = "";


    private final GlobalConfigurationSessionLocal globalConfigSession = getEjbcaWebBean().getEjb().getGlobalConfigurationSession();
    private final AuthenticationToken authenticationToken = getAdmin();

    public AcmeConfigMBean() {
        super();
        globalAcmeConfigurationConfig = (GlobalAcmeConfiguration) globalConfigSession.getCachedConfiguration(GlobalAcmeConfiguration.ACME_CONFIGURATION_ID);
    }

    /** Force reload from underlying (cache) layer for the current SCEP configuration alias */
    private void flushCache() {
        currentAlias = null;
        aliasGuiList = null;
        currentAliasEditMode = false;
        globalAcmeConfigurationConfig = (GlobalAcmeConfiguration) globalConfigSession.getCachedConfiguration(GlobalAcmeConfiguration.ACME_CONFIGURATION_ID);
    }
    /** Build a list sorted by name from the existing SCEP configuration aliases */
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

    public void setCurrentAliasStr(String currentAliasStr) {
        this.currentAliasStr = currentAliasStr;
    }

    public class AcmeAliasGuiInfo {
        String alias;

        public AcmeAliasGuiInfo(GlobalAcmeConfiguration globalAcmeConfigurationConfig, String alias) {
            if (alias != null) {
                this.alias = alias;
            }
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = alias;
        }
    }
}
