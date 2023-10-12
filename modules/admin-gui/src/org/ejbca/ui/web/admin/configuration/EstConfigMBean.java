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

import com.keyfactor.util.StringTools;
import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.EstConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

import javax.ejb.EJB;
import javax.enterprise.context.SessionScoped;
import javax.inject.Named;
import java.io.Serializable;
import java.util.List;

@Named
@SessionScoped
public class EstConfigMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;

    @EJB
    private GlobalConfigurationSessionLocal globalConfigSession;

    private String selectedAlias;
    private String newAlias;
    private boolean viewOnly = true;

    public EstConfigMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
    }

    public EstConfiguration getEstConfiguration() {
        getEjbcaWebBean().reloadEstConfiguration();
        return (EstConfiguration) globalConfigSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
    }

    public List<String> getEstConfigAliasesSelectItemList() {
        return getEstConfiguration().getSortedAliasList();
    }

    /**
     * @return true if no aliases have been configured yet
     */
    public boolean isAliasListEmpty(){
        return getEstConfiguration().getAliasList().isEmpty();
    }

    public String addAlias() throws AuthorizationDeniedException {
        selectedAlias = null;
        viewOnly = false;
        return "edit";
    }

    public String cloneAliasAction() throws AuthorizationDeniedException {
        if (StringUtils.isEmpty(newAlias)) {
            addErrorMessage("ONLYCHARACTERS");
            return null;
        }

        if (!StringTools.checkFieldForLegalChars(newAlias)) {
            addErrorMessage("ONLYCHARACTERS");
            return null;
        }

        if (getEstConfiguration().aliasExists(newAlias)) {
            addErrorMessage("ESTCOULDNOTRENAMEORCLONE");
            return null;
        }

        getEjbcaWebBean().cloneEstAlias(selectedAlias, newAlias);
        newAlias = null;
        selectedAlias = null;
        return "done";
    }

    public String cloneAlias(final String alias) {
        selectedAlias = alias;
        return "clone";
    }

    public String deleteAlias(final String alias) {
        selectedAlias = alias;
        return "delete";
    }

    /**
     * Delete action.
     */
    public String deleteAliasAction() throws AuthorizationDeniedException {
        getEjbcaWebBean().removeEstAlias(selectedAlias);
        if (getEstConfiguration().aliasExists(selectedAlias)) {
            addErrorMessage("ESTCOULDNOTDELETEALIAS");
        }
        selectedAlias = null;
        return "done";
    }

    /**
     * Cancel action.
     */
    public void actionCancel() {
        selectedAlias = null;
        newAlias = null;
    }

    /**
     * @return the navigation outcome defined in faces-config.xml
     */
    public String actionView(final String alias) {
        selectedAlias = alias;
        viewOnly = true;
        return "view";
    }

    /**
     * @return the navigation outcome defined in faces-config.xml
     */
    public String actionEdit(final String alias) {
        selectedAlias = alias;
        viewOnly = false;
        return "edit";
    }

    public boolean isAuthorizedToEdit() {
        return isAuthorizedTo(StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
    }

    public String getSelectedAlias() {
        return selectedAlias;
    }

    public void setSelectedAlias(String selectedAlias) {
        this.selectedAlias = selectedAlias;
    }

    public String getNewAlias() {
        return newAlias;
    }

    public void setNewAlias(String newAlias) {
        this.newAlias = newAlias.trim();
    }

    public boolean isViewOnly() {
        return viewOnly;
    }
}
