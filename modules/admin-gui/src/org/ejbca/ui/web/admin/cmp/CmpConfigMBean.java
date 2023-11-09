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
package org.ejbca.ui.web.admin.cmp;

import com.keyfactor.util.StringTools;
import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

import javax.ejb.EJB;
import javax.enterprise.context.SessionScoped;
import javax.inject.Named;
import java.io.Serializable;

/**
 * JavaServer Faces Managed Bean for managing CMP configuration.
 */
@Named
@SessionScoped
public class CmpConfigMBean extends BaseManagedBean implements Serializable {

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    private static final long serialVersionUID = 1L;

    private String selectedCmpAlias;
    private String newAlias;
    private boolean viewOnly = true;

    public CmpConfigMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
    }

    public CmpConfiguration getCmpConfig() {
        return (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }

    private boolean validateNewAlias() {
        newAlias = newAlias.trim();
        if (StringUtils.isEmpty(newAlias) || !StringTools.checkFieldForLegalChars(newAlias)) {
            addErrorMessage("ONLYCHARACTERS");
            return false;
        } else if (getCmpConfig().aliasExists(newAlias)) {
            addErrorMessage("CMPALIASEXISTS");
            return false;
        }
        return true;
    }

    public String cloneAlias(final String alias) {
        selectedCmpAlias = alias;
        return "clone";
    }

    public String cloneAliasAction() throws AuthorizationDeniedException {
        if (!validateNewAlias()) {
            return null;
        }
        getEjbcaWebBean().cloneCmpAlias(selectedCmpAlias, newAlias);
        selectedCmpAlias = null;
        newAlias = null;
        return "done";
    }

    public String deleteAlias(final String alias) {
        selectedCmpAlias = alias;
        return "delete";
    }

    public String deleteAliasAction() throws AuthorizationDeniedException {
        if (StringUtils.isNotEmpty(selectedCmpAlias)) {
            getEjbcaWebBean().removeCmpAlias(selectedCmpAlias);
        }
        selectedCmpAlias = null;
        newAlias = null;
        return "done";
    }

    public String addAlias() throws AuthorizationDeniedException {
        selectedCmpAlias = null;
        viewOnly = false;
        return "edit";
    }

    public String actionEdit(final String alias) {
        selectedCmpAlias = alias;
        viewOnly = false;
        return "edit";
    }

    public String actionView(final String alias) {
        selectedCmpAlias = alias;
        viewOnly = true;
        return "edit";
    }

    public String getSelectedCmpAlias() {
        return selectedCmpAlias;
    }

    public void setSelectedCmpAlias(String selectedCmpAlias) {
        this.selectedCmpAlias = selectedCmpAlias;
    }

    public String getNewAlias() {
        return newAlias;
    }

    public void setNewAlias(String newAlias) {
        this.newAlias = newAlias;
    }

    public boolean isAuthorizedToEdit() {
        return isAuthorizedTo(StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
    }

    public boolean isViewOnly() {
        return viewOnly;
    }

    public boolean isAliasListEmpty() {
        return getCmpConfig().getSortedAliasList().isEmpty();
    }
}
