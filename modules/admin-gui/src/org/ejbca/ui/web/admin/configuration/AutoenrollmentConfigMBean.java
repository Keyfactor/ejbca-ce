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
import java.util.List;

import javax.enterprise.context.SessionScoped;
import javax.faces.model.SelectItem;
import javax.inject.Named;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

import com.keyfactor.util.StringTools;

/**
 *
 */
@Named
@SessionScoped
public class AutoenrollmentConfigMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;

    private String selectedAlias;
    private String newAlias;
    private boolean viewOnly = true;

    /**
     * Indicates a delete action in progress to render its view.
     */
    private boolean deleteInProgress = false;

    public AutoenrollmentConfigMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
    }

    public List<String> getAutoenrollConfigAliasesSelectItemList() {
        return getEjbcaWebBean().getAutoenrollConfiguration().getSortedAliasList();
    }

    public String addAlias() throws AuthorizationDeniedException {
        selectedAlias = null;
        viewOnly = false;
        return "edit";
    }

    public void renameAlias() throws AuthorizationDeniedException {
        if (StringUtils.isNotEmpty(newAlias) && StringUtils.isNotEmpty(selectedAlias)) {
            if (!StringTools.checkFieldForLegalChars(newAlias)) {
                addErrorMessage("ONLYCHARACTERS");
            } else {
                if (getEjbcaWebBean().getAutoenrollConfiguration().aliasExists(newAlias)) {
                    addErrorMessage("ESTCOULDNOTRENAMEORCLONE");
                } else {
                    getEjbcaWebBean().renameAutoenrollAlias(selectedAlias, newAlias);
                    newAlias = null;
                }
            }
        }
    }

    public String cloneAlias() throws AuthorizationDeniedException {
        if (StringUtils.isEmpty(newAlias)) {
            addErrorMessage("ONLYCHARACTERS");
            return null;
        }
        if (!StringTools.checkFieldForLegalChars(newAlias)) {
            addErrorMessage("ONLYCHARACTERS");
            return null;
        }
        if (getEjbcaWebBean().getAutoenrollConfiguration().aliasExists(newAlias)) {
            addErrorMessage("ESTCOULDNOTRENAMEORCLONE");
            return null;
        }
        getEjbcaWebBean().cloneAutoenrollAlias(selectedAlias, newAlias);
        newAlias = null;
        selectedAlias = null;
        return "done";
    }

    public String deleteAlias() throws AuthorizationDeniedException {
        getEjbcaWebBean().removeAutoenrollAlias(selectedAlias);
        if (getEjbcaWebBean().getAutoenrollConfiguration().aliasExists(selectedAlias)) {
            addErrorMessage("MSAE_COULD_NOT_DELETE_ALIAS");
        }
        selectedAlias = null;
        return "done";
    }

    /**
     * Delete action.
     */
    public String actionDelete(final String alias) {
        selectedAlias = alias;
        return "delete";
    }

    public String actionClone(final String alias) {
        selectedAlias = alias;
        return "clone";
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

    /**
     * @return true if no aliases have been configured yet
     */
    public boolean isAliasListEmpty() {
        return getEjbcaWebBean().getAutoenrollConfiguration().getSortedAliasList().isEmpty();
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

    public boolean isDeleteInProgress() {
        return deleteInProgress;
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
