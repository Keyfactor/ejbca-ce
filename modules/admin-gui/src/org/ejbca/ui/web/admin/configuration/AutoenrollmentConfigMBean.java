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

    public List<SelectItem> getAutoenrollConfigAliasesSelectItemList() {
        List<String> aliasList = getEjbcaWebBean().getAutoenrollConfiguration().getSortedAliasList();
        final List<SelectItem> ret = new ArrayList<>();
        for (String alias : aliasList) {
            ret.add(new SelectItem(alias));
        }
        return ret;
    }

    public void addAlias() throws AuthorizationDeniedException {
        if (StringUtils.isNotEmpty(newAlias)) {
            if (!StringTools.checkFieldForLegalChars(newAlias)) {
                addErrorMessage("ONLYCHARACTERS");
            } else {
                if (getEjbcaWebBean().getAutoenrollConfiguration().aliasExists(newAlias)) {
                    addErrorMessage("MSAE_ALIAS_EXISTS");
                } else {
                    getEjbcaWebBean().addAutoenrollAlias(newAlias);
                    newAlias = null;
                }
            }
        }
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

    public void cloneAlias() throws AuthorizationDeniedException {
        if (StringUtils.isNotEmpty(newAlias) && StringUtils.isNotEmpty(selectedAlias)) {
            if (!StringTools.checkFieldForLegalChars(newAlias)) {
                addErrorMessage("ONLYCHARACTERS");
            } else {
                if (getEjbcaWebBean().getAutoenrollConfiguration().aliasExists(newAlias)) {
                    addErrorMessage("ESTCOULDNOTRENAMEORCLONE");
                } else {
                    getEjbcaWebBean().cloneAutoenrollAlias(selectedAlias, newAlias);
                    newAlias = null;
                }
            }
        }
    }

    public void deleteAutoenrollmentAlias() throws AuthorizationDeniedException {
        if (StringUtils.isNotEmpty(selectedAlias)) {
            getEjbcaWebBean().removeAutoenrollAlias(selectedAlias);
            if (getEjbcaWebBean().getAutoenrollConfiguration().aliasExists(selectedAlias)) {
                addErrorMessage("MSAE_COULD_NOT_DELETE_ALIAS");
            }
        }
        actionCancel();
    }

    /**
     * Delete action.
     */
    public void actionDelete() {
        if (StringUtils.isNotEmpty(selectedAlias)) {
            deleteInProgress = true;
        } else {
            addErrorMessage("MSAE_NOT_SELECTED");
        }
    }

    /**
     * Cancel action.
     */
    public void actionCancel() {
        deleteInProgress = false;
        selectedAlias = null;
        newAlias = null;
    }

    /** @return the navigation outcome defined in faces-config.xml */
    public String actionView() {
        if (StringUtils.isNotEmpty(selectedAlias)) {
            viewOnly = true;
            return "view";
        }
        addErrorMessage("MSAE_NOT_SELECTED");
        return "";
    }

    /** @return the navigation outcome defined in faces-config.xml */
    public String actionEdit() {
        if (StringUtils.isNotEmpty(selectedAlias)) {
            viewOnly = false;
            return "edit";
        }
        addErrorMessage("MSAE_NOT_SELECTED");
        return "";
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
