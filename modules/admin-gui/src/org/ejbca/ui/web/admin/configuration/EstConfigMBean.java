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

import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;
import javax.faces.event.ComponentSystemEvent;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * @version $Id: EstConfigMBean.java 25797 2018-08-10 15:52:00Z jekaterina $
 */
@ManagedBean
@SessionScoped
public class EstConfigMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;

    private String selectedAlias;
    private String newAlias;
    /**
     * Indicates a delete action in progress to render its view.
     */
    private boolean deleteInProgress = false;

    public void initialize(ComponentSystemEvent event) throws Exception {
        // Invoke on initial request only
        final HttpServletRequest req = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        getEjbcaWebBean().initialize(req, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
    }

    public List<SelectItem> getEstConfigAliasesSeletItemList() {
        List<String> aliasList = getEjbcaWebBean().getEstConfiguration().getSortedAliasList();
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
                if (getEjbcaWebBean().getEstConfiguration().aliasExists(newAlias)) {
                    addErrorMessage("ESTALIASEXISTS");
                } else {
                    getEjbcaWebBean().addEstAlias(newAlias);
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
                if (getEjbcaWebBean().getEstConfiguration().aliasExists(newAlias)) {
                    addErrorMessage("ESTCOULDNOTRENAMEORCLONE");
                } else {
                    getEjbcaWebBean().renameEstAlias(selectedAlias, newAlias);
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
                if (getEjbcaWebBean().getEstConfiguration().aliasExists(newAlias)) {
                    addErrorMessage("ESTCOULDNOTRENAMEORCLONE");
                } else {
                    getEjbcaWebBean().cloneEstAlias(selectedAlias, newAlias);
                    newAlias = null;
                }
            }
        }
    }

    public void deleteEstAlias() throws AuthorizationDeniedException {
        if (StringUtils.isNotEmpty(selectedAlias)) {
            getEjbcaWebBean().removeEstAlias(selectedAlias);
            if (getEjbcaWebBean().getEstConfiguration().aliasExists(selectedAlias)) {
                addErrorMessage("ESTCOULDNOTDELETEALIAS");
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
            addErrorMessage("CMPNOTSELECTED");
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
}
