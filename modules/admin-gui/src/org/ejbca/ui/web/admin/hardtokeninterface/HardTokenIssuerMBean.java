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

package org.ejbca.ui.web.admin.hardtokeninterface;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.faces.context.FacesContext;
import javax.faces.event.ComponentSystemEvent;
import javax.faces.model.SelectItem;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.Role;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.hardtoken.HardTokenIssuerExistsException;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.util.SelectItemComparator;

/**
 * @version $Id$
 */

public class HardTokenIssuerMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;

    private HardTokenInterfaceBean tokenbean;

    /**
     * Indicates a delete action in progress to render its view.
     */
    private boolean deleteInProgress = false;
    private String selectedHardTokenIssuer;
    private String newHardTokenIssuer;
    private int newRoleId;

    public void initialize(ComponentSystemEvent event) throws Exception {
        // Invoke on initial request only
        final HttpServletRequest req = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        getEjbcaWebBean().initialize(req, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS);
        tokenbean = (HardTokenInterfaceBean) req.getSession().getAttribute("tokenbean");
        if (tokenbean == null) {
            try {
                tokenbean = (HardTokenInterfaceBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(), HardTokenInterfaceBean.class.getName());
            } catch (ClassNotFoundException exc) {
                throw new ServletException(exc.getMessage());
            } catch (Exception exc) {
                throw new ServletException("Cannot create bean of class " + HardTokenInterfaceBean.class.getName(), exc);
            }
            req.getSession().setAttribute("tokenbean", tokenbean);
        }
        try {
            tokenbean.initialize(req, getEjbcaWebBean());
        } catch (Exception e) {
            throw new java.io.IOException("Error initializing HardTokenIssuerMBean");
        }
    }

    public List<SelectItem> getHardTokenIssuerSeleсtItemList() {
        final Map<Integer, String> adminIdToNameMap = tokenbean.getRoleIdToNameMap();
        final TreeMap<String, HardTokenIssuerInformation> hardTokenIssuers = getEjbcaWebBean().getHardTokenIssuers();
        final List<SelectItem> ret = new ArrayList<>();
        for (Map.Entry<String, HardTokenIssuerInformation> hardTokenIssuer : hardTokenIssuers.entrySet()) {
            String label = hardTokenIssuer.getKey() + ", " + adminIdToNameMap.get(hardTokenIssuer.getValue().getRoleDataId());
            ret.add(new SelectItem(hardTokenIssuer.getKey(), label));
        }
        Collections.sort(ret, new SelectItemComparator());
        return ret;
    }

    public List<SelectItem> getHardTokenIssuingRoles() {
        final List<SelectItem> ret = new ArrayList<>();
        for (Role role : tokenbean.getHardTokenIssuingRoles()) {
            ret.add(new SelectItem(role.getRoleId(), role.getRoleNameFull()));
        }
        return ret;
    }

    public void addHardTokenIssuer() throws AuthorizationDeniedException {
        if (newHardTokenIssuer != null) {
            newHardTokenIssuer = newHardTokenIssuer.trim();
            if (StringUtils.isNotEmpty(newHardTokenIssuer)) {
                if (!StringTools.checkFieldForLegalChars(newHardTokenIssuer)) {
                    addErrorMessage("ONLYCHARACTERS");
                } else {
                    try {
                        tokenbean.addHardTokenIssuer(newHardTokenIssuer, newRoleId);
                        newHardTokenIssuer = null;
                        newRoleId = -1;
                    } catch (HardTokenIssuerExistsException e) {
                        addErrorMessage("ISSUERALREADYEXISTS");
                    }
                }
            }
        }
    }

    public void renameHardTokenIssuer() throws AuthorizationDeniedException {
        if (selectedHardTokenIssuer != null && newHardTokenIssuer != null) {
            selectedHardTokenIssuer = selectedHardTokenIssuer.trim();
            newHardTokenIssuer = newHardTokenIssuer.trim();
            if (StringUtils.isNotEmpty(newHardTokenIssuer) && StringUtils.isNotEmpty(selectedHardTokenIssuer)) {
                if (!StringTools.checkFieldForLegalChars(newHardTokenIssuer)) {
                    addErrorMessage("ONLYCHARACTERS");
                } else {
                    try {
                        tokenbean.renameHardTokenIssuer(selectedHardTokenIssuer, newHardTokenIssuer, newRoleId);
                        newHardTokenIssuer = null;
                    } catch (HardTokenIssuerExistsException e) {
                        addErrorMessage("ISSUERALREADYEXISTS");
                    }
                }
            }
        }
    }

    public void cloneHardTokenIssuer() throws AuthorizationDeniedException {
        if (selectedHardTokenIssuer != null && newHardTokenIssuer != null) {
            selectedHardTokenIssuer = selectedHardTokenIssuer.trim();
            newHardTokenIssuer = newHardTokenIssuer.trim();
            if (StringUtils.isNotEmpty(newHardTokenIssuer) && StringUtils.isNotEmpty(selectedHardTokenIssuer)) {
                if (!StringTools.checkFieldForLegalChars(newHardTokenIssuer)) {
                    addErrorMessage("ONLYCHARACTERS");
                } else {
                    try {
                        tokenbean.cloneHardTokenIssuer(selectedHardTokenIssuer, newHardTokenIssuer, newRoleId);
                        newHardTokenIssuer = null;
                        newRoleId = -1;
                    } catch (HardTokenIssuerExistsException e) {
                        addErrorMessage("ISSUERALREADYEXISTS");
                    }
                }
            }
        }
    }

    public void deleteHardTokenIssuer() throws AuthorizationDeniedException {
        if (selectedHardTokenIssuer != null) {
            selectedHardTokenIssuer = selectedHardTokenIssuer.trim();
            if (StringUtils.isNotEmpty(selectedHardTokenIssuer)) {
                boolean result = tokenbean.removeHardTokenIssuer(selectedHardTokenIssuer);
                if (!result) {
                    addErrorMessage("COULDNTDELETEISSUER");
                }
            }
        }
        actionCancel();
    }


    /**
     * Delete action.
     */
    public void actionDelete() {
        if (StringUtils.isNotEmpty(selectedHardTokenIssuer)) {
            deleteInProgress = true;
        }
    }

    /**
     * Cancel action.
     */
    public void actionCancel() {
        reset();
    }

    void reset() {
        deleteInProgress = false;
        selectedHardTokenIssuer = null;
    }

    /**
     * Edit action.
     *
     * @return the navigation outcome defined in faces-config.xml.
     */
    public String actionEdit() {
        if (StringUtils.isNotEmpty(selectedHardTokenIssuer)) {
            return "edit";
        } else {
            addErrorMessage("HARDTOKENISSUERSELECT");
        }
        return "";
    }

    public boolean isDeleteInProgress() {
        return deleteInProgress;
    }

    public String getSelectedHardTokenIssuer() {
        return selectedHardTokenIssuer;
    }

    public void setSelectedHardTokenIssuer(String selectedHardTokenIssuer) {
        this.selectedHardTokenIssuer = selectedHardTokenIssuer;
    }

    public String getNewHardTokenIssuer() {
        return newHardTokenIssuer;
    }

    public void setNewHardTokenIssuer(String newHardTokenIssuer) {
        this.newHardTokenIssuer = newHardTokenIssuer;
    }

    public int getNewRoleId() {
        return newRoleId;
    }

    public void setNewRoleId(int newRoleId) {
        this.newRoleId = newRoleId;
    }

    public HardTokenInterfaceBean getTokenbean() {
        return tokenbean;
    }
}
