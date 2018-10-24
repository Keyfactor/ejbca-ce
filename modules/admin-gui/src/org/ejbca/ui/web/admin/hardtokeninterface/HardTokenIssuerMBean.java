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
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.annotation.PostConstruct;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.Role;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.hardtoken.HardTokenIssuerExistsException;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * @version $Id: HardTokenIssuerMBean.java 25797 2018-08-10 15:52:00Z jekaterina $
 */
@ManagedBean
@ViewScoped
public class HardTokenIssuerMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(HardTokenIssuerMBean.class);

    HardTokenInterfaceBean tokenbean;

    /**
     * Indicates a delete action in progress to render its view.
     */
    private boolean deleteInProgress = false;
    private String selectedHardTokenIssuer;
    private String newHardTokenIssuer;
    private int newRoleId;

    @PostConstruct
    private void postConstruct() throws Exception {
        final HttpServletRequest req = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        getEjbcaWebBean().initialize(req, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS);
        tokenbean = (HardTokenInterfaceBean) req.getSession().getAttribute("tokenbean");
        if (tokenbean == null) {
            try {
                tokenbean = (HardTokenInterfaceBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(), HardTokenInterfaceBean.class.getName());
            } catch (ClassNotFoundException exc) {
                throw new ServletException(exc.getMessage());
            } catch (Exception exc) {
                throw new ServletException(" Cannot create bean of class " + HardTokenInterfaceBean.class.getName(), exc);
            }
            req.getSession().setAttribute("tokenbean", tokenbean);
        }
        try {
            tokenbean.initialize(req, getEjbcaWebBean());
        } catch (Exception e) {
            throw new java.io.IOException("Error initializing AdminIndexMBean");
        }
    }

    public List<SelectItem> getHardTokenIssuereSeletItemList() {
        Map adminidtonamemap = tokenbean.getRoleIdToNameMap();
        TreeMap<String, HardTokenIssuerInformation> hardTokenIssuers = getEjbcaWebBean().getHardTokenIssuers();
        final List<SelectItem> ret = new ArrayList<>();
        for (Map.Entry<String, HardTokenIssuerInformation> hardTokenIssuer : hardTokenIssuers.entrySet()) {
            String label= hardTokenIssuer.getKey() + ", "+ adminidtonamemap.get(hardTokenIssuer.getValue().getRoleDataId());
            ret.add(new SelectItem(hardTokenIssuer.getKey(), label));
        }
        return ret;
    }

    public List<SelectItem>  getHardTokenIssuingRoles(){
        final List<SelectItem> ret = new ArrayList<>();
        for (Role role : tokenbean.getHardTokenIssuingRoles()) {
            ret.add(new SelectItem(role.getRoleId(), role.getRoleNameFull()));
        }
        return ret;
    }

    public void addHardTokenIssuer() throws AuthorizationDeniedException {
        if (newHardTokenIssuer != null) {
            if (StringUtils.isNotEmpty(newHardTokenIssuer.trim())) {
                if (!StringTools.checkFieldForLegalChars(newHardTokenIssuer)) {
                    addErrorMessage("ONLYCHARACTERS");
                } else {
                    try {
                        tokenbean.addHardTokenIssuer(newHardTokenIssuer.trim(), newRoleId);
                        newHardTokenIssuer = null;
                        newRoleId = -1;
                    } catch (HardTokenIssuerExistsException e) {
                        addErrorMessage("ISSUERALREADYEXISTS");
                        newHardTokenIssuer = null;
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
                        tokenbean.renameHardTokenIssuer(selectedHardTokenIssuer, newHardTokenIssuer.trim(), newRoleId);
                        newHardTokenIssuer = null;
                    } catch (HardTokenIssuerExistsException e) {
                        addErrorMessage("USERDATASOURCEALREADY");
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
                        tokenbean.cloneHardTokenIssuer(selectedHardTokenIssuer,newHardTokenIssuer, newRoleId);
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
            if (!selectedHardTokenIssuer.trim().equals("")) {
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
        deleteInProgress = false;
        selectedHardTokenIssuer = null;
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
}
