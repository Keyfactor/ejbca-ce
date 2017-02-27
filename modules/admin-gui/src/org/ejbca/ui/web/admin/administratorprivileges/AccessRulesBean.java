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
package org.ejbca.ui.web.admin.administratorprivileges;

import java.io.Serializable;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Managed Bean for the Role's access rules manage/view page.
 * 
 * @version $Id$
 */
@ViewScoped
@ManagedBean
public class AccessRulesBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(AccessRulesBean.class);

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private RoleSessionLocal roleSession;

    private String roleIdParam;
    private Role role;

    @PostConstruct
    private void postConstruct() {
        // Read HTTP param "roleId" that should be interpreted as an integer
        roleIdParam = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get("roleId");
    }

    /** @return true when admin is authorized to edit access rules of this role */
    public boolean isAuthorizedToEditRole() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.EDITROLES.resource()) && getRole()!=null;
    }

    /** @return an authorized existing role based on the roleId HTTP param or null if no such role was found. */
    public Role getRole() {
        if (role==null && StringUtils.isNumeric(roleIdParam)) {
            try {
                role = roleSession.getRole(getAdmin(), Integer.parseInt(roleIdParam));
                if (role==null && log.isDebugEnabled()) {
                    log.debug("Admin '" + getAdmin() + "' failed to access non-existing role.");
                }
            } catch (NumberFormatException | AuthorizationDeniedException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Admin '" + getAdmin() + "' failed to access a role: " + e.getMessage());
                }
            }
        }
        return role;
    }
}
