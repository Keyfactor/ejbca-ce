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
package org.ejbca.ra;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.Role;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;


/**
 * Backing bean for the Edit Role page
 *  
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaRoleBean {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaRoleBean.class);
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value="#{raAccessBean}")
    private RaAccessBean raAccessBean;
    public void setRaAccessBean(final RaAccessBean raAccessBean) { this.raAccessBean = raAccessBean; }
    
    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }
    
    @ManagedProperty(value="#{raRolesBean}")
    private RaRolesBean raRolesBean;
    public void setRaRolesBean(final RaRolesBean raRolesBean) { this.raRolesBean = raRolesBean; }
    
    private static final Object NEW_NAMESPACE_ITEM = "#NEW#";
    
    private Integer roleId;
    private Role role;
    
    private String name;
    private String namespace;
    private String newNamespace;
    private boolean hasAccessToEmptyNamespace;
    private List<String> namespaces;
    private List<SelectItem> namespaceOptions = new ArrayList<>();

    
    public void initialize() throws AuthorizationDeniedException {
        if (roleId != null) {
            role = raMasterApiProxyBean.getRole(raAuthenticationBean.getAuthenticationToken(), roleId);
            name = role.getRoleName();
            namespace = role.getNameSpace();
        } else {
            role = new Role("", "");
        }
        
        namespaceOptions = new ArrayList<>();
        namespaces = raMasterApiProxyBean.getAuthorizedRoleNamespaces(raAuthenticationBean.getAuthenticationToken(), role.getRoleId());
        Collections.sort(namespaces);
        hasAccessToEmptyNamespace = namespaces.contains("");
        if (hasAccessToEmptyNamespace) {
            namespaceOptions.add(new SelectItem("", raLocaleBean.getMessage("role_page_namespace_none")));
            namespaceOptions.add(new SelectItem(NEW_NAMESPACE_ITEM, raLocaleBean.getMessage("role_page_namespace_createnew"))); 
        }
        for (final String namespace : namespaces) {
            if (!namespace.equals("")) {
                namespaceOptions.add(new SelectItem(namespace, namespace));
            }
        }
    }
    
    public Integer getRoleId() {
        return roleId;
    }

    public void setRoleId(final Integer roleId) {
        this.roleId = roleId;
    }

    public Role getRole() {
        return role;
    }

    public String getName() {
        return name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public String getNamespace() {
        return namespace;
    }
    
    public void setNamespace(final String namespace) {
        this.namespace = namespace;
    }

    public String getNewNamespace() {
        return newNamespace;
    }

    public void setNewNamespace(final String newNamespace) {
        this.newNamespace = newNamespace;
    }

    public boolean isLimitedToOneNamespace() {
        return !hasAccessToEmptyNamespace && namespaces.size() == 1;
    }

    public boolean getCanCreateNamespaces() {
        return hasAccessToEmptyNamespace;
    }
    
    public List<SelectItem> getNamespaceOptions() {
        return namespaceOptions;
    }

    public String save() {
        // TODO
        
        // XXX note: the CA must check namespace access, including access to use the "" namespace and access to create new namespaces (which is the same)
        
        return "roles?faces-redirect=true&includeViewParams=true";
    }
    
}
