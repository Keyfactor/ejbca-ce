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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.management.RoleSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Managed Bean for the Role's access rules manage/view page.
 * 
 * @version $Id$
 */
@ViewScoped
@ManagedBean
public class AccessRulesBean extends BaseManagedBean implements Serializable {

    public static class AccessRule {
        private final String resource;
        private final boolean state;

        public AccessRule(final String resource, final boolean state) {
            this.resource = resource;
            this.state = state;
        }

        public String getResource() { return resource; }
        public boolean isState() { return state; }
    }

    private static class AccessRulesTemplate {
        private final String name;
        private final HashMap<String,Boolean> accessRules = new HashMap<>();
        
        public AccessRulesTemplate(final String name, final AccessRule...accessRules) {
            this.name = name;
            for (final AccessRule accessRule : accessRules) {
                this.getAccessRules().put(accessRule.getResource(), accessRule.isState());
            }
            AccessRulesHelper.normalizeResources(this.accessRules);
            AccessRulesHelper.minimizeAccessRules(this.accessRules);
        }

        public String getName() { return name; }
        public HashMap<String,Boolean> getAccessRules() { return accessRules; }
    }

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(AccessRulesBean.class);

    private static final String TEMPLATE_NAME_CUSTOM = "CUSTOM";

    private static final List<AccessRulesTemplate> accessRulesTemplates = Arrays.asList(
            new AccessRulesTemplate(TEMPLATE_NAME_CUSTOM),
            new AccessRulesTemplate("SUPERVISOR",
                    new AccessRule(AccessRulesConstants.ROLE_ADMINISTRATOR, Role.STATE_ALLOW),
                    new AccessRule(AuditLogRules.VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, Role.STATE_ALLOW),
                    // From legacy JS
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWHARDTOKENS, Role.STATE_ALLOW)
                    ),
            new AccessRulesTemplate("AUDITOR",
                    new AccessRule(AccessRulesConstants.ROLE_ADMINISTRATOR, Role.STATE_ALLOW),
                    new AccessRule(AuditLogRules.VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, Role.STATE_ALLOW),
                    new AccessRule(InternalKeyBindingRules.VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.CAVIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.CERTIFICATEPROFILEVIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.APPROVALPROFILEVIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(CryptoTokenRules.VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWPUBLISHER, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.SERVICES_VIEW, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW, Role.STATE_ALLOW),
                    new AccessRule(StandardRules.SYSTEMCONFIGURATION_VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.EKUCONFIGURATION_VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.VIEWROLES.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY, Role.STATE_ALLOW)
                    ),
            new AccessRulesTemplate("RAADMINISTRATOR",
                    new AccessRule(AccessRulesConstants.ROLE_ADMINISTRATOR, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_CREATECERTIFICATE, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, Role.STATE_ALLOW),
                    // From legacy JS
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_CREATEENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_EDITENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_DELETEENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_REVOKEENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_KEYRECOVERY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_APPROVEENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWPUKS, Role.STATE_ALLOW),
                    new AccessRule(AuditLogRules.VIEW.resource(), Role.STATE_ALLOW)
                    ),
            new AccessRulesTemplate("CAADMINISTRATOR",
                    new AccessRule(AccessRulesConstants.ROLE_ADMINISTRATOR, Role.STATE_ALLOW),
                    new AccessRule(StandardRules.CAFUNCTIONALITY.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.CAVIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.CERTIFICATEPROFILEVIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_EDITPUBLISHER, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWPUBLISHER, Role.STATE_ALLOW),
                    // This was present in legacy DefaultRoles, but makes very little sense
                    //new AccessRule(AuditLogRules.LOG.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_RAFUNCTIONALITY, Role.STATE_ALLOW),
                    new AccessRule(StandardRules.EDITROLES.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.VIEWROLES.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.ENDENTITYPROFILEBASE, Role.STATE_ALLOW),
                    //new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES, Role.STATE_ALLOW),
                    new AccessRule(CryptoTokenRules.VIEW.resource(), Role.STATE_ALLOW),
                    /*
                     * Note:
                     * We DO NOT allow CA Administrators to USE CryptoTokens, since this would mean that they could
                     * bind any existing CryptoToken to a new CA and access the keys.
                     * new AccessRule(CryptoTokenRules.USE.resource(), Role.STATE_ALLOW)
                     */
                    new AccessRule(InternalKeyBindingRules.DELETE.resource(), Role.STATE_ALLOW),
                    new AccessRule(InternalKeyBindingRules.MODIFY.resource(), Role.STATE_ALLOW),
                    new AccessRule(InternalKeyBindingRules.VIEW.resource(), Role.STATE_ALLOW),
                    // From legacy JS
                    new AccessRule(AuditLogRules.VIEW.resource(), Role.STATE_ALLOW)
                    ),
            new AccessRulesTemplate("SUPERADMINISTRATOR", new AccessRule(StandardRules.ROLE_ROOT.resource(), Role.STATE_ALLOW))
            // Ignore the legacy "HARDTOKENISSUER" template since it is rarely used
            //,new AccessRulesTemplate("HARDTOKENISSUER")
            );

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private RoleSessionLocal roleSession;

    private Map<Integer, String> caIdToNameMap;
    private Map<Integer, String> eepIdToNameMap;
    private String roleIdParam;
    private String advancedParam;
    private Role role;

    private String accessRulesTemplateSelected = TEMPLATE_NAME_CUSTOM;
    private List<SelectItem> availableAccessRulesTemplates = null;
    private List<String> resourcesCaSelected = new ArrayList<>();
    private LinkedList<SelectItem> availableResourcesCa = null;
    private List<String> resourcesEeSelected = new ArrayList<>();
    private List<SelectItem> availableResourcesEe = null;
    private List<String> resourcesEepSelected = new ArrayList<>();
    private LinkedList<SelectItem> availableResourcesEep = null;
    private List<String> resourcesIkbSelected = new ArrayList<>();
    private List<SelectItem> availableResourcesIkb = null;
    private List<String> resourcesOtherSelected = new ArrayList<>();
    private List<SelectItem> availableResourcesOther = null;

    @PostConstruct
    private void postConstruct() {
        final Map<String, String> requestParameterMap = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap();
        // Read HTTP param "roleId" that should be interpreted as an integer
        roleIdParam = requestParameterMap.get("roleId");
        // Read HTTP param "advanced" that should be interpreted as an boolean
        advancedParam = requestParameterMap.get("advanced");
        caIdToNameMap = caSession.getCAIdToNameMap();
        eepIdToNameMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
        reinitSelection();
    }

    /** @return true in advanced access rule mode */
    public boolean isAdvancedMode() {
        return Boolean.parseBoolean(advancedParam);
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

    /** Recalculate selection based on current state of template selection or loaded role's access rules */
    private void reinitSelection() {
        // Reset available lists that might be rendered differently depending on selected template
        availableResourcesCa = null;
        availableResourcesEe = null;
        availableResourcesEep = null;
        availableResourcesIkb = null;
        availableResourcesOther = null;
        // Calculate available templates and the current best match  
        getAvailableAccessRulesTemplates();
        // Select access rules that are allowed by the role
        final LinkedHashMap<String, Boolean> accessRules = getRole().getAccessRules();
        // Find CA access resources allowed by this role
        setResourcesCaSelected(getSelectedRulesFromIdentifiers(accessRules, StandardRules.CAACCESS.resource(), caIdToNameMap.keySet()));
        // Find RA resources allowed by this role
        setResourcesEeSelected(getSelectedRulesFromSelectItems(accessRules, getAvailableResourcesEe()));
        // Find EEP resources allowed by this role
        setResourcesEepSelected(getSelectedRulesFromIdentifiers(accessRules, AccessRulesConstants.ENDENTITYPROFILEPREFIX, eepIdToNameMap.keySet()));
        // Find IKB resources allowed by this role
        setResourcesIkbSelected(getSelectedRulesFromSelectItems(accessRules, getAvailableResourcesIkb()));
        // Find Other resources allowed by this role
        setResourcesOtherSelected(getSelectedRulesFromSelectItems(accessRules, getAvailableResourcesOther()));
    }

    /** @return minimal list of resources that the provided access rules grants */
    private List<String> getSelectedRulesFromIdentifiers(final LinkedHashMap<String, Boolean> accessRules, final String baseResource, final Set<Integer> ids) {
        final List<String> ret = new ArrayList<>();
        if (AccessRulesHelper.hasAccessToResource(accessRules, baseResource)) {
            ret.add(baseResource);
        } else {
            for (final int id : ids) {
                final String resource = AccessRulesHelper.normalizeResource(baseResource + id);
                if (AccessRulesHelper.hasAccessToResource(accessRules, resource)) {
                    ret.add(resource);
                }
            }
        }
        return ret;
    }
    
    /** @return minimal list of resources that the provided access rules grants */
    private List<String> getSelectedRulesFromSelectItems(final LinkedHashMap<String, Boolean> accessRules, final List<SelectItem> selectItems) {
        final List<String> ret = new ArrayList<>();
        for (final SelectItem selectItem : selectItems) {
            final String resource = AccessRulesHelper.normalizeResource(String.valueOf(selectItem.getValue()));
            if (AccessRulesHelper.hasAccessToResource(getRole().getAccessRules(), resource)) {
                ret.add(resource);
            }
        }
        return ret;
    }

    /** @return the currently select role template */
    public String getAccessRulesTemplateSelected() { return accessRulesTemplateSelected; }
    /** Set the currently select role template */
    public void setAccessRulesTemplateSelected(String accessRulesTemplateSelected) { this.accessRulesTemplateSelected = accessRulesTemplateSelected; }

    /** @return true if this role is assumed to have been configured outside of the basic mode */
    public boolean isAccessRulesTemplateCustom() { return TEMPLATE_NAME_CUSTOM.equals(getAccessRulesTemplateSelected()); }
    /** @return true if this role is assumed to have been configured using the CAAdministrator template */
    private boolean isAccessRulesTemplateCaAdmin() { return "CAADMINISTRATOR".equals(getAccessRulesTemplateSelected()); }
    /** @return true if this role is assumed to have been configured using the SuperAdministrator template */
    private boolean isAccessRulesTemplateSuperAdmin() { return "SUPERADMINISTRATOR".equals(getAccessRulesTemplateSelected()); }

    /** @return currently selected AccessRuleTemplate */
    private AccessRulesTemplate getAccessRulesTemplate() {
        for (final AccessRulesTemplate accessRulesTemplate : accessRulesTemplates) {
            if (accessRulesTemplate.getName().equals(getAccessRulesTemplateSelected())) {
                return accessRulesTemplate;
            }
        }
        return null;
    }

    /** Invoked by the user when changing selected template and JavaScript is enabled */
    public void actionAccessRulesTemplateSelectAjaxListener(final AjaxBehaviorEvent event) {
        actionAccessRulesTemplateSelect();
    }

    /** Invoked by the user when changing selected template and JavaScript is disabled (or via the AJAX call) */
    public void actionAccessRulesTemplateSelect() {
        final AccessRulesTemplate accessRulesTemplate = getAccessRulesTemplate();
        final LinkedHashMap<String, Boolean> accessRules = getRole().getAccessRules();
        accessRules.clear();
        accessRules.putAll(accessRulesTemplate.getAccessRules());
        reinitSelection();
    }

    /** @return a list of available access rules templates (and detects the best match to the existing role's rules for performance reasons at the same time) */
    public List<SelectItem> getAvailableAccessRulesTemplates() {
        if (availableAccessRulesTemplates==null) {
            availableAccessRulesTemplates = new ArrayList<>();
            for (final AccessRulesTemplate accessRulesTemplate : accessRulesTemplates) {
                // Ensure that current admin is authorized to all access rules implied by the template
                final List<String> allowedResources = new ArrayList<>();
                // Ensure that there is no access rule in role that is not covered by template to check for a match
                final HashMap<String, Boolean> remainingAccessRulesInRole = new HashMap<>(getRole().getAccessRules());
                AccessRulesHelper.normalizeResources(remainingAccessRulesInRole);
                AccessRulesHelper.minimizeAccessRules(remainingAccessRulesInRole);
                filterOutSelectItems(remainingAccessRulesInRole, getAvailableResourcesCa());
                filterOutSelectItems(remainingAccessRulesInRole, getAvailableResourcesEep());
                for (final Entry<String,Boolean> entry : accessRulesTemplate.getAccessRules().entrySet()) {
                    if (entry.getValue().booleanValue()) {
                        final String resource = entry.getKey();
                        allowedResources.add(resource);
                        remainingAccessRulesInRole.remove(AccessRulesHelper.normalizeResource(resource));
                    }
                }
                if (authorizationSession.isAuthorizedNoLogging(getAdmin(), allowedResources.toArray(new String[0]))) {
                    availableAccessRulesTemplates.add(new SelectItem(accessRulesTemplate.getName(), super.getEjbcaWebBean().getText(accessRulesTemplate.getName())));
                    // Check if this template matches the Role's current access rules
                    if (remainingAccessRulesInRole.isEmpty()) {
                        accessRulesTemplateSelected = accessRulesTemplate.getName();
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Role '" + getRole().getRoleNameFull() + "' does not qualify as a '" + accessRulesTemplate.getName() + "'. Extra rules: " +
                                    Arrays.toString(remainingAccessRulesInRole.keySet().toArray()));
                        }
                    }
                }
            }
            if (!isAccessRulesTemplateCustom()) {
                // Remove the CUSTOM template from the list of selectable templates since it is really configured in advanced mode
                for (final SelectItem selectItem : new ArrayList<>(availableAccessRulesTemplates)) {
                    if (selectItem.getValue().equals(TEMPLATE_NAME_CUSTOM)) {
                        availableAccessRulesTemplates.remove(selectItem);
                        break;
                    }
                }
            }
            super.sortSelectItemsByLabel(availableAccessRulesTemplates);
        }
        return availableAccessRulesTemplates;
    }

    /** @return true if the CA selection box should be modifiable */
    public boolean isRenderResourcesCaSelection() {
        return !isAccessRulesTemplateCustom() && !isAccessRulesTemplateSuperAdmin();
    }

    /** @return the currently selected CA access resources */
    public List<String> getResourcesCaSelected() { return resourcesCaSelected; }
    /** Set the currently selected CA access resources */
    public void setResourcesCaSelected(final List<String> resourcesCaSelected) { this.resourcesCaSelected = new ArrayList<>(resourcesCaSelected); }
    
    /** @return the selectable CA access resources */
    public List<SelectItem> getAvailableResourcesCa() {
        if (availableResourcesCa==null) {
            availableResourcesCa = new LinkedList<>();
            for (final int caId : caSession.getAuthorizedCaIds(getAdmin())) {
                final String name = caIdToNameMap.containsKey(caId) ? caIdToNameMap.get(caId) : String.valueOf(caId);
                availableResourcesCa.add(new SelectItem(AccessRulesHelper.normalizeResource(StandardRules.CAACCESS.resource() + caId), name));
            }
            super.sortSelectItemsByLabel(availableResourcesCa);
            if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CAACCESS.resource())) {
                availableResourcesCa.addFirst(new SelectItem(StandardRules.CAACCESS.resource(), super.getEjbcaWebBean().getText("ALL")));
            }
        }
        return availableResourcesCa;
    }

    /** @return true if the RA rules selection box should be modifiable */
    public boolean isRenderResourcesEeSelection() {
        return !isAccessRulesTemplateCustom() && !isAccessRulesTemplateSuperAdmin() && !isAccessRulesTemplateCaAdmin();
    }
    
    /** @return the currently selected RA functionality resources */
    public List<String> getResourcesEeSelected() { return resourcesEeSelected; }
    /** Set the currently selected RA functionality resources */
    public void setResourcesEeSelected(final List<String> resourcesEeSelected) { this.resourcesEeSelected = new ArrayList<>(resourcesEeSelected); }
    
    /** @return the selectable RA functionality resources */
    public List<SelectItem> getAvailableResourcesEe() {
        if (availableResourcesEe==null) {
            availableResourcesEe = new ArrayList<>(Arrays.asList(
                    // Not part of basic mode
                    //new SelectItem(AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES, super.getEjbcaWebBean().getText("EDITENDENTITYPROFILES")),
                    //new SelectItem(AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES, super.getEjbcaWebBean().getText("VIEWENDENTITYPROFILES")),
                    //new SelectItem(AccessRulesConstants.REGULAR_EDITUSERDATASOURCES, super.getEjbcaWebBean().getText("EDITUSERDATASOURCES")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_APPROVEENDENTITY), super.getEjbcaWebBean().getText("APPROVEENDENTITYRULE")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_REVOKEENDENTITY), super.getEjbcaWebBean().getText("REVOKEENDENTITYRULE")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_VIEWENDENTITY), super.getEjbcaWebBean().getText("VIEWENDENTITYRULE")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_CREATEENDENTITY), super.getEjbcaWebBean().getText("CREATEENDENTITYRULE")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_EDITENDENTITY), super.getEjbcaWebBean().getText("EDITENDENTITYRULE")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_DELETEENDENTITY), super.getEjbcaWebBean().getText("DELETEENDENTITYRULE")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY), super.getEjbcaWebBean().getText("VIEWHISTORYRULE"))
                    ));
            if (isEnabledIssueHardwareTokens()) {
                availableResourcesEe.add(new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_VIEWHARDTOKENS), super.getEjbcaWebBean().getText("VIEWHARDTOKENRULE")));
                availableResourcesEe.add(new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_VIEWPUKS), super.getEjbcaWebBean().getText("VIEWPUKENDENTITYRULE")));
            }
            if (isEnabledKeyRecovery()) {
                availableResourcesEe.add(new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_KEYRECOVERY), super.getEjbcaWebBean().getText("KEYRECOVERENDENTITYRULE")));
            }
            // Disable the selections what it not allowed by current template
            for (final SelectItem selectItem : availableResourcesEe) {
                if (!AccessRulesHelper.hasAccessToResource(getAccessRulesTemplate().getAccessRules(), String.valueOf(selectItem.getValue()))) {
                    selectItem.setDisabled(true);
                }
            }
            super.sortSelectItemsByLabel(availableResourcesEe);
        }
        return availableResourcesEe;
    }

    /** @return true if the End Entity Profile rule selection box should be modifiable */
    public boolean isRenderResourcesEepSelection() {
        return !isAccessRulesTemplateCustom() && !isAccessRulesTemplateSuperAdmin() && !isAccessRulesTemplateCaAdmin();
    }
    
    /** @return the currently selected EEP resources */
    public List<String> getResourcesEepSelected() { return resourcesEepSelected; }
    /** Set the currently selected EEP resources */
    public void setResourcesEepSelected(final List<String> resourcesEepSelected) { this.resourcesEepSelected = new ArrayList<>(resourcesEepSelected); }
    
    /** @return the selectable EEP resources */
    public List<SelectItem> getAvailableResourcesEep() {
        if (availableResourcesEep==null) {
            availableResourcesEep = new LinkedList<>();
            for (final int eepId : endEntityProfileSession.getAuthorizedEndEntityProfileIds(getAdmin(), AccessRulesConstants.REGULAR_VIEWENDENTITY)) {
                final String name = eepIdToNameMap.containsKey(eepId) ? eepIdToNameMap.get(eepId) : String.valueOf(eepId);
                availableResourcesEep.add(new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId), name));
            }
            super.sortSelectItemsByLabel(availableResourcesEep);
            if (authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.ENDENTITYPROFILEPREFIX)) {
                availableResourcesEep.addFirst(new SelectItem(AccessRulesConstants.ENDENTITYPROFILEPREFIX, super.getEjbcaWebBean().getText("ALL")));
            }
        }
        return availableResourcesEep;
    }

    /** @return true if the InternalKeyBinding rule selection box should be modifiable */
    public boolean isRenderResourcesIkbSelection() {
        return !isAccessRulesTemplateCustom() && !isAccessRulesTemplateSuperAdmin();
    }
    
    /** @return the currently selected IKB resources */
    public List<String> getResourcesIkbSelected() { return resourcesIkbSelected; }
    /** Set the currently selected IKB resources */
    public void setResourcesIkbSelected(final List<String> resourcesIkbSelected) { this.resourcesIkbSelected = new ArrayList<>(resourcesIkbSelected); }
    
    /** @return the selectable IKB resources */
    public List<SelectItem> getAvailableResourcesIkb() {
        if (availableResourcesIkb==null) {
            availableResourcesIkb = Arrays.asList(
                    new SelectItem(AccessRulesHelper.normalizeResource(InternalKeyBindingRules.DELETE.resource()), super.getEjbcaWebBean().getText(InternalKeyBindingRules.DELETE.getReference())),
                    new SelectItem(AccessRulesHelper.normalizeResource(InternalKeyBindingRules.MODIFY.resource()), super.getEjbcaWebBean().getText(InternalKeyBindingRules.MODIFY.getReference())),
                    new SelectItem(AccessRulesHelper.normalizeResource(InternalKeyBindingRules.VIEW.resource()), super.getEjbcaWebBean().getText(InternalKeyBindingRules.VIEW.getReference()))
                    );
            super.sortSelectItemsByLabel(availableResourcesIkb);
            // Disable the selections what it not allowed by current template
            for (final SelectItem selectItem : availableResourcesIkb) {
                if (!AccessRulesHelper.hasAccessToResource(getAccessRulesTemplate().getAccessRules(), String.valueOf(selectItem.getValue()))) {
                    selectItem.setDisabled(true);
                }
            }
        }
        return availableResourcesIkb;
    }

    /** @return true if the Other rule selection box should be modifiable */
    public boolean isRenderResourcesOtherSelection() {
        return !isAccessRulesTemplateCustom() && !isAccessRulesTemplateSuperAdmin();
    }
    
    /** @return the currently selected Other resources */
    public List<String> getResourcesOtherSelected() { return resourcesOtherSelected; }
    /** Set the currently selected Other resources */
    public void setResourcesOtherSelected(final List<String> resourcesOtherSelected) { this.resourcesOtherSelected = new ArrayList<>(resourcesOtherSelected); }
    
    /** @return the selectable Other resources */
    public List<SelectItem> getAvailableResourcesOther() {
        if (availableResourcesOther==null) {
            availableResourcesOther = new ArrayList<>();
            availableResourcesOther.add(new SelectItem(AccessRulesHelper.normalizeResource(AuditLogRules.VIEW.resource()), super.getEjbcaWebBean().getText("VIEWAUDITLOG")));
            if (isEnabledIssueHardwareTokens()) {
                availableResourcesOther.add(new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS), super.getEjbcaWebBean().getText("ISSUEHARDTOKENS")));
            }
            super.sortSelectItemsByLabel(availableResourcesOther);
            // Disable the selections what it not allowed by current template
            for (final SelectItem selectItem : availableResourcesOther) {
                if (!AccessRulesHelper.hasAccessToResource(getAccessRulesTemplate().getAccessRules(), String.valueOf(selectItem.getValue()))) {
                    selectItem.setDisabled(true);
                }
            }
        }
        return availableResourcesOther;
    }

    /** @return true if this installation is configured to issue hardware tokens */
    private boolean isEnabledIssueHardwareTokens() {
        return super.getEjbcaWebBean().getGlobalConfiguration().getIssueHardwareTokens();
    }

    /** @return true if this installation is configured to perform key recovery */
    private boolean isEnabledKeyRecovery() {
        return super.getEjbcaWebBean().getGlobalConfiguration().getEnableKeyRecovery();
    }

    /** Invoked by the user to save the current selection */
    public void actionSaveAccessRules() {
        // Add access rules from template that are not user configurable
        final HashMap<String,Boolean> newAccessRules = new HashMap<>(getAccessRulesTemplate().getAccessRules());
        filterOutSelectItems(newAccessRules, getAvailableResourcesCa());
        filterOutSelectItems(newAccessRules, getAvailableResourcesEe());
        filterOutSelectItems(newAccessRules, getAvailableResourcesEep());
        filterOutSelectItems(newAccessRules, getAvailableResourcesIkb());
        filterOutSelectItems(newAccessRules, getAvailableResourcesOther());
        // Add access rules selected by the user
        for (final String resource : getResourcesCaSelected()) {
            newAccessRules.put(resource, Role.STATE_ALLOW);
        }
        for (final String resource : getResourcesEeSelected()) {
            newAccessRules.put(resource, Role.STATE_ALLOW);
        }
        for (final String resource : getResourcesEepSelected()) {
            newAccessRules.put(resource, Role.STATE_ALLOW);
        }
        for (final String resource : getResourcesIkbSelected()) {
            newAccessRules.put(resource, Role.STATE_ALLOW);
        }
        for (final String resource : getResourcesOtherSelected()) {
            newAccessRules.put(resource, Role.STATE_ALLOW);
        }
        // Replace access rules and persist
        final Role role = getRole();
        role.getAccessRules().clear();
        role.getAccessRules().putAll(newAccessRules);
        try {
            this.role = roleSession.persistRole(getAdmin(), role);
            super.addGlobalMessage(FacesMessage.SEVERITY_INFO, "ACCESSRULES_INFO_SAVED");
        } catch (RoleExistsException e) {
            throw new IllegalStateException(e);
        } catch (AuthorizationDeniedException e) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ACCESSRULES_ERROR_UNAUTH", e.getMessage());
        } finally {
            super.nonAjaxPostRedirectGet("?roleId=" + role.getRoleId());
        }
    }

    /** Remove the resources of the SelectItem values from the access rule map if present */
    private void filterOutSelectItems(final HashMap<String, Boolean> newAccessRules, final List<SelectItem> selectItems) {
        for (final SelectItem selectItem : selectItems) {
            final String resource = String.valueOf(selectItem.getValue());
            if (newAccessRules.get(resource)!=null && newAccessRules.get(resource).booleanValue()) {
                // Only remove allow rules
                newAccessRules.remove(resource);
            }
        }
    }
    
    /** @return a normalized, minimized and sorted list of access rules  */
    public List<AccessRule> getAccessRules() {
        final List<AccessRule> ret = new ArrayList<>();
        final LinkedHashMap<String, Boolean> accessRules = getRole().getAccessRules();
        AccessRulesHelper.normalizeResources(accessRules);
        AccessRulesHelper.minimizeAccessRules(accessRules);
        AccessRulesHelper.sortAccessRules(accessRules);
        for (final Entry<String,Boolean> entry : accessRules.entrySet()) {
            ret.add(new AccessRule(entry.getKey(), entry.getValue()));
        }
        return ret;
    }
}
