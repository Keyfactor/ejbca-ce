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
package org.ejbca.ui.web.admin.ca;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.bean.SessionBeans;
import org.ejbca.ui.web.admin.cainterface.CADataHandler;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;

/**
 * 
 * JSF MBean backing the manage ca page.
 *
 * 
 */
@ManagedBean
@ViewScoped
public class ManageCAsMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    
    @EJB
    private CaSessionLocal caSession;

    @EJB
    private CertificateProfileSessionLocal certificateProfileSessionLocal;

    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;

    @EJB
    private RoleSessionLocal roleSession;

    private TreeMap<String, Integer> canames = getEjbcaWebBean().getCANames();
    private CAInterfaceBean caBean;
    private int selectedCaId;
    private String createCaName;
    private CADataHandler cadatahandler;
    private Map<Integer, String> caidtonamemap;


    public String getCreateCaName() {
        return createCaName;
    }

    public void setCreateCaName(String createCaName) {
        this.createCaName = createCaName;
    }

    public ManageCAsMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource());
    }

    @PostConstruct
    public void init() {
        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        try {
            caBean = SessionBeans.getCaBean(request);
        } catch (ServletException e) {
            throw new IllegalStateException("Could not initiate CAInterfaceBean", e);
        }
        cadatahandler = caBean.getCADataHandler();
        caidtonamemap = caSession.getCAIdToNameMap();
    }

    public Map<Integer, String> getListOfCas() {
        final Map<Integer, String> caMap = new LinkedHashMap<>();
        for (final String nameofca : canames.keySet()) {
            int caId = canames.get(nameofca);
            int caStatus = caBean.getCAStatusNoAuth(caId);

            String nameandstatus = nameofca + ", (" + getEjbcaWebBean().getText(CAConstants.getStatusText(caStatus)) + ")";
            if (caSession.authorizedToCANoLogging(getAdmin(), caId)) {
                caMap.put(caId, nameandstatus);
            }
        }
        return caMap;
    }

    public String getEditCAButtonValue() {
        return isAuthorized() ? getEjbcaWebBean().getText("VIEWCA") : getEjbcaWebBean().getText("EDITCA");
    }

    private boolean isAuthorized() {
        boolean onlyView = false;
        if (getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource())
                || getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAVIEW.resource())) {
            onlyView = !getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource())
                    && getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAVIEW.resource());
        }
        return onlyView;
    }

    public int getSelectedCaId() {
        return selectedCaId;
    }

    public void setSelectedCaId(final int selectedCaId) {
        this.selectedCaId = selectedCaId;
    }

    public boolean isCanRemoveResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAREMOVE.resource());
    }

    public String getImportKeystoreText() {
        return getEjbcaWebBean().getText("IMPORTCA_KEYSTORE") + "...";
    }

    public boolean isCanAddResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAADD.resource());
    }

    public String getImportCertificateText() {
        return getEjbcaWebBean().getText("IMPORTCA_CERTIFICATE") + "...";
    }

    public boolean isCanRenewResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CARENEW.resource());
    }

    public boolean isCanAddOrEditResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAADD.resource())
                || getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource());
    }

    public boolean isCanAddAndEditResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAADD.resource(), StandardRules.CAEDIT.resource());
    }

    public String getCreateCaNameTitle() {
        return " : " + this.createCaName;
    }

    public boolean isCanEditResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource());
    }

    public String getConfirmMessage() {
        if (selectedCaId != 0) {
            return getEjbcaWebBean().getText("AREYOUSURETODELETECA", true, caidtonamemap.get(selectedCaId));
        } else {
            return StringUtils.EMPTY;
        }
    }

    public String editCaPage() {
        if (selectedCaId == 0) {
            return EditCaUtil.MANAGE_CA_NAV;
        }
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("editcaname", caidtonamemap.get(selectedCaId));
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("caid", selectedCaId);
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("iseditca", true);
        return EditCaUtil.EDIT_CA_NAV;
    }

    public String createCaPage() {
        if (StringUtils.isBlank(createCaName)) {
            addErrorMessage("CA_NAME_EMPTY");
            return EditCaUtil.MANAGE_CA_NAV;
        }
        if (canames.containsKey(createCaName)) {
            addErrorMessage("CAALREADYEXISTS", createCaName);
            return EditCaUtil.MANAGE_CA_NAV;
        }

        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("createcaname", EditCaUtil.getTrimmedName(this.createCaName));
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("iseditca", false);
        return EditCaUtil.EDIT_CA_NAV;
    }

    private List<String> certificateProfilesUsedByCa(int selectedCaId) {
        final List<String> certificateProfileList = new ArrayList<>();
        final Map<Integer, CertificateProfile> certificateProfileMap = certificateProfileSessionLocal.getAllCertificateProfiles();

        for (Map.Entry<Integer, CertificateProfile> entry : certificateProfileMap.entrySet()) {
            final List<Integer> availableCAs = entry.getValue().getAvailableCAs();

            if (availableCAs.stream().anyMatch(e -> e == selectedCaId)) {
                certificateProfileList.add(certificateProfileSessionLocal.getCertificateProfileName(entry.getKey()));
            }
        }
        return certificateProfileList;
    }

    /**
     * @return a list with EndEntity Profile names
     * If "Any" is chosen the CA is removable
     * The default EndEntity "Empty" is never added to the returned list.
     */
    private List<String> endEntityProfilesUsedByCa(int selectedCaId) throws EndEntityProfileNotFoundException, AuthorizationDeniedException {
        final List<String> endEntityProfileList = new ArrayList<>();
        final Map<Integer, String> endEntityProfileMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();

        for (Map.Entry<Integer, String> entry : endEntityProfileMap.entrySet()) {
            if (entry.getKey() == EndEntityConstants.EMPTY_END_ENTITY_PROFILE) {
                continue;
            }
            final Map<String, Integer> casInProfile = endEntityProfileSession.getAvailableCasInProfile(getAdmin(),
                    endEntityProfileSession.getEndEntityProfileId(entry.getValue()));
            if (casInProfile.isEmpty() || casInProfile.entrySet().stream().anyMatch(e -> (e.getValue() == selectedCaId))) {
                endEntityProfileList.add(endEntityProfileSession.getEndEntityProfileName(entry.getKey()));
            }
        }
        return endEntityProfileList;
    }

    private List<String> rolesUsedByCa(int selectedCaId) {
        final List<String> rolesList = new ArrayList<>();

        final List<Role> roles = roleSession.getAuthorizedRoles(getAdmin());

        for (final Role role : roles) {
            rolesList.addAll(getRolesUsedByCa(role, StandardRules.CAACCESS.resource(), selectedCaId));
            Collections.sort(rolesList);
        }

        return rolesList;
    }

    private List<String> getRolesUsedByCa(final Role role, final String baseResource, final Integer selectedCaId) {
        final LinkedHashMap<String, Boolean> accessRules = role.getAccessRules();
        final List<String> result = new ArrayList<>();
        final String superAdmin = "Super Administrator Role";

        final String resource = AccessRulesHelper.normalizeResource(baseResource + selectedCaId);


        if (AccessRulesHelper.hasAccessToResource(accessRules, baseResource) && !role.getName().equals(superAdmin) ){
            result.add(role.getName());
        } else {
            if (AccessRulesHelper.hasAccessToResource(accessRules, resource) && !role.getName().equals(superAdmin))  {
                result.add(role.getName());
            }
        }

        return result;
    }

    public String deleteCA() {
        try {
            if (!cadatahandler.removeCA(selectedCaId)) {
                addErrorMessage("COULDNTDELETECA");
                if (!certificateProfilesUsedByCa(selectedCaId).isEmpty()) {
                    addErrorMessage("CA_INCERTIFICATEPROFILES");
                    addNonTranslatedErrorMessage(StringUtils.join(certificateProfilesUsedByCa(selectedCaId), ", "));
                }if(!endEntityProfilesUsedByCa(selectedCaId).isEmpty()){
                    addErrorMessage("CA_INENDENTITYPROFILES");
                    addNonTranslatedErrorMessage(StringUtils.join(endEntityProfilesUsedByCa(selectedCaId), ", "));
                }if(!rolesUsedByCa(selectedCaId).isEmpty()) {
                    addErrorMessage("CA_INROLES");
                    addNonTranslatedErrorMessage(StringUtils.join(rolesUsedByCa(selectedCaId), ", "));
                }
            }
        } catch (AuthorizationDeniedException | EndEntityProfileNotFoundException e) {
            addNonTranslatedErrorMessage(e.getMessage());
        }
        return EditCaUtil.MANAGE_CA_NAV;
    }

    public String renameCA() {
        if (StringUtils.isBlank(createCaName)) {
            addErrorMessage("CA_NAME_EMPTY");
            return EditCaUtil.MANAGE_CA_NAV;
        } else if (canames.containsKey(createCaName)) {
            addErrorMessage("CAALREADYEXISTS", createCaName);
            return EditCaUtil.MANAGE_CA_NAV;
        } else if (selectedCaId == 0) {
            addErrorMessage("SELECTCATORENAME");
            return EditCaUtil.MANAGE_CA_NAV;
        }

        try {
            caSession.renameCA(getAdmin(), caSession.getCAIdToNameMap().get(selectedCaId), createCaName);
        } catch (CAExistsException | CADoesntExistsException | AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
        }
        return EditCaUtil.MANAGE_CA_NAV;
    }

    public String createAuthCertSignRequest() {
        if (selectedCaId != 0) {
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("selectedCaName", caidtonamemap.get(selectedCaId));
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("selectedCaId", selectedCaId);
            return EditCaUtil.SIGN_CERT_REQ_NAV;
        } else {
            addErrorMessage("SELECTCAFIRST");
            return EditCaUtil.MANAGE_CA_NAV;
        }
    }
}
