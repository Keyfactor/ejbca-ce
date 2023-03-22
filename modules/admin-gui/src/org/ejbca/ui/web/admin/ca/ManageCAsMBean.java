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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.ZipInputStream;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.view.ViewScoped;
import javax.inject.Named;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Part;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.cesecore.util.SecureZipUnpacker;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.bean.SessionBeans;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;

/**
 * 
 * JSF MBean backing the manage ca page.
 *
 * 
 */
@Named
@ViewScoped
public class ManageCAsMBean extends BaseManagedBean implements Serializable {
    protected static final Logger log = Logger.getLogger(ManageCAsMBean.class);
    private static final long serialVersionUID = 1L;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSessionLocal;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private RoleMemberSessionLocal roleMemberSession;
    @EJB
    private RoleDataSessionLocal roleDataSession;
    @EJB
    private RoleMemberDataSessionLocal roleMemberDataSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    private TreeMap<String, Integer> canames = getEjbcaWebBean().getCANames();
    private CAInterfaceBean caBean;
    private int selectedCaId;
    private String createCaName;
    private Map<Integer, String> caidtonamemap;
    private transient Part certificateBundle;

    public void setCertificateBundle(final Part certificateBundle) {
        this.certificateBundle = certificateBundle;
    }

    public Part getCertificateBundle() {
        return certificateBundle;
    }

    public void importCertificateBundle(final AjaxBehaviorEvent event) {
        try {
            if (certificateBundle == null) {
                FacesContext.getCurrentInstance().addMessage(null,
                        new FacesMessage(FacesMessage.SEVERITY_ERROR, "No certificate bundle was selected.", null));
                return;
            }
            final AtomicInteger certificatesImported = new AtomicInteger();
            final AtomicInteger certificatesIgnored = new AtomicInteger();
            final AtomicInteger errors = new AtomicInteger();
            SecureZipUnpacker.Builder.fromZipInputStream(new ZipInputStream(certificateBundle.getInputStream()))
                    .onError(e -> {
                        log.error("An error occurred when unpacking the certificate bundle. " + e.getMessage());
                        new FacesMessage(FacesMessage.SEVERITY_INFO,
                                "An error occurred when unpacking the certificate bundle. " + e.getMessage(),
                                null);
                    })
                    .build()
                    .unpackFilesToMemory()
                    .stream()
                    .forEach(unpackedFile -> {
                        try {
                            final List<X509Certificate> certificates = CertTools.getCertsFromPEM(
                                    new ByteArrayInputStream(unpackedFile.getContentAsBytes()), X509Certificate.class);
                            log.info("Processing zip entry " + unpackedFile.getFileName() + " with " + certificates.size()
                                    + " certificates.");
                            for (final X509Certificate certificate : certificates) {
                                if (CertTools.isSelfSigned(certificate)) {
                                    log.info("Ignoring CA certificate for " + certificate.getSubjectDN());
                                    certificatesIgnored.incrementAndGet();
                                    continue;
                                }
                                if (null != certificateStoreSession.findCertificateByFingerprint(
                                        CertTools.getFingerprintAsString(certificate))) {
                                    log.info("Ignoring certificate with fingerprint 0x" +
                                            CertTools.getFingerprintAsString(certificate) + " already in the database.");
                                    certificatesIgnored.incrementAndGet();
                                    continue;
                                }
                                final Optional<CAInfo> issuer = caSession.getIssuerFor(getAdmin(), certificate);
                                if (!issuer.isPresent()) {
                                    log.info("Ignoring certificate " + CertTools.getSubjectDN(certificate)
                                            + " issued by " + certificate.getIssuerDN() + " not known by this instance.");
                                    certificatesIgnored.incrementAndGet();
                                    return;
                                }
                                if (!endEntityManagementSession.existsUser(CertTools.getFingerprintAsString(certificate))) {
                                    final EndEntityInformation endEntityInformation = new EndEntityInformation();
                                    endEntityInformation.setUsername(CertTools.getFingerprintAsString(certificate));
                                    endEntityInformation.setCAId(issuer.get().getCAId());
                                    endEntityInformation.setTokenType(EndEntityConstants.TOKEN_USERGEN);
                                    endEntityInformation.setStatus(EndEntityConstants.STATUS_GENERATED);
                                    endEntityInformation.setType(new EndEntityType(EndEntityTypes.ENDUSER));
                                    endEntityInformation.setDN(CertTools.getSubjectDN(certificate));
                                    endEntityInformation.setEndEntityProfileId(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
                                    endEntityInformation.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
                                    endEntityInformation.setPassword("foo123");
                                    endEntityManagementSession.addUser(getAdmin(), endEntityInformation, false);
                                }
                                certificateStoreSession.storeCertificate(getAdmin(),
                                        certificate,
                                        CertTools.getFingerprintAsString(certificate),
                                        CertTools.getFingerprintAsString(issuer.get().getCertificateChain().get(0)),
                                        CertificateConstants.CERT_ACTIVE,
                                        CertificateConstants.CERTTYPE_ENDENTITY,
                                        CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                                        EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                                        caSession.determineCrlPartitionIndex(issuer.get().getCAId(), EJBTools.wrap(certificate)),
                                        null,
                                        System.currentTimeMillis(), null);
                                log.info("Imported certificate for '" + CertTools.getSubjectDN(certificate)
                                        + "' from zip entry " + unpackedFile.getFileName() + ".");
                                certificatesImported.incrementAndGet();
                            }
                        } catch (CertificateParsingException e) {
                            log.error("The zip entry " + unpackedFile.getFileName() + " could not be parsed. " +
                                    "Is the zip entry containing X.509 certificate(s) in PEM format?"
                                            + e.getMessage(), null);
                            errors.incrementAndGet();
                        } catch (AuthorizationDeniedException e) {
                            log.error(e.getMessage());
                            errors.incrementAndGet();
                        } catch (CertificateSerialNumberException | IllegalNameException | EndEntityExistsException
                                | CADoesntExistsException | EndEntityProfileValidationException | ApprovalException
                                | WaitingForApprovalException | CustomFieldException e) {
                            log.error("Could not add end entity when processing file " + unpackedFile.getFileName() + ". "
                                    + e.getMessage(), null);
                            errors.incrementAndGet();
                        }
                    });
            FacesContext.getCurrentInstance().addMessage(null,
                    new FacesMessage(FacesMessage.SEVERITY_INFO,
                            certificatesImported.get() + " certificates were imported and "
                                    + certificatesIgnored.get() + " certificates were ignored.",
                            null));
            if (errors.get() > 0) {
                FacesContext.getCurrentInstance().addMessage(null,
                        new FacesMessage(FacesMessage.SEVERITY_ERROR,
                                errors.get() + " errors occurred during the import.",
                                null));
            }
        } catch (IOException e) {
            new FacesMessage(FacesMessage.SEVERITY_ERROR,
                    "The selected certificate bundle could not be uploaded." + e.getMessage(),
                    null);
        }
    }

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
            if (casInProfile.entrySet().stream().anyMatch(e -> (e.getValue() == selectedCaId))) {
                endEntityProfileList.add(endEntityProfileSession.getEndEntityProfileName(entry.getKey()));
            }
        }
        return endEntityProfileList;
    }

    private List<String> rolesUsedByCa(int selectedCaId) {
        final List<String> rolesList = new ArrayList<>();

        final List<Role> roles = roleSession.getAuthorizedRoles(getAdmin());

        for (final Role role : roles) {
            rolesList.addAll(getRolesUsedByCa(role, selectedCaId));
            Collections.sort(rolesList);
        }

        return rolesList;
    }

    private List<String> getRolesUsedByCa(final Role role,  final Integer selectedCaId) {
        final List<String> result = new ArrayList<>();

        final String resource = AccessRulesHelper.normalizeResource(StandardRules.CAACCESS.resource() + selectedCaId);
        if (role.getAccessRules().containsKey(resource)) {
            result.add(role.getName());
        } else {
            try {
                final List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(getAdmin(), role.getRoleId());
                for (RoleMember roleMember : roleMembers) {
                    if (roleMember.getTokenIssuerId() == selectedCaId) {
                        // Do more expensive checks if it is a potential match
                        final AccessMatchValue accessMatchValue = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(
                                roleMember.getTokenType()).getAccessMatchValueIdMap().get(roleMember.getTokenMatchKey());
                        if (accessMatchValue.isIssuedByCa()) {
                            result.add(role.getName());
                            break;
                        }
                    }
                }
            } catch (AuthorizationDeniedException e) {
                log.error("Failed to check roles depended on CA", e);
            }
        }

        return result;
    }

    public String deleteCA() {
        try {
            if (!removeCA(selectedCaId)) {
                addErrorMessage("COULDNTDELETECA");
                final List<String> certificateProfilesUsedByCa = certificateProfilesUsedByCa(selectedCaId);
                if (!certificateProfilesUsedByCa.isEmpty()) {
                    addErrorMessage("CA_INCERTIFICATEPROFILES");
                    addNonTranslatedErrorMessage(StringUtils.join(certificateProfilesUsedByCa, ", "));
                }
                final List<String> endEntityProfilesUsedByCa = endEntityProfilesUsedByCa(selectedCaId);
                if (!endEntityProfilesUsedByCa.isEmpty()) {
                    addErrorMessage("CA_INENDENTITYPROFILES");
                    addNonTranslatedErrorMessage(StringUtils.join(endEntityProfilesUsedByCa, ", "));
                }
                final List<String> rolesUsedByCa = rolesUsedByCa(selectedCaId);
                if (!rolesUsedByCa.isEmpty()) {
                    addErrorMessage("CA_INROLES");
                    addNonTranslatedErrorMessage(StringUtils.join(rolesUsedByCa, ", "));
                }
            }
        } catch (AuthorizationDeniedException | EndEntityProfileNotFoundException e) {
            addNonTranslatedErrorMessage(e.getMessage());
        }
        return EditCaUtil.MANAGE_CA_NAV;
    }
    
    private boolean removeCA(final int caId) throws AuthorizationDeniedException{     
        final boolean caIdIsPresent = endEntityManagementSession.checkForCAId(caId) ||
                certificateProfileSessionLocal.existsCAIdInCertificateProfiles(caId) ||
                endEntityProfileSession.existsCAInEndEntityProfiles(caId) ||
                isCaIdInUseByRoleOrRoleMember(caId);   
        if (!caIdIsPresent) {
            caSession.removeCA(getEjbcaWebBean().getAdminObject(), caId);
        }
        return !caIdIsPresent;
    }
    
    private boolean isCaIdInUseByRoleOrRoleMember(final int caId) {
        for (final Role role : roleDataSession.getAllRoles()) {
            if (role.getAccessRules().containsKey(AccessRulesHelper.normalizeResource(StandardRules.CAACCESS.resource() + caId))) {
                return true;
            }
            for (final RoleMember roleMember : roleMemberDataSession.findRoleMemberByRoleId(role.getRoleId())) {
                if (roleMember.getTokenIssuerId()==caId) {
                    // Do more expensive checks if it is a potential match
                    final AccessMatchValue accessMatchValue = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(
                            roleMember.getTokenType()).getAccessMatchValueIdMap().get(roleMember.getTokenMatchKey());
                    if (accessMatchValue.isIssuedByCa()) {
                        return true;
                    }
                }
            }
        }
        return false;
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
            
            int selectedCaType;
            try {
                selectedCaType = caSession.getCAInfo(getAdmin(), selectedCaId).getCAType();
            } catch (AuthorizationDeniedException e) {
                throw new IllegalStateException("Admin is not authorized to get ca type!", e);
            }
            
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("selectedCaName", caidtonamemap.get(selectedCaId));
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("selectedCaId", selectedCaId);
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("selectedCaType", selectedCaType);

            return EditCaUtil.SIGN_CERT_REQ_NAV;
        } else {
            addErrorMessage("SELECTCAFIRST");
            return EditCaUtil.MANAGE_CA_NAV;
        }
    }
}
