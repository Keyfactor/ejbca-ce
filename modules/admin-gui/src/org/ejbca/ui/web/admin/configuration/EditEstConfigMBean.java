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

import com.keyfactor.util.StringTools;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.ejbca.config.EstConfiguration;
import org.ejbca.core.model.UsernameGenerateMode;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.model.SelectItem;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Backing bean for edit EST alias view.
 */
@Named
@ViewScoped
public class EditEstConfigMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;

    private static final String HIDDEN_PWD = "**********";

    // UniqueIdentifier is left out, because we don't want people to use that
    private static final List<String> dnfields = Arrays.asList("CN", "UID", "OU", "O", "L", "ST", "DC", "C", "emailAddress", "SN", "givenName", "initials", "surname", "title",
            "unstructuredAddress", "unstructuredName", "postalCode", "businessCategory", "dnQualifier", "postalAddress",
            "telephoneNumber", "pseudonym", "streetAddress", "name", "role", "CIF", "NIF", "VID", "PID", "CertificationID");

    private String selectedRaNameSchemeDnPart;

    @EJB
    private CaSessionLocal caSession;

    private TreeMap<Integer, String> caIdToNameMap;
    private TreeMap<String, Integer> caNameToIdMap;

    @Inject
    private EstConfigMBean estConfigMBean;
    private EstAliasGui estAliasGui = null;

    @PostConstruct
    public void initialize() {
        getEjbcaWebBean().clearEstConfigClone();
        caIdToNameMap = caSession.getAuthorizedCaIdsToNames(getAdmin());
        caNameToIdMap = caSession.getAuthorizedCaNamesToIds(getAdmin());
    }

    public class EstAliasGui {
        private String name;
        private String caId;
        private String endEntityProfileId;
        private String certificateProfileId;
        private Boolean certificateRequired;
        private String userName;
        private String password;
        private Boolean allowSameKey;
        private String extUsernameComponent;
        private String operationmode;
        private String authModule;
        private String vendorCas;
        private String selectedVendorCa;
        private boolean vendorMode;
        private boolean allowChangeSubjectName;
        private String extDnPartPwdComponent;
        private boolean usesProxyCa;
        private boolean serverKeyGenEnabled;
        private String raNameGenPrefix;
        private String raNameGenPostfix;
        private String raNameGenParams;
        private String raNameGenScheme;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getCaId() {
            return caId;
        }

        public void setCaId(String caId) {
            this.caId = caId;
        }

        public String getEndEntityProfileId() {
            return endEntityProfileId;
        }

        public void setEndEntityProfileId(String endEntityProfileId) {
            this.endEntityProfileId = endEntityProfileId;
        }

        public String getCertificateProfileId() {
            return certificateProfileId;
        }

        public void setCertificateProfileId(String certificateProfileId) {
            this.certificateProfileId = certificateProfileId;
        }

        public Boolean getCertificateRequired() {
            return certificateRequired;
        }

        public void setCertificateRequired(Boolean certificateRequired) {
            this.certificateRequired = certificateRequired;
        }

        public String getUserName() {
            return userName;
        }

        public void setUserName(String userName) {
            this.userName = userName;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public Boolean getAllowSameKey() {
            return allowSameKey;
        }

        public void setAllowSameKey(Boolean allowSameKey) {
            this.allowSameKey = allowSameKey;
        }

        public String getOperationMode() {
            return operationmode;
        }

        public void setOperationMode(String operationmode) {
            this.operationmode = operationmode;
        }

        public void setVendorMode(boolean vendorMode) {
            this.vendorMode = vendorMode;
        }

        public boolean getVendorMode() {
            return this.vendorMode;
        }

        public void setAllowChangeSubjectName(boolean allowChangeSubjectName) {
            this.allowChangeSubjectName = allowChangeSubjectName;
        }

        public boolean getAllowChangeSubjectName() {
            return this.allowChangeSubjectName;
        }

        public void setSelectedVendorCa(String selectedVendorCa) {
            this.selectedVendorCa = selectedVendorCa;
        }

        public String getSelectedVendorCa() {
            return selectedVendorCa == null
                    ? String.valueOf(getVendorCaSelectItems().get(0).getValue())
                    : selectedVendorCa;
        }

        public void setVendorCas(String vendorCas) {
            this.vendorCas = vendorCas;
        }


        public String getVendorCas() {
            return vendorCas == null ? "" : vendorCas;
        }

        public void setAuthenticationModule(final String authModule) {
            this.authModule = authModule;
        }

        public String getAuthenticationModule() {
            return this.authModule;
        }

        public String getExtDnPartPwdComponent() {
            return extDnPartPwdComponent;
        }

        public void setExtDnPartPwdComponent(String extDnPartPwdComponent) {
            this.extDnPartPwdComponent = extDnPartPwdComponent;
        }

        public boolean getDnPartPwdSelected() {
            return getAuthenticationModule().equals(EstConfiguration.CONFIG_AUTHMODULE_DN_PART_PWD);
        }

        public void setDnPartPwdSelected(boolean dnPartPwdSelected) {
            if (dnPartPwdSelected) {
                setAuthenticationModule(EstConfiguration.CONFIG_AUTHMODULE_DN_PART_PWD);
            } else if (getAuthenticationModule().equals(EstConfiguration.CONFIG_AUTHMODULE_DN_PART_PWD)) {
                setAuthenticationModule("");
            }
        }

        public void setHttpBasicAuthSelected(boolean selected) {
            if (selected) {
                setAuthenticationModule(EstConfiguration.CONFIG_AUTHMODULE_HTTP_BASIC_AUTH);
            } else {
                setAuthenticationModule("");
            }
        }

        public boolean getHttpBasicAuthSelected() {
            return getAuthenticationModule().equals(EstConfiguration.CONFIG_AUTHMODULE_HTTP_BASIC_AUTH);
        }

        public boolean getChallengePwdSelected() {
            return getAuthenticationModule().equals(EstConfiguration.CONFIG_AUTHMODULE_CHALLENGE_PWD);
        }

        public void setChallengePwdSelected(boolean challengePwdSelected) {
            if (challengePwdSelected) {
                setAuthenticationModule(EstConfiguration.CONFIG_AUTHMODULE_CHALLENGE_PWD);
            } else if (getAuthenticationModule().equals(EstConfiguration.CONFIG_AUTHMODULE_CHALLENGE_PWD)) {
                setAuthenticationModule("");
            }
        }

        public void setExtUsernameComponent(String extUsernameComponent) {
            this.extUsernameComponent = extUsernameComponent;
        }

        public String getExtUsernameComponent() {
            return extUsernameComponent;
        }

        public boolean isUsesProxyCa() {
            return usesProxyCa;
        }

        public void setUsesProxyCa(boolean usesProxyCa) {
            this.usesProxyCa = usesProxyCa;
        }

        public boolean isServerKeyGenEnabled() {
            return serverKeyGenEnabled;
        }

        public void setServerKeyGenEnabled(boolean serverKeyGenEnabled) {
            this.serverKeyGenEnabled = serverKeyGenEnabled;
        }

        public void setRaNameGenPrefix(final String raNameGenPrefix) {
            this.raNameGenPrefix = raNameGenPrefix;
        }

        public String getRaNameGenPrefix() {
            return raNameGenPrefix;
        }

        public void setRaNameGenPostfix(final String raNameGenPostfix) {
            this.raNameGenPostfix = raNameGenPostfix;
        }

        public String getRaNameGenPostfix() {
            return raNameGenPostfix;
        }

        public void setRaNameGenParams(final String raNameGenParams) {
            this.raNameGenParams = raNameGenParams;
        }

        public String getRaNameGenParams() {
            return raNameGenParams;
        }

        public void setRaNameGenScheme(final String raNameGenScheme) {
            this.raNameGenScheme = raNameGenScheme;
        }

        public String getRaNameGenScheme() {
            return raNameGenScheme;
        }
    }

    protected EstAliasGui getDefaultEstAliasGui() {
        EstAliasGui estAliasGui = new EstAliasGui();
        estAliasGui.setCaId(EstConfiguration.DEFAULT_DEFAULTCA);
        estAliasGui.setCertificateProfileId(EstConfiguration.DEFAULT_CERTPROFILE);
        estAliasGui.setEndEntityProfileId(EstConfiguration.DEFAULT_EEPROFILE);
        estAliasGui.setCertificateRequired(Boolean.valueOf(EstConfiguration.DEFAULT_REQCERT));
        estAliasGui.setUserName(EstConfiguration.DEFAULT_REQUSERNAME);
        estAliasGui.setPassword(EstConfiguration.DEFAULT_REQPASSWORD);
        estAliasGui.setAllowSameKey(Boolean.valueOf(EstConfiguration.DEFAULT_ALLOWUPDATEWITHSAMEKEY));
        estAliasGui.setRaNameGenScheme(EstConfiguration.DEFAULT_RA_USERNAME_GENERATION_SCHEME);
        estAliasGui.setRaNameGenParams(EstConfiguration.DEFAULT_RA_USERNAME_GENERATION_PARAMS);
        estAliasGui.setRaNameGenPrefix(EstConfiguration.DEFAULT_RA_USERNAME_GENERATION_PREFIX);
        estAliasGui.setRaNameGenPostfix(EstConfiguration.DEFAULT_RA_USERNAME_GENERATION_POSTFIX);
        estAliasGui.setVendorMode(Boolean.valueOf(EstConfiguration.DEFAULT_VENDOR_CERTIFICATE_MODE));
        estAliasGui.setVendorCas(EstConfiguration.DEFAULT_VENDOR_CA_IDS);
        estAliasGui.setOperationMode(EstConfiguration.OPERATION_MODE_RA);
        estAliasGui.setExtUsernameComponent(EstConfiguration.DEFAULT_EXTRACT_USERNAME_COMPONENT);
        estAliasGui.setExtDnPartPwdComponent(EstConfiguration.DEFAULT_EXTRACTDNPARTPWD_COMPONENT);
        estAliasGui.setAuthenticationModule(EstConfiguration.DEFAULT_CLIENT_AUTHENTICATION_MODULE);
        estAliasGui.setAllowChangeSubjectName(Boolean.valueOf(EstConfiguration.DEFAULT_ALLOW_CHANGESUBJECTNAME));
        estAliasGui.setUsesProxyCa(Boolean.valueOf(EstConfiguration.DEFAULT_SUPPORT_PROXY_CA));
        estAliasGui.setServerKeyGenEnabled(Boolean.valueOf(EstConfiguration.DEFAULT_SERVER_KEYGEN_ENABLED));
        return estAliasGui;
    }

    protected EstAliasGui readEstAliasGui(final String aliasName) {
        EstAliasGui estAliasGui = new EstAliasGui();
        estAliasGui.setName(aliasName);
        EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfiguration();
        estAliasGui.setCaId(estConfiguration.getDefaultCAID(aliasName));
        estAliasGui.setEndEntityProfileId(String.valueOf(estConfiguration.getEndEntityProfileID(aliasName)));
        String certProfileID = estConfiguration.getCertProfileID(aliasName);
        // If we had the old type, EJBCA 6.11 of CP, which is the name, convert it to ID
        if (certProfileID != null && !NumberUtils.isNumber(certProfileID)) {
            Map<String, Integer> certificateProfiles = getEjbcaWebBean().getCertificateProfilesNoKeyId(estAliasGui.getEndEntityProfileId());
            if (certificateProfiles.get(certProfileID) != null) {
                certProfileID = String.valueOf(certificateProfiles.get(certProfileID));
            }
        }
        estAliasGui.setCertificateProfileId(certProfileID);
        estAliasGui.setCertificateRequired(estConfiguration.getCert(aliasName));
        estAliasGui.setUserName(estConfiguration.getUsername(aliasName));
        estAliasGui.setPassword(EditEstConfigMBean.HIDDEN_PWD);
        estAliasGui.setAllowSameKey(estConfiguration.getKurAllowSameKey(aliasName));
        estAliasGui.setServerKeyGenEnabled(estConfiguration.getServerKeyGenerationEnabled(aliasName));
        estAliasGui.setExtUsernameComponent(estConfiguration.getExtractUsernameComponent(aliasName));
        estAliasGui.setOperationMode(estConfiguration.getOperationMode(aliasName));
        estAliasGui.setVendorMode(estConfiguration.getVendorMode(aliasName));
        estAliasGui.setAuthenticationModule(estConfiguration.getAuthenticationModule(aliasName));
        estAliasGui.setChallengePwdSelected(estConfiguration.getAuthenticationModule(aliasName).equals(EstConfiguration.CONFIG_AUTHMODULE_CHALLENGE_PWD));
        estAliasGui.setDnPartPwdSelected(estConfiguration.getAuthenticationModule(aliasName).equals(EstConfiguration.CONFIG_AUTHMODULE_DN_PART_PWD));
        estAliasGui.setExtDnPartPwdComponent(estConfiguration.getExtractDnPwdComponent(aliasName));
        estAliasGui.setAllowChangeSubjectName(estConfiguration.getAllowChangeSubjectName(aliasName));
        estAliasGui.setRaNameGenPrefix(estConfiguration.getRANameGenPrefix(aliasName));
        estAliasGui.setRaNameGenPostfix(estConfiguration.getRANameGenPostfix(aliasName));
        estAliasGui.setRaNameGenParams(estConfiguration.getRANameGenParams(aliasName));
        estAliasGui.setRaNameGenScheme(estConfiguration.getRANameGenScheme(aliasName));

        String vendorCaIds = estConfiguration.getVendorCaIds(aliasName);
        ArrayList<String> vendorCaNames = new ArrayList<>();
        if (!StringUtils.isEmpty(vendorCaIds)) {
            for (String vendorCaId : vendorCaIds.split(";")) {
                String caName = caIdToNameMap.get(Integer.parseInt(vendorCaId));
                vendorCaNames.add(caName);
            }
            estAliasGui.setVendorCas(StringUtils.join(vendorCaNames, ";"));
        } else {
            estAliasGui.setVendorCas("");
        }
        estAliasGui.setUsesProxyCa(estConfiguration.getSupportProxyCa(aliasName));
        return estAliasGui;
    }


    public EstAliasGui getEstAlias() throws NumberFormatException {
        String aliasName = estConfigMBean.getSelectedAlias();
        if (estAliasGui == null) {
            if (StringUtils.isEmpty(aliasName)) {
                this.estAliasGui = getDefaultEstAliasGui();
            } else {
                this.estAliasGui = readEstAliasGui(aliasName);
            }
        }
        return estAliasGui;
    }

    public boolean isViewOnly() {
        return estConfigMBean.isViewOnly();
    }

    public boolean isRaMode() {
        return estAliasGui.getOperationMode().equals("ra");
    }

    public boolean isVendorMode() {
        return estAliasGui.getVendorMode();
    }

    public List<SelectItem> getExtUsernameComponentSelectItems() {
        final List<SelectItem> selectItems = getDnFieldSelectItems();
        selectItems.add(0, new SelectItem("DN"));
        return selectItems;
    }

    public List<SelectItem> getCaItemList() throws NumberFormatException, AuthorizationDeniedException {
        final List<SelectItem> ret = new ArrayList<>();
        if (StringUtils.isEmpty(getEstAlias().getCaId())) {
            ret.add(new SelectItem("", EjbcaJSFHelper.getBean().getText().get("ESTDEFAULTCA_DISABLED")));
        }
        for (String caname : caNameToIdMap.keySet()) {
            final Integer caId = caNameToIdMap.get(caname);
            ret.add(new SelectItem(caId, caname));
        }
        return ret;
    }

    public List<SelectItem> getEndEntityProfileItemList() {
        final List<SelectItem> ret = new ArrayList<>();
        Map<String, String> nameToIdMap = getEjbcaWebBean().getAuthorizedEEProfilesAndIdsNoKeyId(AccessRulesConstants.CREATE_END_ENTITY);
        for (String endEntityProfileName : nameToIdMap.keySet()) {
            String endEntityProfileId = nameToIdMap.get(endEntityProfileName);
            ret.add(new SelectItem(endEntityProfileId, endEntityProfileName));
        }
        return ret;
    }

    public List<SelectItem> getCertificateProfileItemList() {
        final List<SelectItem> ret = new ArrayList<>();
        if (estAliasGui.getEndEntityProfileId() != null) {
            Map<String, Integer> certificateProfiles = getEjbcaWebBean().getCertificateProfilesNoKeyId(estAliasGui.getEndEntityProfileId());
            for (String certificateProfileName : certificateProfiles.keySet()) {
                int certificateProfileId = certificateProfiles.get(certificateProfileName);
                ret.add(new SelectItem(certificateProfileId, certificateProfileName));
            }
        }
        return ret;
    }

    public String cancel() {
        reset();
        return "done";
    }

    public boolean renameOrAddAlias() throws AuthorizationDeniedException {

        String oldAlias = estConfigMBean.getSelectedAlias();
        String newAlias = estAliasGui.getName();

        if (StringUtils.isNotEmpty(oldAlias) && Objects.equals(oldAlias, newAlias)) {
            return true;
        }

        if (StringUtils.isEmpty(newAlias)) {
            addErrorMessage("ONLYCHARACTERS");
            return false;
        }

        if (!StringTools.checkFieldForLegalChars(newAlias)) {
            addErrorMessage("ONLYCHARACTERS");
            return false;
        }

        if (estConfigMBean.getEstConfiguration().aliasExists(newAlias)) {
            addErrorMessage("ESTCOULDNOTRENAMEORCLONE");
            return false;
        }

        if (StringUtils.isEmpty(oldAlias)) {
            getEjbcaWebBean().addEstAlias(newAlias);
        } else {
            getEjbcaWebBean().renameEstAlias(oldAlias, newAlias);
        }

        estAliasGui.setName(newAlias);
        estConfigMBean.setSelectedAlias(newAlias);
        getEjbcaWebBean().clearEstConfigClone();
        getEjbcaWebBean().reloadEstConfiguration();
        return true;
    }

    public String save() throws AuthorizationDeniedException {

        if (!renameOrAddAlias()) {
            return null;
        }

        String alias = estAliasGui.getName();
        EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfigForEdit(alias);
        if (StringUtils.isEmpty(estAliasGui.getCaId())) {
            estConfiguration.setDefaultCAID(alias);
        } else {
            estConfiguration.setDefaultCAID(alias, Integer.valueOf(estAliasGui.getCaId()));
        }
        if (estAliasGui.getEndEntityProfileId() != null) {
            estConfiguration.setEndEntityProfileID(alias, Integer.valueOf(estAliasGui.getEndEntityProfileId()));
        }
        if (estAliasGui.getCertificateProfileId() != null) {
            estConfiguration.setCertProfileID(alias, Integer.valueOf(estAliasGui.getCertificateProfileId()));
        }
        estConfiguration.setCert(alias, estAliasGui.getCertificateRequired());
        estConfiguration.setUsername(alias, estAliasGui.getUserName());
        // If the client secret was not changed from the placeholder value in the UI, set the old value, i.e. no change
        if (!estAliasGui.getPassword().equals(EditEstConfigMBean.HIDDEN_PWD)) {
            estConfiguration.setPassword(alias, estAliasGui.getPassword());
        }
        estConfiguration.setKurAllowSameKey(alias, estAliasGui.getAllowSameKey());
        estConfiguration.setServerKeyGenerationEnabled(alias, estAliasGui.isServerKeyGenEnabled());
        estConfiguration.setExtractUsernameComponent(alias, estAliasGui.getExtUsernameComponent());
        estConfiguration.setExtractDnPwdComponent(alias, estAliasGui.getExtDnPartPwdComponent());
        estConfiguration.setOperationMode(alias, estAliasGui.getOperationMode());
        estConfiguration.setVendorMode(alias, estAliasGui.getVendorMode());
        estConfiguration.setAuthenticationModule(alias, estAliasGui.getAuthenticationModule());
        estConfiguration.setAllowChangeSubjectName(alias, estAliasGui.getAllowChangeSubjectName());
        estConfiguration.setRANameGenPrefix(alias, estAliasGui.getRaNameGenPrefix());
        estConfiguration.setRANameGenPostfix(alias, estAliasGui.getRaNameGenPostfix());
        estConfiguration.setRANameGenParams(alias, estAliasGui.getRaNameGenParams());
        estConfiguration.setRANameGenScheme(alias, estAliasGui.getRaNameGenScheme());

        final String currentVendorCas = getCurrentVendorCas();
        if (StringUtils.isEmpty(currentVendorCas)) {
            estConfiguration.setVendorCaIds(alias, "");
        } else {
            final String[] vendorCaNames = currentVendorCas.split(";");
            final ArrayList<String> vendorCaIds = new ArrayList<>();
            for (String vendorCaName : vendorCaNames) {
                Integer caId = caNameToIdMap.get(vendorCaName.trim());
                vendorCaIds.add(caId.toString());
            }
            estConfiguration.setVendorCaIds(alias, StringUtils.join(vendorCaIds, ";"));
        }
        updateSupportProxyCa();
        estConfiguration.setSupportProxyCa(alias, estAliasGui.isUsesProxyCa());
        getEjbcaWebBean().updateEstConfigFromClone(alias);
        reset();
        return "done";
    }

    public void actionAddVendorCa() {
        final String currentVendorCas = getCurrentVendorCas();
        List<String> currentVendorCaList = new ArrayList<>();
        if (StringUtils.isNotBlank(currentVendorCas)) {
            currentVendorCaList = new ArrayList<>(Arrays.asList(currentVendorCas.split(";")));
        }
        if (!currentVendorCaList.contains(estAliasGui.getSelectedVendorCa())) {
            currentVendorCaList.add(estAliasGui.getSelectedVendorCa());
        }
        setCurrentVendorCas(StringUtils.join(currentVendorCaList, ";"));
        updateSupportProxyCa();
    }

    public void actionRemoveVendorCa() {
        final String currentVendorCas = getCurrentVendorCas();
        if (StringUtils.isNotBlank(currentVendorCas)) {
            final List<String> currentVendorCaList = new ArrayList<>(Arrays.asList(currentVendorCas.split(";")));
            if (currentVendorCaList.remove(estAliasGui.getSelectedVendorCa())) {
                setCurrentVendorCas(StringUtils.join(currentVendorCaList, ";"));
                updateSupportProxyCa();
            }
        }
    }

    private void updateSupportProxyCa() {
        final AuthenticationToken authenticationToken = getAdmin();
        final CaSessionLocal caSession = getEjbcaWebBean().getEjb().getCaSession();
        estAliasGui.setUsesProxyCa(false); //default, repeated for remove action

        if (!isRaMode() && isVendorMode() && StringUtils.isNotBlank(getCurrentVendorCas())) {
            List<String> currentVendorCaList = new ArrayList<>(Arrays.asList(getCurrentVendorCas().split(";")));
            for (String caName : currentVendorCaList) {
                try {
                    if (caSession.getCAInfo(authenticationToken, caName).getCAType() == CAInfo.CATYPE_PROXY) {
                        estAliasGui.setUsesProxyCa(true);
                        return;
                    }
                } catch (AuthorizationDeniedException e) {
                    // should not happen
                    throw new IllegalStateException("Vendor CA is not authorized.");
                }
            }
        }

        if (isRaMode() && StringUtils.isNotBlank(estAliasGui.getCaId())) {
            try {
                if (caSession.getCAInfo(authenticationToken, Integer.valueOf(estAliasGui.getCaId())).getCAType() == CAInfo.CATYPE_PROXY) {
                    estAliasGui.setUsesProxyCa(true);
                }
            } catch (AuthorizationDeniedException e) {
                // should not happen
                throw new IllegalStateException("RA CA is not authorized.");
            }
        }
    }

    public List<SelectItem> getVendorCaSelectItems() {
        return caIdToNameMap.values().stream().map(SelectItem::new).collect(Collectors.toList());
    }

    private String vendorCas;

    public String getCurrentVendorCas() {
        return vendorCas == null ? estAliasGui.getVendorCas() : vendorCas;
    }

    public void setCurrentVendorCas(String vendorCas) {
        this.vendorCas = vendorCas;
    }

    /**
     * Add DN field to name generation parameter
     */
    public void actionAddRaNameSchemeDnPart() {
        String currentNameGenParam = estAliasGui.getRaNameGenParams();
        String[] params = currentNameGenParam == null ? new String[0] : currentNameGenParam.split(";");
        // Verify that current param is instance of DN fields
        if ((params.length > 0) && (dnfields.contains(params[0]))) {
            if (!ArrayUtils.contains(params, getSelectedRaNameSchemeDnPart())) {
                currentNameGenParam += ";" + getSelectedRaNameSchemeDnPart();
            }
        } else {
            currentNameGenParam = getSelectedRaNameSchemeDnPart();
        }
        estAliasGui.setRaNameGenParams(currentNameGenParam);
    }

    /**
     * Remove DN field from name generation parameter
     */
    public void actionRemoveRaNameSchemeDnPart() {
        String currentNameGenParam = estAliasGui.getRaNameGenParams();
        if (StringUtils.contains(currentNameGenParam, getSelectedRaNameSchemeDnPart())) {
            String[] params = currentNameGenParam.split(";");
            if (params.length == 1) {
                currentNameGenParam = "";
            } else {
                if (StringUtils.equals(params[0], getSelectedRaNameSchemeDnPart())) {
                    currentNameGenParam = StringUtils.remove(currentNameGenParam, getSelectedRaNameSchemeDnPart() + ";");
                } else {
                    currentNameGenParam = StringUtils.remove(currentNameGenParam, ";" + getSelectedRaNameSchemeDnPart());
                }
            }
            estAliasGui.setRaNameGenParams(currentNameGenParam);
        }
    }

    public String getSelectedEstAlias() {
        return estConfigMBean.getSelectedAlias();
    }

    /**
     * Get the available RA name generation schemes for radio buttons
     */
    public List<SelectItem> getAvailableRaNameGenSchemes() {
        return Arrays.stream(UsernameGenerateMode.values())
                .map(UsernameGenerateMode::name)
                .map(SelectItem::new).collect(Collectors.toList());
    }

    /**
     * Get the selected name generation DN part for addition or removal
     */
    public String getSelectedRaNameSchemeDnPart() {
        return selectedRaNameSchemeDnPart == null ? dnfields.get(0) : selectedRaNameSchemeDnPart;
    }

    /**
     * Set the selected name generation DN part for addition or removal
     */
    public void setSelectedRaNameSchemeDnPart(final String selectedRaNameSchemeDnPart) {
        this.selectedRaNameSchemeDnPart = selectedRaNameSchemeDnPart;
    }

    /**
     * Get the DN field select items. Full list of available DN fields.
     */
    public List<SelectItem> getDnFieldSelectItems() {
        return dnfields.stream().map(SelectItem::new).collect(Collectors.toList());
    }

    private void reset() {
        estAliasGui = null;
        getEjbcaWebBean().clearEstConfigClone();
        estConfigMBean.actionCancel();
    }

    public EstConfigMBean getEstConfigMBean() {
        return estConfigMBean;
    }

    public void setEstConfigMBean(EstConfigMBean estConfigMBean) {
        this.estConfigMBean = estConfigMBean;
    }
}