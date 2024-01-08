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

package org.ejbca.ui.web.admin.cmp;

import com.keyfactor.util.StringTools;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.UsernameGenerateMode;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

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
import java.util.Objects;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * JavaServer Faces Managed Bean for editing CMP alias.
 */
@Named
@ViewScoped
public class EditCmpConfigMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private static final String HIDDEN_PWD = "**********";
    public static final String PBE_MODE = "pbe";

    // UniqueIdentifier is left out, because we don't want people to use that
    private static final List<String> dnfields = List.of("CN", "UID", "OU", "O", "L", "ST", "DC", "C", "emailAddress",
            "SN", "givenName", "initials", "surname", "title", "unstructuredAddress", "unstructuredName", "postalCode",
            "businessCategory", "dnQualifier", "postalAddress", "telephoneNumber", "pseudonym", "streetAddress", "name",
            "role", "CIF", "NIF", "VID", "PID", "CertificationID");

    @EJB
    private CaSessionLocal caSession;
    @Inject
    private CmpConfigMBean cmpConfigMBean;

    private TreeMap<Integer, String> caIdToNameMap;
    private TreeMap<String, Integer> caNameToIdMap;
    private CmpDto cmpDto;

    private String selectedRaNameSchemeDnPart;
    private String selectedVendorCa;
    private String selectedCmpResponseAdditionalCaCert;
    private String selectedPkiResponseAdditionalCaCert;

    // Authentication module specific
    private boolean hmacSelected;
    private boolean hmacSharedSecret;
    private boolean eeCertSelected;
    private boolean regTokenPwdSelected;
    private boolean dnPartPwdSelected;
    private String hmacParam;
    private String selectedIssuerCa;
    private String selectedDnField;

    public EditCmpConfigMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
    }

    @PostConstruct
    public void initialize() {
        final String alias = getSelectedCmpAlias();
        if (alias != null) {
            cmpDto = readCmpDto(alias);
        } else {
            cmpDto = getDefaultCmpDto();
        }

        final String hmacAuthParam = getAuthenticationParameter(CmpConfiguration.AUTHMODULE_HMAC);
        final String eeCertParam = getAuthenticationParameter(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        final String dnPartPwdParam = getAuthenticationParameter(CmpConfiguration.AUTHMODULE_DN_PART_PWD);

        hmacSelected = isModulesContainsModule(CmpConfiguration.AUTHMODULE_HMAC);
        eeCertSelected = isModulesContainsModule(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        regTokenPwdSelected = isModulesContainsModule(CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD);
        dnPartPwdSelected = isModulesContainsModule(CmpConfiguration.AUTHMODULE_DN_PART_PWD);

        hmacParam = EditCmpConfigMBean.HIDDEN_PWD;
        if (hmacAuthParam.isEmpty() || hmacAuthParam.equals("-")) {
            hmacSharedSecret = true;
            hmacParam = "";
        }
        if (!StringUtils.isEmpty(eeCertParam)) {
            selectedIssuerCa = eeCertParam;
        }
        if (!StringUtils.isEmpty(dnPartPwdParam)) {
            selectedDnField = dnPartPwdParam;
        }
        caIdToNameMap = caSession.getAuthorizedCaIdsToNames(getAdmin());
        caNameToIdMap = caSession.getAuthorizedCaNamesToIds(getAdmin());
    }

    protected boolean isModulesContainsModule(final String authModule) {
        return CmpConfiguration.isModulesContainsModule(getCmpDto().getAuthenticationModule(), authModule);
    }

    public String getAuthenticationParameter(final String authModule) {
        return CmpConfiguration.getAuthenticationParameter(authModule, getCmpDto().getAuthenticationModule(), getCmpDto().getAuthenticationParameters());
    }

    public CmpDto getCmpDto() {
        return cmpDto;
    }

    public void setCmpDto(CmpDto cmpDto) {
        this.cmpDto = cmpDto;
    }

    protected CmpDto getDefaultCmpDto() {
        CmpDto cmpDto = new CmpDto();
        cmpDto.setCMPDefaultCA(CmpConfiguration.DEFAULT_DEFAULTCA);
        cmpDto.setResponseProtection(CmpConfiguration.DEFAULT_RESPONSE_PROTECTION);
        cmpDto.setRaMode(CmpConfiguration.isRAMode(CmpConfiguration.DEFAULT_OPERATION_MODE));
        cmpDto.setAuthenticationModule(CmpConfiguration.DEFAULT_CLIENT_AUTHENTICATION_MODULE);
        cmpDto.setAuthenticationParameters(CmpConfiguration.DEFAULT_CLIENT_AUTHENTICATION_PARAMS);
        cmpDto.setExtractUsernameComponent(CmpConfiguration.DEFAULT_EXTRACT_USERNAME_COMPONENT);
        cmpDto.setVendorMode(Boolean.parseBoolean(CmpConfiguration.DEFAULT_VENDOR_MODE));
        cmpDto.setVendorCaIds(CmpConfiguration.DEFAULT_VENDOR_CA_IDS);
        cmpDto.setResponseCaPubsCA(CmpConfiguration.DEFAULT_RESPONSE_CAPUBS_CA);
        cmpDto.setResponseCaPubsIssuingCA(Boolean.parseBoolean(CmpConfiguration.DEFAULT_RESPONSE_CAPUBS_ISSUING_CA));
        cmpDto.setResponseExtraCertsCA(CmpConfiguration.DEFAULT_RESPONSE_EXTRACERTS_CA);
        cmpDto.setAllowRAVerifyPOPO(Boolean.parseBoolean(CmpConfiguration.DEFAULT_ALLOW_RA_VERIFY_POPO));
        cmpDto.setRaNameGenScheme(CmpConfiguration.DEFAULT_RA_USERNAME_GENERATION_SCHEME);
        cmpDto.setRaNameGenParams(CmpConfiguration.DEFAULT_RA_USERNAME_GENERATION_PARAMS);
        cmpDto.setRaNameGenPrefix(CmpConfiguration.DEFAULT_RA_USERNAME_GENERATION_PREFIX);
        cmpDto.setRaNameGenPostfix(CmpConfiguration.DEFAULT_RA_USERNAME_GENERATION_POSTFIX);
        cmpDto.setRaPwdGenParams(CmpConfiguration.DEFAULT_RA_PASSWORD_GENERARION_PARAMS);
        cmpDto.setAllowRACustomSerno(Boolean.parseBoolean(CmpConfiguration.DEFAULT_RA_ALLOW_CUSTOM_SERNO));
//        data.put(alias + CONFIG_RA_ENDENTITYPROFILE, "EMPTY");
        cmpDto.setRaEEProfile(CmpConfiguration.DEFAULT_RA_EEPROFILE);
        cmpDto.setRaCertProfile(CmpConfiguration.DEFAULT_RA_CERTPROFILE);
        cmpDto.setRaCAName(CmpConfiguration.DEFAULT_RA_CANAME);
        cmpDto.setRaCertPath(CmpConfiguration.DEFAULT_RACERT_PATH);
        cmpDto.setOmitVerificationsInEEC(Boolean.parseBoolean(CmpConfiguration.DEFAULT_RA_OMITVERIFICATIONSINEEC));
        cmpDto.setKurAllowAutomaticUpdate(Boolean.parseBoolean(CmpConfiguration.DEFAULT_KUR_ALLOW_AUTOMATIC_KEYUPDATE));
        cmpDto.setAllowServerGeneratedKeys(Boolean.parseBoolean(CmpConfiguration.DEFAULT_ALLOW_SERVERGENERATED_KEYS));
        cmpDto.setKurAllowSameKey(Boolean.parseBoolean(CmpConfiguration.DEFAULT_KUR_ALLOW_SAME_KEY));
        cmpDto.setCertReqHandlerClass(CmpConfiguration.DEFAULT_CERTREQHANDLER);
        cmpDto.setUseExtendedValidation(Boolean.parseBoolean(CmpConfiguration.DEFAULT_EXTENDEDVALIDATION));
        return cmpDto;
    }


    protected CmpDto readCmpDto(final String aliasName) {
        CmpConfiguration cmpConfiguration = getEjbcaWebBean().getCmpConfigForEdit(aliasName);
        final CmpDto cmpDTO = new CmpDto();
        cmpDTO.setAlias(aliasName);
        cmpDTO.setCMPDefaultCA(cmpConfiguration.getCMPDefaultCA(aliasName));
        cmpDTO.setResponseProtection(cmpConfiguration.getResponseProtection(aliasName));
        cmpDTO.setRaMode(cmpConfiguration.getRAMode(aliasName));
        cmpDTO.setAuthenticationModule(cmpConfiguration.getAuthenticationModule(aliasName));
        cmpDTO.setAuthenticationParameters(cmpConfiguration.getAuthenticationParameters(aliasName));
        cmpDTO.setExtractUsernameComponent(cmpConfiguration.getExtractUsernameComponent(aliasName));
        cmpDTO.setVendorMode(cmpConfiguration.getVendorMode(aliasName));
        cmpDTO.setVendorCaIds(cmpConfiguration.getVendorCaIds(aliasName));
        cmpDTO.setResponseCaPubsCA(cmpConfiguration.getResponseCaPubsCA(aliasName));
        cmpDTO.setResponseCaPubsIssuingCA(cmpConfiguration.getResponseCaPubsIssuingCA(aliasName));
        cmpDTO.setResponseExtraCertsCA(cmpConfiguration.getResponseExtraCertsCA(aliasName));
        cmpDTO.setAllowRAVerifyPOPO(cmpConfiguration.getAllowRAVerifyPOPO(aliasName));
        cmpDTO.setRaNameGenScheme(cmpConfiguration.getRANameGenScheme(aliasName));
        cmpDTO.setRaNameGenParams(cmpConfiguration.getRANameGenParams(aliasName));
        cmpDTO.setRaNameGenPrefix(cmpConfiguration.getRANameGenPrefix(aliasName));
        cmpDTO.setRaNameGenPostfix(cmpConfiguration.getRANameGenPostfix(aliasName));
        cmpDTO.setRaPwdGenParams(cmpConfiguration.getRAPwdGenParams(aliasName));
        cmpDTO.setAllowRACustomSerno(cmpConfiguration.getAllowRACustomSerno(aliasName));
        cmpDTO.setRaEEProfile(cmpConfiguration.getRAEEProfile(aliasName));
        cmpDTO.setRaCertProfile(cmpConfiguration.getRACertProfile(aliasName));
        cmpDTO.setRaCAName(cmpConfiguration.getRACAName(aliasName));
        cmpDTO.setRaCertPath(cmpConfiguration.getRACertPath(aliasName));
        cmpDTO.setOmitVerificationsInEEC(cmpConfiguration.getOmitVerificationsInEEC(aliasName));
        cmpDTO.setKurAllowAutomaticUpdate(cmpConfiguration.getKurAllowAutomaticUpdate(aliasName));
        cmpDTO.setAllowServerGeneratedKeys(cmpConfiguration.getAllowServerGeneratedKeys(aliasName));
        cmpDTO.setKurAllowSameKey(cmpConfiguration.getKurAllowSameKey(aliasName));
        cmpDTO.setCertReqHandlerClass(cmpConfiguration.getCertReqHandlerClass(aliasName));
        cmpDTO.setUseExtendedValidation(cmpConfiguration.getUseExtendedValidation(aliasName));
        return cmpDTO;
    }

    protected void updateCmpConfiguration() {
        final String alias = this.cmpDto.getAlias();
        CmpConfiguration cmpConfiguration = getEjbcaWebBean().getCmpConfigForEdit(alias);
        cmpConfiguration.setCMPDefaultCA(alias, this.cmpDto.getCMPDefaultCA());
        cmpConfiguration.setResponseProtection(alias, this.cmpDto.getResponseProtection());
        cmpConfiguration.setRAMode(alias, this.cmpDto.isRaMode());
        cmpConfiguration.setAuthenticationModule(alias, this.cmpDto.getAuthenticationModule());
        cmpConfiguration.setAuthenticationParameters(alias, this.cmpDto.getAuthenticationParameters());
        cmpConfiguration.setExtractUsernameComponent(alias, this.cmpDto.getExtractUsernameComponent());
        cmpConfiguration.setVendorMode(alias, this.cmpDto.isVendorMode());
        cmpConfiguration.setVendorCaIds(alias, this.cmpDto.getVendorCaIds());
        cmpConfiguration.setResponseCaPubsCA(alias, this.cmpDto.getResponseCaPubsCA());
        cmpConfiguration.setResponseExtraCertsCA(alias, this.cmpDto.getResponseExtraCertsCA());
        cmpConfiguration.setResponseCaPubsIssuingCA(alias, this.cmpDto.isResponseCaPubsIssuingCA());
        cmpConfiguration.setAllowRAVerifyPOPO(alias, this.cmpDto.isAllowRAVerifyPOPO());
        cmpConfiguration.setRANameGenScheme(alias, this.cmpDto.getRaNameGenScheme());
        cmpConfiguration.setRANameGenParams(alias, this.cmpDto.getRaNameGenParams());
        cmpConfiguration.setRANameGenPrefix(alias, this.cmpDto.getRaNameGenPrefix());
        cmpConfiguration.setRANameGenPostfix(alias, this.cmpDto.getRaNameGenPostfix());
        cmpConfiguration.setRAPwdGenParams(alias, this.cmpDto.getRaPwdGenParams());
        cmpConfiguration.setAllowRACustomSerno(alias, this.cmpDto.isAllowRACustomSerno());
        cmpConfiguration.setRAEEProfile(alias, this.cmpDto.getRaEEProfile());
        cmpConfiguration.setRACertProfile(alias, this.cmpDto.getRaCertProfile());
        cmpConfiguration.setRACAName(alias, this.cmpDto.getRaCAName());
        cmpConfiguration.setRACertPath(alias, this.cmpDto.getRaCertPath());
        cmpConfiguration.setOmitVerificationsInEEC(alias, this.cmpDto.isOmitVerificationsInEEC());
        cmpConfiguration.setKurAllowAutomaticUpdate(alias, this.cmpDto.isKurAllowAutomaticUpdate());
        cmpConfiguration.setAllowServerGeneratedKeys(alias, this.cmpDto.isAllowServerGeneratedKeys());
        cmpConfiguration.setKurAllowSameKey(alias, this.cmpDto.isKurAllowSameKey());
        cmpConfiguration.setCertReqHandlerClass(alias, this.cmpDto.getCertReqHandlerClass());
        cmpConfiguration.setUseExtendedValidation(alias, this.cmpDto.isUseExtendedValidation());
    }

    public boolean renameOrAddAlias() throws AuthorizationDeniedException {

        String oldAlias = getSelectedCmpAlias();
        String newAlias = getCmpDto().getAlias();

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

        if (cmpConfigMBean.getCmpConfig().aliasExists(newAlias)) {
            addErrorMessage("ESTCOULDNOTRENAMEORCLONE");
            return false;
        }

        if (StringUtils.isEmpty(oldAlias)) {
            getEjbcaWebBean().addCmpAlias(newAlias);
        } else {
            getEjbcaWebBean().renameCmpAlias(oldAlias, newAlias);
        }

        getCmpDto().setAlias(newAlias);
        getEjbcaWebBean().clearCmpConfigClone();
        getEjbcaWebBean().reloadCmpConfiguration();
        return true;
    }

    public String save() throws AuthorizationDeniedException {
        if (!renameOrAddAlias()) {
            return null;
        }

        if (UsernameGenerateMode.RANDOM.name().equals(getCmpDto().getRaNameGenScheme()) ||
                UsernameGenerateMode.USERNAME.name().equals(getCmpDto().getRaNameGenScheme())) {
            getCmpDto().setRaNameGenParams("");
        }

        setAuthParameters();
        updateCmpConfiguration();

        getEjbcaWebBean().updateCmpConfigFromClone(getSelectedCmpAlias());
        getEjbcaWebBean().reloadCmpConfiguration();
        return "done";
    }

    public String cancel() {
        return "done";
    }

    public void actionAddRaNameSchemeDnPart() {
        String currentNameGenParam = getCmpDto().getRaNameGenParams();
        String[] params = currentNameGenParam == null ? new String[0] : currentNameGenParam.split(";");
        // Verify that current param is instance of DN fields
        if ((params.length > 0) && (dnfields.contains(params[0]))) {
            if (!ArrayUtils.contains(params, getSelectedRaNameSchemeDnPart())) {
                currentNameGenParam += ";" + getSelectedRaNameSchemeDnPart();
            }
        } else {
            currentNameGenParam = getSelectedRaNameSchemeDnPart();
        }
        getCmpDto().setRaNameGenParams(currentNameGenParam);
    }

    public void actionRemoveRaNameSchemeDnPart() {
        String currentNameGenParam = getCmpDto().getRaNameGenParams();
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
            getCmpDto().setRaNameGenParams(currentNameGenParam);
        }
    }

    /**
     * CMP Authentication Modules
     **/

    // The authentication module is different from all other fields in this page.
    // Due to legacy design, all of the has to be set at once, rather than
    // using getters & setters, in order to not overwrite value for other fields.
    private void setAuthParameters() {
        ArrayList<String> authModules = new ArrayList<>();
        ArrayList<String> authParams = new ArrayList<>();

        if (hmacSelected && hmacSharedSecret) {
            authModules.add(CmpConfiguration.AUTHMODULE_HMAC);
            authParams.add("-");
        } else if (hmacSelected && !hmacSharedSecret) {
            authModules.add(CmpConfiguration.AUTHMODULE_HMAC);
            // If the client secret was not changed from the placeholder value in the UI, set the old value, i.e. no change
            String currentHmacAuthParam = getAuthenticationParameter(CmpConfiguration.AUTHMODULE_HMAC);
            if (!hmacParam.equals(EditCmpConfigMBean.HIDDEN_PWD)) {
                authParams.add(hmacParam);
            } else {
                authParams.add(currentHmacAuthParam);
            }
        }

        if (!getCmpDto().isRaMode() && eeCertSelected) {
            authModules.add(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
            authParams.add("-");
        } else if (getCmpDto().isRaMode() && eeCertSelected && !cmpDto.getResponseProtection().equals(PBE_MODE)) {
            authModules.add(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
            authParams.add(selectedIssuerCa);
        }

        if (regTokenPwdSelected && !getCmpDto().isRaMode()) {
            authModules.add(CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD);
            authParams.add("-");
        }

        if (!getCmpDto().isRaMode() && dnPartPwdSelected) {
            authModules.add(CmpConfiguration.AUTHMODULE_DN_PART_PWD);
            authParams.add(selectedDnField);
        }

        if (!authModules.isEmpty()) {
            getCmpDto().setAuthenticationModule(StringUtils.join(authModules, ";"));
            getCmpDto().setAuthenticationParameters(StringUtils.join(authParams, ";"));
        }
    }

    public List<SelectItem> getCaNameSelectItems() {
        return caNameToIdMap.keySet().stream()
                .map(SelectItem::new)
                .collect(Collectors.toList());
    }

    public List<SelectItem> getCertConfirmCaSelectItems() {
        return Stream.concat(
                        Stream.of(new SelectItem(getEjbcaWebBean().getText("CMPDEFAULTCA_DISABLED"))),
                        getCaNameSelectItems().stream())
                .collect(Collectors.toList());
    }

    public List<SelectItem> getDnFieldSelectItems() {
        return dnfields.stream()
                .map(SelectItem::new)
                .collect(Collectors.toList());
    }

    public List<SelectItem> getExtUsernameComponentSelectItems() {
        return Stream.concat(
                        Stream.of(new SelectItem("DN")),
                        getDnFieldSelectItems().stream())
                .collect(Collectors.toList());
    }

    public List<SelectItem> getVendorCaSelectItems() {
        return caIdToNameMap.values().stream()
                .map(SelectItem::new)
                .collect(Collectors.toList());
    }

    public List<SelectItem> getRaEeProfileSelectItems() {
        return getEjbcaWebBean().getAuthorizedEEProfileNamesAndIds(AccessRulesConstants.CREATE_END_ENTITY).entrySet().stream()
                .map(entry -> new SelectItem(entry.getValue(), entry.getKey()))
                .collect(Collectors.toList());
    }

    public List<SelectItem> getRaCertProfileSelectItems() {
        return Stream.concat(
                Stream.of(new SelectItem(CmpConfiguration.PROFILE_DEFAULT)),
                getEjbcaWebBean().getAvailableCertProfilesOfEEProfile(getCmpDto().getRaEEProfile()).stream()
                        .map(SelectItem::new)
        ).collect(Collectors.toList());
    }

    public List<SelectItem> getRaCaSelectItems() throws CADoesntExistsException, AuthorizationDeniedException {
        return Stream.concat(
                Stream.of(new SelectItem(CmpConfiguration.PROFILE_DEFAULT)),
                getEjbcaWebBean().getAvailableCAsOfEEProfile(getCmpDto().getRaEEProfile()).stream()
                        .map(SelectItem::new)
        ).collect(Collectors.toList());
    }

    public List<SelectItem> getCmpResponseProtectionSelectItems() {
        return CmpConfiguration.getCmpResponseProtectionList(getCmpDto().isRaMode()).stream()
                .map(SelectItem::new)
                .collect(Collectors.toList());
    }

    public List<SelectItem> getAdditionalCaCertSelectItems() {
        return caNameToIdMap.entrySet().stream()
                .map(entry -> new SelectItem(entry.getValue(), entry.getKey()))
                .collect(Collectors.toList());
    }

    public CmpConfigMBean getCmpConfigMBean() {
        return cmpConfigMBean;
    }

    public void setCmpConfigMBean(CmpConfigMBean cmpConfigBean) {
        this.cmpConfigMBean = cmpConfigBean;
    }

    public String getSelectedCmpAlias() {
        return cmpConfigMBean.getSelectedCmpAlias();
    }

    public boolean isViewOnly() {
        return cmpConfigMBean.isViewOnly();
    }

    public void setHmacSelected(final boolean hmacSelected) {
        this.hmacSelected = hmacSelected;
    }

    public boolean isHmacSelected() {
        return hmacSelected;
    }

    public void setHmacSecret(final String hmacSecret) {
        this.hmacParam = hmacSecret;
    }

    public String getHmacSecret() {
        return hmacParam;
    }

    public void setHmacSecretMode(final String mode) {
        hmacSharedSecret = mode.equals("shared");
    }

    public String getHmacSecretMode() {
        if (hmacSharedSecret) {
            return "shared";
        }
        return "specified";
    }

    public boolean isHmacSecretShared() {
        return hmacSharedSecret;
    }

    public boolean isEeCertSelected() {
        return eeCertSelected;
    }

    public void setEeCertSelected(boolean eeCertSelected) {
        this.eeCertSelected = eeCertSelected;
    }

    public String getSelectedIssuerCa() {
        return StringUtils.isEmpty(selectedIssuerCa)
                ? String.valueOf(getCaNameSelectItems().get(0).getValue())
                : selectedIssuerCa;
    }

    public void setSelectedIssuerCa(final String selectedIssuerCa) {
        this.selectedIssuerCa = selectedIssuerCa;
    }

    public void setRegTokenPwdSelected(final boolean regTokenPwdSelected) {
        this.regTokenPwdSelected = regTokenPwdSelected;
    }

    public boolean isRegTokenPwdSelected() {
        return regTokenPwdSelected;
    }

    public void setDnPartPwdSelected(final boolean dnPartPwdSelected) {
        this.dnPartPwdSelected = dnPartPwdSelected;
    }

    public boolean isDnPartPwdSelected() {
        return dnPartPwdSelected;
    }

    public String getSelectedDnField() {
        return StringUtils.isEmpty(selectedDnField)
                ? String.valueOf(getDnFieldSelectItems().get(0).getValue())
                : selectedDnField;
    }

    public void setSelectedDnField(final String selectedDnField) {
        this.selectedDnField = selectedDnField;
    }

    /**
     * @param mode 'client' or 'ra'
     */
    public void setOperationalMode(final String mode) {
        if (CmpConfiguration.RA_MODE.equals(mode)) {
            getCmpDto().setRaMode(true);
        } else {
            getCmpDto().setRaMode(false);
            setResponseProtection("signature");
        }
    }

    public String getOperationalMode() {
        return CmpConfiguration.getOperationalMode(getCmpDto().isRaMode());
    }

    public boolean isCaSharedSecret() {
        return getHmacSecretMode().equals("shared");
    }

    public String getSelectedUsernameComponent() {
        String current = getCmpDto().getExtractUsernameComponent();
        return StringUtils.isEmpty(current)
                ? String.valueOf(getExtUsernameComponentSelectItems().get(0).getValue())
                : current;
    }

    public void setSelectedUsernameComponent(final String selectedUsernameComponent) {
        getCmpDto().setExtractUsernameComponent(selectedUsernameComponent);
    }

    public String getVendorCa() {
        final String vendorCas = getCmpDto().getVendorCaIds();
        if (StringUtils.isEmpty(vendorCas)) {
            return "";
        }
        final String[] vendorCaIds = vendorCas.split(";");
        final ArrayList<String> vendorCaNames = new ArrayList<>();
        for (String caId : vendorCaIds) {
            String caName = caIdToNameMap.get(Integer.parseInt(caId));
            vendorCaNames.add(caName);
        }
        return StringUtils.join(vendorCaNames, ";");
    }

    public void setSelectedVendorCa(final String selectedVendorCa) {
        this.selectedVendorCa = selectedVendorCa;
    }

    public String getSelectedVendorCa() {
        if (selectedVendorCa != null) {
            return selectedVendorCa;
        } else if (!getVendorCaSelectItems().isEmpty()) {
            return String.valueOf(getVendorCaSelectItems().get(0).getValue());
        } else {
            return null;
        }
    }

    public void actionAddVendorCa() {
        final String currentVendorCas = getCmpDto().getVendorCaIds();
        List<String> currentVendorCaList = new ArrayList<>();
        if (StringUtils.isNotBlank(currentVendorCas)) {
            currentVendorCaList = new ArrayList<>(Arrays.asList(currentVendorCas.split(";")));
        }
        final Integer selectedVendorCaId = caNameToIdMap.get(getSelectedVendorCa());
        if (!currentVendorCaList.contains(selectedVendorCaId.toString())) {
            currentVendorCaList.add(selectedVendorCaId.toString());
        }
        getCmpDto().setVendorCaIds(StringUtils.join(currentVendorCaList, ";"));
    }

    public void actionRemoveVendorCa() {
        final String currentVendorCas = getCmpDto().getVendorCaIds();
        if (StringUtils.isNotBlank(currentVendorCas)) {
            final List<String> currentVendorCaList = new ArrayList<>(Arrays.asList(currentVendorCas.split(";")));
            final Integer selectedVendorCaId = caNameToIdMap.get(getSelectedVendorCa());
            if (currentVendorCaList.remove(selectedVendorCaId.toString())) {
                getCmpDto().setVendorCaIds(StringUtils.join(currentVendorCaList, ";"));
            }
        }
    }

    public void actionAddCmpResponseAdditionalCaCert() {
        final String responseCaPubsCaList = getCmpDto().getResponseCaPubsCA();
        List<String> newResponseCaPubsCaList = new ArrayList<>();
        if (StringUtils.isNotBlank(responseCaPubsCaList)) {
            newResponseCaPubsCaList = new ArrayList<>(Arrays.asList(responseCaPubsCaList.split(";")));
        }
        if (!newResponseCaPubsCaList.contains(getSelectedCmpResponseAdditionalCaCert())) {
            newResponseCaPubsCaList.add(getSelectedCmpResponseAdditionalCaCert());
        }
        getCmpDto().setResponseCaPubsCA(StringUtils.join(newResponseCaPubsCaList, ";"));
    }

    public void actionRemoveCmpResponseAdditionalCaCert() {
        final String responseCaPubsCaList = getCmpDto().getResponseCaPubsCA();
        if (StringUtils.isNotBlank(responseCaPubsCaList)) {
            final List<String> list = new ArrayList<>(Arrays.asList(responseCaPubsCaList.split(";")));
            if (list.remove(getSelectedCmpResponseAdditionalCaCert())) {
                getCmpDto().setResponseCaPubsCA(StringUtils.join(list, ";"));
            }
        }
    }

    public void actionAddPkiResponseAdditionalCaCert() {
        final String cas = getCmpDto().getResponseExtraCertsCA();
        List<String> list = new ArrayList<>();
        if (StringUtils.isNotBlank(cas)) {
            list = new ArrayList<>(Arrays.asList(cas.split(";")));
        }
        if (!list.contains(getSelectedPkiResponseAdditionalCaCert())) {
            list.add(getSelectedPkiResponseAdditionalCaCert());
        }
        getCmpDto().setResponseExtraCertsCA(StringUtils.join(list, ";"));
    }

    public void actionRemovePkiResponseAdditionalCaCert() {
        final String cas = getCmpDto().getResponseExtraCertsCA();
        if (StringUtils.isNotBlank(cas)) {
            final List<String> list = new ArrayList<>(Arrays.asList(cas.split(";")));
            if (list.remove(getSelectedPkiResponseAdditionalCaCert())) {
                getCmpDto().setResponseExtraCertsCA(StringUtils.join(list, ";"));
            }
        }
    }


    public List<SelectItem> getAvailableRaNameGenSchemes() {
        return Arrays.stream(UsernameGenerateMode.values())
                .map(UsernameGenerateMode::name)
                .map(SelectItem::new).collect(Collectors.toList());
    }

    public String getSelectedRaNameSchemeDnPart() {
        return selectedRaNameSchemeDnPart == null ? dnfields.get(0) : selectedRaNameSchemeDnPart;
    }

    public void setSelectedRaNameSchemeDnPart(final String selectedRaNameSchemeDnPart) {
        this.selectedRaNameSchemeDnPart = selectedRaNameSchemeDnPart;
    }

    public void setResponseProtection(final String mode) {
        if (PBE_MODE.equals(mode)) {
            hmacSelected = true;
            eeCertSelected = false;
            selectedIssuerCa = "";
        }
        getCmpDto().setResponseProtection(mode);
    }

    public String getResponseProtection() {
        return getCmpDto().getResponseProtection();
    }

    public void setSelectedCmpResponseAdditionalCaCert(final String selectedCmpResponseAdditionalCaCert) {
        this.selectedCmpResponseAdditionalCaCert = selectedCmpResponseAdditionalCaCert;
    }

    public String getSelectedCmpResponseAdditionalCaCert() {
        return selectedCmpResponseAdditionalCaCert == null
                ?
                String.valueOf(getAdditionalCaCertSelectItems().get(0).getValue())
                : selectedCmpResponseAdditionalCaCert;
    }

    public String getSelectedCmpResponseAdditionalCaCertList() throws NumberFormatException, AuthorizationDeniedException {
        final String responseCaPubsCaList = getCmpDto().getResponseCaPubsCA();
        return getEjbcaWebBean().getCaNamesString(responseCaPubsCaList);
    }

    public void setSelectedPkiResponseAdditionalCaCert(final String selectedPkiResponseAdditionalCaCert) {
        this.selectedPkiResponseAdditionalCaCert = selectedPkiResponseAdditionalCaCert;
    }

    public String getSelectedPkiResponseAdditionalCaCert() {
        return selectedPkiResponseAdditionalCaCert == null
                ?
                String.valueOf(getAdditionalCaCertSelectItems().get(0).getValue())
                : selectedPkiResponseAdditionalCaCert;
    }

    public String getSelectedPkiResponseAdditionalCaCertList() throws AuthorizationDeniedException {
        final String responseCaExtraCertsCaList = getCmpDto().getResponseExtraCertsCA();
        return getEjbcaWebBean().getCaNamesString(responseCaExtraCertsCaList);
    }

    public String getResponseConfigDefaultCa() {
        String current = getCmpDto().getCMPDefaultCA();
        for (String caName : caNameToIdMap.keySet()) {
            if (caSession.getCaSubjectDn(caName).equals(current)) {
                return caName;
            }
        }
        return getEjbcaWebBean().getText("CMPDEFAULTCA_DISABLED");
    }

    public void setResponseConfigDefaultCa(final String ca) {
        if (ca.equals(getEjbcaWebBean().getText("CMPDEFAULTCA_DISABLED")) || StringUtils.isEmpty(ca)) {
            getCmpDto().setCMPDefaultCA("");
        } else {
            getCmpDto().setCMPDefaultCA(caSession.getCaSubjectDn(ca));
        }
    }

    public boolean isShowExtendedConfiguration() {
        return getEjbcaWebBean().isRunningEnterprise();
    }
}
