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
        getEjbcaWebBean().clearCmpConfigClone();

        String aliasName = cmpConfigMBean.getSelectedCmpAlias();
        
        if (cmpDto == null) {
            if (StringUtils.isEmpty(aliasName)) {
                this.cmpDto = getDefaultCmpDto();
            } else {
                this.cmpDto = readCmpDtoFromDB(aliasName);
            }
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

    /**
     * Used when there is no alias available such as when creating a new alias), to load the default cmp data
     * @return data class containing default cmp data
     */
    protected CmpDto getDefaultCmpDto() {
        final CmpDto cmpDtoDefault = new CmpDto();
        cmpDtoDefault.setCMPDefaultCA(CmpConfiguration.DEFAULT_DEFAULTCA);
        cmpDtoDefault.setResponseProtection(CmpConfiguration.DEFAULT_RESPONSE_PROTECTION);
        cmpDtoDefault.setRaMode(CmpConfiguration.isRAMode(CmpConfiguration.DEFAULT_OPERATION_MODE));
        cmpDtoDefault.setAuthenticationModule(CmpConfiguration.DEFAULT_CLIENT_AUTHENTICATION_MODULE);
        cmpDtoDefault.setAuthenticationParameters(CmpConfiguration.DEFAULT_CLIENT_AUTHENTICATION_PARAMS);
        cmpDtoDefault.setExtractUsernameComponent(CmpConfiguration.DEFAULT_EXTRACT_USERNAME_COMPONENT);
        cmpDtoDefault.setVendorMode(Boolean.parseBoolean(CmpConfiguration.DEFAULT_VENDOR_MODE));
        cmpDtoDefault.setVendorCaIds(CmpConfiguration.DEFAULT_VENDOR_CA_IDS);
        cmpDtoDefault.setResponseCaPubsCA(CmpConfiguration.DEFAULT_RESPONSE_CAPUBS_CA);
        cmpDtoDefault.setResponseCaPubsIssuingCA(Boolean.parseBoolean(CmpConfiguration.DEFAULT_RESPONSE_CAPUBS_ISSUING_CA));
        cmpDtoDefault.setResponseExtraCertsCA(CmpConfiguration.DEFAULT_RESPONSE_EXTRACERTS_CA);
        cmpDtoDefault.setAllowRAVerifyPOPO(Boolean.parseBoolean(CmpConfiguration.DEFAULT_ALLOW_RA_VERIFY_POPO));
        cmpDtoDefault.setRaNameGenScheme(CmpConfiguration.DEFAULT_RA_USERNAME_GENERATION_SCHEME);
        cmpDtoDefault.setRaNameGenParams(CmpConfiguration.DEFAULT_RA_USERNAME_GENERATION_PARAMS);
        cmpDtoDefault.setRaNameGenPrefix(CmpConfiguration.DEFAULT_RA_USERNAME_GENERATION_PREFIX);
        cmpDtoDefault.setRaNameGenPostfix(CmpConfiguration.DEFAULT_RA_USERNAME_GENERATION_POSTFIX);
        cmpDtoDefault.setRaPwdGenParams(CmpConfiguration.DEFAULT_RA_PASSWORD_GENERARION_PARAMS);
        cmpDtoDefault.setAllowRACustomSerno(Boolean.parseBoolean(CmpConfiguration.DEFAULT_RA_ALLOW_CUSTOM_SERNO));
        cmpDtoDefault.setRaEEProfile(CmpConfiguration.DEFAULT_RA_EEPROFILE);
        cmpDtoDefault.setRaCertProfile(CmpConfiguration.DEFAULT_RA_CERTPROFILE);
        cmpDtoDefault.setRaCAName(CmpConfiguration.DEFAULT_RA_CANAME);
        cmpDtoDefault.setRaCertPath(CmpConfiguration.DEFAULT_RACERT_PATH);
        cmpDtoDefault.setOmitVerificationsInEEC(Boolean.parseBoolean(CmpConfiguration.DEFAULT_RA_OMITVERIFICATIONSINEEC));
        cmpDtoDefault.setKurAllowAutomaticUpdate(Boolean.parseBoolean(CmpConfiguration.DEFAULT_KUR_ALLOW_AUTOMATIC_KEYUPDATE));
        cmpDtoDefault.setAllowServerGeneratedKeys(Boolean.parseBoolean(CmpConfiguration.DEFAULT_ALLOW_SERVERGENERATED_KEYS));
        cmpDtoDefault.setKurAllowSameKey(Boolean.parseBoolean(CmpConfiguration.DEFAULT_KUR_ALLOW_SAME_KEY));
        cmpDtoDefault.setCertReqHandlerClass(CmpConfiguration.DEFAULT_CERTREQHANDLER);
        cmpDtoDefault.setUseExtendedValidation(Boolean.parseBoolean(CmpConfiguration.DEFAULT_EXTENDEDVALIDATION));
        return cmpDtoDefault;
    }


    /**
     * Reads the existing data associated with the given cmp alias from database    
     * @param alias cmp alias to load data from database for
     * @return a data class containing cmp information read from db
     */
    protected CmpDto readCmpDtoFromDB(final String alias) {
        CmpConfiguration cmpConfiguration = getEjbcaWebBean().getCmpConfiguration();
        final CmpDto cmpDTOFromDB = new CmpDto();
        cmpDTOFromDB.setAlias(alias); 
        cmpDTOFromDB.setCMPDefaultCA(cmpConfiguration.getCMPDefaultCA(alias));
        cmpDTOFromDB.setResponseProtection(cmpConfiguration.getResponseProtection(alias));
        cmpDTOFromDB.setRaMode(cmpConfiguration.getRAMode(alias)); 
        cmpDTOFromDB.setAuthenticationModule(cmpConfiguration.getAuthenticationModule(alias));
        cmpDTOFromDB.setAuthenticationParameters(cmpConfiguration.getAuthenticationParameters(alias));
        cmpDTOFromDB.setExtractUsernameComponent(cmpConfiguration.getExtractUsernameComponent(alias));
        cmpDTOFromDB.setVendorMode(cmpConfiguration.getVendorMode(alias));
        cmpDTOFromDB.setVendorCaIds(cmpConfiguration.getVendorCaIds(alias));
        cmpDTOFromDB.setResponseCaPubsCA(cmpConfiguration.getResponseCaPubsCA(alias));
        cmpDTOFromDB.setResponseCaPubsIssuingCA(cmpConfiguration.getResponseCaPubsIssuingCA(alias));
        cmpDTOFromDB.setResponseExtraCertsCA(cmpConfiguration.getResponseExtraCertsCA(alias));
        cmpDTOFromDB.setAllowRAVerifyPOPO(cmpConfiguration.getAllowRAVerifyPOPO(alias));
        cmpDTOFromDB.setRaNameGenScheme(cmpConfiguration.getRANameGenScheme(alias));
        cmpDTOFromDB.setRaNameGenParams(cmpConfiguration.getRANameGenParams(alias));
        cmpDTOFromDB.setRaNameGenPrefix(cmpConfiguration.getRANameGenPrefix(alias));
        cmpDTOFromDB.setRaNameGenPostfix(cmpConfiguration.getRANameGenPostfix(alias));
        cmpDTOFromDB.setRaPwdGenParams(cmpConfiguration.getRAPwdGenParams(alias));
        cmpDTOFromDB.setAllowRACustomSerno(cmpConfiguration.getAllowRACustomSerno(alias));
        cmpDTOFromDB.setRaEEProfile(cmpConfiguration.getRAEEProfile(alias));
        cmpDTOFromDB.setRaCertProfile(cmpConfiguration.getRACertProfile(alias));
        cmpDTOFromDB.setRaCAName(cmpConfiguration.getRACAName(alias));
        cmpDTOFromDB.setRaCertPath(cmpConfiguration.getRACertPath(alias));
        cmpDTOFromDB.setOmitVerificationsInEEC(cmpConfiguration.getOmitVerificationsInEEC(alias));
        cmpDTOFromDB.setKurAllowAutomaticUpdate(cmpConfiguration.getKurAllowAutomaticUpdate(alias));
        cmpDTOFromDB.setAllowServerGeneratedKeys(cmpConfiguration.getAllowServerGeneratedKeys(alias));
        cmpDTOFromDB.setKurAllowSameKey(cmpConfiguration.getKurAllowSameKey(alias));
        cmpDTOFromDB.setCertReqHandlerClass(cmpConfiguration.getCertReqHandlerClass(alias));
        cmpDTOFromDB.setUseExtendedValidation(cmpConfiguration.getUseExtendedValidation(alias));
        return cmpDTOFromDB;
    }

    /**
     * Updates the current cmp alias data, using info given in the UI
     * @param alias that its data need to be updated
     * @param cmpDto the data class containing up to date information from UI
     */
    protected void updateCmpConfiguration(final String alias, final CmpDto cmpDto) {
        CmpConfiguration cmpConfiguration = getEjbcaWebBean().getCmpConfigForEdit(alias);
        cmpConfiguration.setCMPDefaultCA(alias, cmpDto.getCMPDefaultCA());
        cmpConfiguration.setResponseProtection(alias, cmpDto.getResponseProtection());
        cmpConfiguration.setRAMode(alias, cmpDto.isRaMode());
        cmpConfiguration.setAuthenticationModule(alias, cmpDto.getAuthenticationModule());
        cmpConfiguration.setAuthenticationParameters(alias, cmpDto.getAuthenticationParameters());
        cmpConfiguration.setExtractUsernameComponent(alias, cmpDto.getExtractUsernameComponent());
        cmpConfiguration.setVendorMode(alias, cmpDto.isVendorMode());
        cmpConfiguration.setVendorCaIds(alias, cmpDto.getVendorCaIds());
        cmpConfiguration.setResponseCaPubsCA(alias, cmpDto.getResponseCaPubsCA());
        cmpConfiguration.setResponseExtraCertsCA(alias, cmpDto.getResponseExtraCertsCA());
        cmpConfiguration.setResponseCaPubsIssuingCA(alias, cmpDto.isResponseCaPubsIssuingCA());
        cmpConfiguration.setAllowRAVerifyPOPO(alias, cmpDto.isAllowRAVerifyPOPO());
        cmpConfiguration.setRANameGenScheme(alias, cmpDto.getRaNameGenScheme());
        cmpConfiguration.setRANameGenParams(alias, cmpDto.getRaNameGenParams());
        cmpConfiguration.setRANameGenPrefix(alias, cmpDto.getRaNameGenPrefix());
        cmpConfiguration.setRANameGenPostfix(alias, cmpDto.getRaNameGenPostfix());
        cmpConfiguration.setRAPwdGenParams(alias, cmpDto.getRaPwdGenParams());
        cmpConfiguration.setAllowRACustomSerno(alias, cmpDto.isAllowRACustomSerno());
        cmpConfiguration.setRAEEProfile(alias, cmpDto.getRaEEProfile());
        cmpConfiguration.setRACertProfile(alias, cmpDto.getRaCertProfile());
        cmpConfiguration.setRACAName(alias, cmpDto.getRaCAName());
        cmpConfiguration.setRACertPath(alias, cmpDto.getRaCertPath());
        cmpConfiguration.setOmitVerificationsInEEC(alias, cmpDto.isOmitVerificationsInEEC());
        cmpConfiguration.setKurAllowAutomaticUpdate(alias, cmpDto.isKurAllowAutomaticUpdate());
        cmpConfiguration.setAllowServerGeneratedKeys(alias, cmpDto.isAllowServerGeneratedKeys());
        cmpConfiguration.setKurAllowSameKey(alias, cmpDto.isKurAllowSameKey());
        cmpConfiguration.setCertReqHandlerClass(alias, cmpDto.getCertReqHandlerClass());
        cmpConfiguration.setUseExtendedValidation(alias, cmpDto.isUseExtendedValidation());
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

    /**
     * Saves the updated cmp configuration from UI, into the database by calling updateCmpConfigFromClone from EjbcaWebBean class.
     * @return string pointing to the result page (cmp aliases page)
     * @throws AuthorizationDeniedException
     */
    public String save() throws AuthorizationDeniedException {

        if (!renameOrAddAlias()) {
            return null;
        }
        getEjbcaWebBean().clearCmpConfigClone();

        if (UsernameGenerateMode.RANDOM.name().equals(getCmpDto().getRaNameGenScheme())
                || UsernameGenerateMode.USERNAME.name().equals(getCmpDto().getRaNameGenScheme())) {
            getCmpDto().setRaNameGenParams("");
        }

        setAuthParameters();

        final String currentCmpAlias = this.cmpDto.getAlias();

        updateCmpConfiguration(currentCmpAlias, this.cmpDto);
        getEjbcaWebBean().updateCmpConfigFromClone(currentCmpAlias);
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
