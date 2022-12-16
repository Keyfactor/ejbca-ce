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

package org.ejbca.ui.web.admin.keys.validation;

import java.io.Serializable;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.component.html.HtmlPanelGrid;
import javax.faces.component.html.HtmlSelectOneMenu;
import javax.faces.context.FacesContext;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;
import javax.faces.validator.ValidatorException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.validation.ExternalCommandCertificateValidator;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.KeyValidationFailedActions;
import org.cesecore.keys.validation.KeyValidatorBase;
import org.cesecore.keys.validation.KeyValidatorDateConditions;
import org.cesecore.keys.validation.KeyValidatorDoesntExistsException;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.keys.validation.KeyValidatorSettingsTemplate;
import org.cesecore.keys.validation.PhasedValidator;
import org.cesecore.keys.validation.Validator;
import org.cesecore.keys.validation.ValidatorBase;
import org.cesecore.keys.validation.ValidatorFactory;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiModelAware;
import org.cesecore.util.ui.DynamicUiModelException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.psm.jsf.JsfDynamicUiPsmFactory;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JSF MBean backing the edit key validators page.
 *
 */
// Declarations in faces-config.xml
//@javax.faces.bean.ViewScoped
//@javax.faces.bean.ManagedBean(name="validatorBean")
public class ValidatorBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = -2889613238729145716L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(ValidatorBean.class);

    @EJB
    private GlobalConfigurationSessionLocal configurationSession;

    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;

    @EJB
    private KeyValidatorSessionLocal keyValidatorSession;

    // Declarations in faces-config.xml
    // @javax.faces.bean.ManagedProperty(value="#{validatorsBean}")
    private ValidatorsBean validatorsBean;

    public ValidatorBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.VALIDATORVIEW.resource());
    }
    
    /** The validators ID. */
    private int validatorId;
    
    private String validatorName = "";
    
    //As a default type, use the first on the list
    private String validatorType = getSortedListOfValidators().get(0).getValidatorTypeIdentifier();
    
    /** Map contains a potential validator of each type, so that we don't lose values when we switch. */
    private Map<String, Validator> stagedValidators = new HashMap<>();

    /** Dynamic UI PIM component. */
    private DynamicUiModel uiModel;

    /** Dynamic UI PSM component. */
    private HtmlPanelGrid dataGrid;

    /**
     * Resets the dynamic UI properties PSM.
     */
    private void reset() {
        setValidatorId(-1);
    }
    
    /**
     * Checks if the administrator is authorized the edit key validators.
     * 
     * @return true if the administrator is authorized.
     */
    public boolean hasEditRights() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_EDITVALIDATOR);
    }

    /**
     * Gets the ValidatorsBean reference.
     * @return the ValidatorsBean.
     */
    public ValidatorsBean getValidatorsBean() {
        return validatorsBean;
    }

    /**
     * Sets the ValidatorsBean reference.
     * @param bean
     */
    public void setValidatorsBean(final ValidatorsBean bean) {
        this.validatorsBean = bean;
    }

    /**
     * Processes the key validation type changed event and renders the concrete validator view. 
     * 
     * @param e the event.
     * @throws DynamicUiModelException if the PSM could not be initialized.
     */
    public void validatorTypeChanged(final AjaxBehaviorEvent e) throws DynamicUiModelException {
        setValidatorType((String) ((HtmlSelectOneMenu) e.getComponent()).getValue());
        FacesContext.getCurrentInstance().renderResponse();
    }
    
    public String getValidatorType() {
        final Validator v = getValidator();
        return v == null ? null : v.getValidatorTypeIdentifier();
    }
  
    /**˛
     * Sets the selected validator type. This re-creates the entire validator, so only do it if it actually changed type.
     * @param type the type {@link ValidatorBase#getValidatorTypeIdentifier()}.
     */
    public void setValidatorType(final String type) {
       
        if (!this.validatorType.equals(type)) {
            Validator validator;
            //If we changed type, check if this one has been used before in the current view. If not, create one. 
            if(stagedValidators.containsKey(type)) {
                validator = stagedValidators.get(type);
            } else {
                validator = ValidatorFactory.INSTANCE.getArcheType(type);
                stagedValidators.put(validatorType, validator);
            }           
            initializeDynamicUI(validator);
        }
       
    }
    /**
     * Processes the issuance phase changed event and renders the concrete validator view. 
     * 
     * @param e the event.
     * @throws DynamicUiModelException if the PSM could not be initialized.
     */
    public void validatorPhaseChanged(final AjaxBehaviorEvent e) throws DynamicUiModelException {
        setIssuancePhase((int) ((HtmlSelectOneMenu) e.getComponent()).getValue());
        FacesContext.getCurrentInstance().renderResponse();
    }

    public int getIssuancePhase() {
        final Validator v = getValidator();
        // Default to DATA_VALIDATION is the session is screwed up
        return v == null ? IssuancePhase.DATA_VALIDATION.getIndex() : v.getPhase();
    }

    public void setIssuancePhase(final int issuancePhase) {
        if (issuancePhase != getValidator().getPhase()) {
            getValidator().setPhase(issuancePhase);
            if (getValidator().getFailedAction() == KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex() && isApprovalRequestPhase()) {
                getValidator().setFailedAction(KeyValidationFailedActions.LOG_INFO.getIndex());
            }
            if (getValidator().getNotApplicableAction() == KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex() && isApprovalRequestPhase()) {
                getValidator().setNotApplicableAction(KeyValidationFailedActions.LOG_INFO.getIndex());
            }
        }
    }

    /**
     * Gets the selected validator.
     * @return the Validator or null if no validator is selected.
     */
    public Validator getValidator() {
        //if ID is something other than -1, then we're editing an existing validator, otherwise creating one. 
        final int identifier = (validatorsBean.getValidatorId() != null ? validatorsBean.getValidatorId() : -1);
        setValidatorId(identifier);

        Validator validator;
        if (identifier != -1) {
            validator = keyValidatorSession.getValidator(identifier);
            this.validatorType = validator.getValidatorTypeIdentifier();
        } else {
            //Otherwise, let's create a brand new one with the default type
            validator = ValidatorFactory.INSTANCE.getArcheType(this.validatorType);
        }
        initializeDynamicUI(validator);
        
        // Set the staging map with this validator type. The staging map allows us to store several potential 
        // validators, making sure that we can retain values while flipping through types. Just don't overwrite
        // if it's already staged
        if (!stagedValidators.containsKey(validator.getValidatorTypeIdentifier())) {
            stagedValidators.put(validator.getValidatorTypeIdentifier(), validator);
        }
        
        return validator;
     }
    
    private void initializeDynamicUI(final Validator validator) {
     // (Re-)initialize dynamic UI PSM.
        if (validator instanceof DynamicUiModelAware) {
            if (uiModel == null || !uiModel.equals(((DynamicUiModelAware) validator).getDynamicUiModel())) {
                ((DynamicUiModelAware) validator).initDynamicUiModel();
                uiModel = ((DynamicUiModelAware) validator).getDynamicUiModel();
                if (log.isDebugEnabled()) {
                    log.debug("Request dynamic UI properties for validator with (id=" + validator.getProfileId() + ") with properties " + validator.getFilteredDataMapForLogging());
                }
                try {
                    initGrid(uiModel, validator.getClass().getSimpleName());
                } catch (DynamicUiModelException e) {
                    log.warn("Could not initialize dynamic UI PSM: " + e.getMessage(), e);
                }
            }
        }
    }

     /**
      * Gets the validators ID.
      * @return the ID in String format
      */
    public String getValidatorId() {
        return (validatorId != -1 ? String.valueOf(validatorId) : "ID will be assigned on clicking Save");
    }

    /**
     * Sets the validators ID.
     * @param validatorId the ID.
     */
    public void setValidatorId(int validatorId) {
        this.validatorId = validatorId;
    }
    
    public String getValidatorName() {
        return validatorName;
    }  
    
    public void setValidatorName(final String validatorName) {
        this.validatorName = validatorName;
    }

    /**
     * Gets the dynamic UI properties PSM component as HTML data grid.
     * @return the data grid.
     * @throws DynamicUiModelException if the PSM could not be initialized.
     */
    public HtmlPanelGrid getDataGrid() throws DynamicUiModelException {
        return dataGrid;
    }

    /**
     * Sets the dynamic UI properties PSM component as HTML data grid.
     * @param dataGrid the data grid.
     */
    public void setDataGrid(final HtmlPanelGrid dataGrid) {
        this.dataGrid = dataGrid;
    }
    
    /**
     * Initializes the dynamic UI model grid panel.
     * @param pim the PIM.
     * @param prefix the HTML components ID prefix.
     * @throws DynamicUiModelException if the PSM could not be created.
     */
    private void initGrid(final DynamicUiModel pim, final String prefix) throws DynamicUiModelException {
        if (dataGrid == null) {
            dataGrid = new HtmlPanelGrid();
            dataGrid.setId(getClass().getSimpleName()+"-dataGrid");
        }
        uiModel.setDisabled(validatorsBean.getViewOnly());
        JsfDynamicUiPsmFactory.initGridInstance(dataGrid, pim, prefix);
    }

    /**
     * Checks whether the Validator settings template is set to "Use custom settings".
     * @return true if custom settings are enabled
     */
    public boolean isCustomBaseSettingsEnabled() {
        return KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption() == getValidator().getSettingsTemplate();
    }

    /**
     * Gets the available key validator types.
     *
     * @return List of the available key validator types
     */
    public List<SelectItem> getAvailableValidators() {      
        final List<SelectItem> ret = new ArrayList<>();
        for (final Validator validator : getSortedListOfValidators()) {
            ret.add(new SelectItem(validator.getValidatorTypeIdentifier(), validator.getLabel()));
        }
        return ret;
    }
    
    private List<Validator> getSortedListOfValidators() {
        final List<Class<?>> excludeClasses = new ArrayList<>();
        if (!((GlobalConfiguration) configurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableExternalScripts()) {
            excludeClasses.add(ExternalCommandCertificateValidator.class);
        }
        List<Validator> result = ValidatorFactory.INSTANCE.getAllImplementations(excludeClasses);
        result.sort( new Comparator<Validator>() {
            @Override
            public int compare(Validator o1, Validator o2) {
                return o1.getLabel().compareToIgnoreCase(o2.getLabel());
            }
        });
        return result;
    }

    /**
     * Gets a list of select items of the available base parameter options.
     * @return the list.
     */
    public List<SelectItem> getAvailableValidatorSettingsTemplates() {
        final List<SelectItem> result = new ArrayList<>();
        final KeyValidatorSettingsTemplate[] items = KeyValidatorSettingsTemplate.values();
        for (int i = 0, j = items.length; i < j; i++) {
            result.add(new SelectItem(items[i].getOption(), getEjbcaWebBean().getText(items[i].getLabel())));
        }
        return result;
    }

    /**
     * Gets a list of select items of the certificate issuance process phases (see {@link IssuancePhase}).
     * @return the list.
     */
    public List<SelectItem> getAllApplicablePhases() {
        final List<SelectItem> result = new ArrayList<>();
        final IssuancePhase[] items = IssuancePhase.values();
        for(IssuancePhase phase : items) {
            result.add(new SelectItem(phase.getIndex(), getEjbcaWebBean().getText(phase.getLabel())));
        }
        return result;
    }

    /**
     * Gets a list of select items of the certificate issuance process phases (see {@link IssuancePhase}).
     * @return the list.
     */
    public List<SelectItem> getApplicablePhases() {
        final List<SelectItem> result = new ArrayList<>();
        final Validator v = getValidator();
        if (v != null) {
            for (Integer index : ((PhasedValidator) v).getApplicablePhases()) {
                result.add(new SelectItem(index, getEjbcaWebBean().getText(IssuancePhase.fromIndex(index).getLabel())));
            }
        }
        return result;
    }

    /**
     * Validates the description field, see {@link ValidatorBase#getDescription()}.
     * @param context the faces context.
     * @param component the events source component
     * @param value the source components value attribute
     * @throws ValidatorException if the validation fails.
     */
    public void validateDescription(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        final String descripion = (String) value;
        if (StringUtils.isNotBlank(descripion) && descripion.trim().length() > 256) {
            final String message = "Description must not contain more than 256 characters.";
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
        }
    }

    /**
     * Validates the BaseKeyValildator notBefore field, see {@link org.cesecore.keys.validation.ValidityAwareValidator#getNotBefore()}.
     * @param context the faces context.
     * @param component the events source component
     * @param value the source components value attribute
     * @throws ValidatorException if the validation fails.
     */
    public void validateNotBefore(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        final String string = (String) value;
        try {
            if (StringUtils.isNotBlank(string) && null == KeyValidatorBase.parseDate(string)) {
                final String message = "Key validator not before must be a valid ISO 8601 date or time " + value;
                throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
            }
        } catch (ParseException e) {
            log.debug("Could not parse Date: " + string);
        }
    }

    /**
     * Validates the BaseKeyValildator notBefore condition field, see {@link org.cesecore.keys.validation.ValidityAwareValidator#getNotBeforeCondition()}.
     * @param context the faces context.
     * @param component the events source component
     * @param value the source components value attribute
     * @throws ValidatorException if the validation fails.
     */
    public void validateNotBeforeCondition(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        final Integer type = (Integer) value;
        if (!KeyValidatorDateConditions.index().contains(type)) {
            final String message = "Key validator not before condition must be on of " + KeyValidatorDateConditions.index();
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
        }
    }

    /**
     * Validates the BaseKeyValildator notAfter field, see {@link org.cesecore.keys.validation.ValidityAwareValidator#getNotAfter()}.
     * @param context the faces context.
     * @param component the events source component
     * @param value the source components value attribute
     * @throws ValidatorException if the validation fails.
     */
    public void validateNotAfter(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        final String string = (String) value;
        try {
            if (StringUtils.isNotBlank(string) && null == KeyValidatorBase.parseDate((String) value)) {
                final String message = "Key validator not after must be a valid ISO 8601 date or time " + value;
                throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
            }
        } catch (ParseException e) {
            log.debug("Could not parse Date: " + string);
        }
    }

    /**
     * Validates the BaseKeyValildator notAfter condition field, see {@link org.cesecore.keys.validation.ValidityAwareValidator#getNotAfterCondition()}.
     * @param context the faces context.
     * @param component the events source component
     * @param value the source components value attribute
     * @throws ValidatorException if the validation fails.
     */
    public void validateNotAfterCondition(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        final Integer index = (Integer) value;
        if (!KeyValidatorDateConditions.index().contains(index)) {
            final String message = "Key validator not after condition must be on of " + KeyValidatorDateConditions.index();
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
        }
    }

    /**
     * Validates the BaseKeyValildator failedAction field, see {@link ValidatorBase#getFailedAction()}.
     * @param context the faces context.
     * @param component the events source component
     * @param value the source components value attribute
     * @throws ValidatorException if the validation fails.
     */
    public void validateFailedAction(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        final Integer index = (Integer) value;
        if (!KeyValidationFailedActions.index().contains(index)) {
            final String message = "Key validator action must be on of " + KeyValidatorDateConditions.index();
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
        }
    }

    /**
     * Validates the BaseKeyValildator certificateProfileIds field, see {@link ValidatorBase#getCertificateProfileIds()}.
     * @param context the faces context.
     * @param component the events source component
     * @param value the source components value attribute
     * @throws ValidatorException if the validation fails.
     */
    public void validateCertificateProfileIds(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        @SuppressWarnings("unchecked")
        final List<Integer> selectedIds = (List<Integer>) value;
        final List<Integer> ids = new ArrayList<>(certificateProfileSession.getCertificateProfileIdToNameMap().keySet());
        for (int id : selectedIds) {
            if (!ids.contains(id)) {
                final String message = "Key validator certificate profile id must be on of " + ids;
                throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
            }
        }
    }

    /**
     * Cancel action.
     * @return the navigation outcome defined in faces-config.xml.
     */
    public String cancel() {
        reset();
        return "done";
    }

    /**
     * Save action.
     * @return the navigation outcome defined in faces-config.xml.
     */
    public String save() {
        final Validator validator = getValidator();
        if (log.isDebugEnabled()) {
            log.debug("Try to save validator: " + validator);
        }
        try {
            if (validator instanceof DynamicUiModelAware) {
                ((DynamicUiModelAware) validator).getDynamicUiModel().writeProperties(((ValidatorBase) validator).getRawData());
            }
            keyValidatorSession.changeKeyValidator(getAdmin(), validator);
            addInfoMessage("VALIDATORSAVED");
            reset();
            return "done";
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage("Not authorized to edit validator " + validator.getProfileName());
        } catch (KeyValidatorDoesntExistsException e) {
            // NOPMD: ignore do nothing
        } catch (CesecoreException e) {
            if (e.getErrorCode().equals(ErrorCode.DOMAIN_BLACKLIST_FILE_PARSING_FAILED)) {
            addNonTranslatedErrorMessage("Failed to save domain list validator. " + e.getMessage());
            } else {
            addNonTranslatedErrorMessage("An exception occured: " + e.getMessage());
            }
        }
        return StringUtils.EMPTY;
    }

    /**
     * Gets a list of select items of the available certificate profiles.
     * @return the list.
     */
    public List<SelectItem> getAvailableCertificateProfiles() {
        final List<SelectItem> result = new ArrayList<>();
        List<Integer> authorizedCertificateProfiles = certificateProfileSession.getAuthorizedCertificateProfileIds(getAdmin(), CertificateConstants.CERTTYPE_UNKNOWN);
        final Map<Integer, String> map = certificateProfileSession.getCertificateProfileIdToNameMap();
        for(Integer certificateProfileId : authorizedCertificateProfiles) {
            // Don't include fixed certificate profiles in validators, keep it clean and force usage of "real"
            // profiles if you want to issue serious certificates.
            if (certificateProfileId > CertificateProfileConstants.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
                result.add(new SelectItem(certificateProfileId, map.get(certificateProfileId)));
            }
        }
        Collections.sort(result, new Comparator<SelectItem>() {
            @Override
            public int compare(SelectItem o1, SelectItem o2) {
                return o1.getLabel().compareToIgnoreCase(o2.getLabel());
            }
        });
        return result;
    }

    /**
     * Gets the BaseKeyValidator certificateProfileIds field.
     * @return the list
     */
    public List<Integer> getCertificateProfileIds() {
        final Validator v = getValidator();
        return v == null ? new ArrayList<Integer>() : v.getCertificateProfileIds();
    }

    /**
     * Sets the BaseKeyValidator certificateProfileIds field.
     * @param ids the list of certificate profile IDs.
     */
    public void setCertificateProfileIds(List<Integer> ids) {
        getValidator().setCertificateProfileIds(ids);
    }

    /**
     * Gets a list of select items of the available notBefore conditions.
     * @return the list.
     */
    public List<SelectItem> getAvailableNotBeforeConditions() {
        return conditionsToSelectItems();
    }

    /**
     * Gets a list of select items of the available notAfter conditions.
     * @return the list.
     */
    public List<SelectItem> getAvailableNotAfterConditions() {
        return conditionsToSelectItems();
    }

    /**
     * Gets a list of select items of the available failed actions.
     * @return the list.
     */
    public List<SelectItem> getAvailableFailedActions() {
        final List<SelectItem> result = new ArrayList<>();
        final KeyValidationFailedActions[] items = KeyValidationFailedActions.values();
        for (int i = 0, j = items.length; i < j; i++) {
            if (i == KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex() && isApprovalRequestPhase()) {
                continue;
            }
            result.add(new SelectItem(items[i].getIndex(), getEjbcaWebBean().getText(items[i].getLabel())));
        }
        return result;
    }

    private boolean isApprovalRequestPhase() {
        Validator validator = stagedValidators.get(validatorType);
        return validator != null && validator.getPhase() == IssuancePhase.APPROVAL_VALIDATION.getIndex();
    }

    /**
     * Transforms date condition enumerations to a list of select items.
     * @return the list.
     */
    private List<SelectItem> conditionsToSelectItems() {
        final List<SelectItem> result = new ArrayList<>();
        final KeyValidatorDateConditions[] items = KeyValidatorDateConditions.values();
        for (int i = 0, j = items.length; i < j; i++) {
            result.add(new SelectItem(items[i].getIndex(), getEjbcaWebBean().getText(items[i].getLabel())));
        }
        return result;
    }
}