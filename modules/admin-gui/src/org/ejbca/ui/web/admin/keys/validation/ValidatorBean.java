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
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.component.html.HtmlSelectOneMenu;
import javax.faces.context.FacesContext;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;
import javax.faces.validator.ValidatorException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.validation.KeyValidationFailedActions;
import org.cesecore.keys.validation.KeyValidatorBase;
import org.cesecore.keys.validation.KeyValidatorDateConditions;
import org.cesecore.keys.validation.KeyValidatorDoesntExistsException;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.keys.validation.KeyValidatorSettingsTemplate;
import org.cesecore.keys.validation.Validator;
import org.cesecore.keys.validation.ValidatorBase;
import org.cesecore.keys.validation.ValidatorFactory;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JSF MBean backing the edit key validators page.
 *  
 * @version $Id$
 */
// Declarations in faces-config.xml
//@javax.faces.bean.SessionScoped
//@javax.faces.bean.ManagedBean(name="validatorBean")
public class ValidatorBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = -2889613238729145716L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(ValidatorBean.class);

    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;

    @EJB
    private KeyValidatorSessionLocal keyValidatorSession;

    // Declarations in faces-config.xml
    // @javax.faces.bean.ManagedProperty(value="#{certProfilesBean}")
    private ValidatorsBean validatorsBean;

    /** Selected key validator id.*/
    private int currentValidatorId = -1;
    
    /** Selected key validator. */
    private Validator validator = null;

    /** Since this MBean is session scoped we need to reset all the values when needed. */
    private void reset() {
        currentValidatorId = -1;
        validator = null;
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
     * Gets the selected key validator id.
     * @return the id.
     */
    public Integer getSelectedKeyValidatorId() {
        return validatorsBean.getSelectedKeyValidatorId();
    }

    /**
     * Gets the selected key validator name.
     * @return the name.
     */
    public String getSelectedKeyValidatorName() {
        return keyValidatorSession.getKeyValidatorName(getSelectedKeyValidatorId());
    }

    /**
     * Gets the selected validator.
     * @return the  validator.
     */
    public Validator getValidator() {
        if (currentValidatorId != -1 && validator != null && getSelectedKeyValidatorId().intValue() != currentValidatorId) {
            reset();
        }
        if (validator == null) {
            if (log.isDebugEnabled()) {
                log.debug("Request validator with id " + getSelectedKeyValidatorId());
            }
            currentValidatorId = getSelectedKeyValidatorId().intValue();
            validator = keyValidatorSession.getValidator(currentValidatorId);
        }
        return validator;
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
     * Processes the key validation type changed event and renders the concrete key validator view. 
     * 
     * @param e the event.
     */
    public void validatorTypeChanged(AjaxBehaviorEvent e) {
        if (log.isDebugEnabled()) {
            log.debug("Setting key validator type " + ((HtmlSelectOneMenu) e.getComponent()).getValue());
        }
        final String type = (String) ((HtmlSelectOneMenu) e.getComponent()).getValue();
        validator = ValidatorFactory.INSTANCE.getArcheType(type);
        validator.setDataMap(getValidator().getDataMap());
        validator.setProfileId(getSelectedKeyValidatorId());
        validator.setProfileName(getSelectedKeyValidatorName());
        FacesContext.getCurrentInstance().renderResponse();
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
        for (final Validator validator : ValidatorFactory.INSTANCE.getAllImplementations()) {
            ret.add(new SelectItem(validator.getValidatorTypeIdentifier(), validator.getLabel()));
        }
        Collections.sort(ret, new Comparator<SelectItem>() {
            @Override
            public int compare(SelectItem o1, SelectItem o2) {
                return o1.getLabel().compareToIgnoreCase(o2.getLabel());
            }
        });
        return ret;
    }

    /**
     * Gets a list of select items of the available base parameter options.
     * @return the list.
     */
    public List<SelectItem> getAvailableValidatorSettingsTemplates() {
        final List<SelectItem> result = new ArrayList<SelectItem>();
        final KeyValidatorSettingsTemplate[] items = KeyValidatorSettingsTemplate.values();
        for (int i = 0, j = items.length; i < j; i++) {
            result.add(new SelectItem(items[i].getOption(), getEjbcaWebBean().getText(items[i].getLabel())));
        }
        return result;
    }

    /**
     * Gets the selected validator type.
     * 
     * @return the selected type.
     */
    public String getValidatorType() {
        if(validator != null) {
            return validator.getValidatorTypeIdentifier();
        } else {
            return null;
        }
    }
    
    public void setValidatorType(String value) {
        // this re-creates the whole validator, so only do it if it actually changed type
        if (!validator.getValidatorTypeIdentifier().equals(value)) {
            if (log.isTraceEnabled()) {
                log.trace("Changing validator type to "+value);
            }
            validator = ValidatorFactory.INSTANCE.getArcheType(value);
            validator.setDataMap(getValidator().getDataMap());
            validator.setProfileId(getSelectedKeyValidatorId());
            validator.setProfileName(getSelectedKeyValidatorName());
        }
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
     * Validates the BaseKeyValildator notBefore field, see {@link ValidatorBase#getNotBefore()}.
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
     * Validates the BaseKeyValildator notBefore condition field, see {@link ValidatorBase#getNotBeforeCondition()}.
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
     * Validates the BaseKeyValildator notAfter field, see {@link ValidatorBase#getNotAfter()}.
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
     * Validates the BaseKeyValildator notAfter condition field, see {@link ValidatorBase#getNotAfterCondition()}.
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
        final List<String> selectedIds = (List<String>) value;
        final List<Integer> ids = new ArrayList<Integer>(certificateProfileSession.getCertificateProfileIdToNameMap().keySet());
        for (String id : selectedIds) {
            if (!ids.contains(Integer.parseInt(id))) {
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
        try {
            keyValidatorSession.changeKeyValidator(getAdmin(), validator);
            getEjbcaWebBean().getInformationMemory().keyValidatorsEdited();
            addInfoMessage("VALIDATORSAVED");
            reset();
            return "done";
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage("Not authorized to edit key validator.");
        } catch (KeyValidatorDoesntExistsException e) {
            // NOPMD: ignore do nothing
        }
        return StringUtils.EMPTY;
    }

    /**
     * Gets a list of select items of the available certificate profiles.
     * @return the list.
     */
    public List<SelectItem> getAvailableCertificateProfiles() {
        final List<SelectItem> result = new ArrayList<SelectItem>();
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
     * Gets the BaseKeyValidator allCertificateProfileIds field.
     * @return the list
     */
    public boolean isAllCertificateProfileIds() {
        return validator.isAllCertificateProfileIds();
    }

    /**
     * Sets the BaseKeyValidator allCcertificateProfileIds field.
     * @param true or false.
     */
    public void setAllCertificateProfileIds(boolean isAll) {
        validator.setAllCertificateProfileIds(isAll);
    }

    /**
     * Gets the BaseKeyValidator certificateProfileIds field.
     * @return the list
     */
    public List<Integer> getCertificateProfileIds() {
        return validator.getCertificateProfileIds();
    }

    /**
     * Sets the BaseKeyValidator certificateProfileIds field.
     * @param the list of certificate profile ids.
     */
    public void setCertificateProfileIds(List<String> ids) {
        final List<Integer> list = new ArrayList<Integer>();
        for (String id : ids) {
            list.add(Integer.parseInt(id));
        }
        validator.setCertificateProfileIds(list);
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
        final List<SelectItem> result = new ArrayList<SelectItem>();
        final KeyValidationFailedActions[] items = KeyValidationFailedActions.values();
        for (int i = 0, j = items.length; i < j; i++) {
            result.add(new SelectItem(items[i].getIndex(), getEjbcaWebBean().getText(items[i].getLabel())));
        }
        return result;
    }

    /**
     * Gets the BaseKeyValidator failedAction field.
     * @return the failed action index.
     */
    public Integer getFailedAction() {
        return validator.getFailedAction();
    }

    /**
     * Sets the BaseKeyValidator failedAction field.
     * @param index the failed action index.
     */
    public void setFailedAction(Integer index) {
        validator.setFailedAction(index);
    }

    /**
     * Sets the BaseKeyValidator notApplicableAction field.
     * @param index the not applicable action index.
     */
    public void setNotApplicableAction(Integer index) {
        validator.setNotApplicableAction(index);
    }

    /**
     * Gets the BaseKeyValidator notApplicableAction field.
     * @return the notApplicableAction action index.
     */
    public Integer getNotApplicableAction() {
        return validator.getNotApplicableAction();
    }

    /**
     * Gets a list of available ECC curve key, label pairs.
     * @return the list.
     */
    public Map<String, String> getAvailableEcCurves() {
        final Map<String, String> result = new TreeMap<String, String>();
        final Map<String, List<String>> map = AlgorithmTools.getNamedEcCurvesMap(false);
        final String[] keys = map.keySet().toArray(new String[map.size()]);
        Arrays.sort(keys);
        result.put(getEjbcaWebBean().getText("AVAILABLEECDSABYBITS"), CertificateProfile.ANY_EC_CURVE);
        List<String> curves;
        for (final String key : keys) {
            curves = map.get(key);
            if (log.isDebugEnabled()) {
                log.debug("Availabe EC curve: " + curves);
            }
            result.put(StringTools.getAsStringWithSeparator(" / ", curves), key);
        }
        return result;
    }

    /**
     * Gets the available key algorithms.
     * @return the list
     */
    public List<SelectItem> getAvailableKeyAlgorithms() {
        final List<SelectItem> result = new ArrayList<SelectItem>();
        result.add(new SelectItem("-1", getEjbcaWebBean().getText("ALL")));
        for (final String current : AlgorithmTools.getAvailableKeyAlgorithms()) {
            result.add(new SelectItem(current));
        }
        return result;
    }

    /**
     * Transforms date condition enumerations to a list of select items.
     * @return the list.
     */
    private List<SelectItem> conditionsToSelectItems() {
        final List<SelectItem> result = new ArrayList<SelectItem>();
        final KeyValidatorDateConditions[] items = KeyValidatorDateConditions.values();
        for (int i = 0, j = items.length; i < j; i++) {
            result.add(new SelectItem(items[i].getIndex(), getEjbcaWebBean().getText(items[i].getLabel())));
        }
        return result;
    }

    /**
     * Processes the key validation base parameter options changed event and renders the concrete key validator view. 
     * 
     * @param e the event.
     */
    public void validatorTemplateChanged(AjaxBehaviorEvent e) {
        if (log.isDebugEnabled()) {
            log.debug("Setting key validator base parameter option " + ((HtmlSelectOneMenu) e.getComponent()).getValue());
        }
        final Integer value = (Integer) ((HtmlSelectOneMenu) e.getComponent()).getValue();
        final Validator keyValidator = getValidator();
        keyValidator.setSettingsTemplate(value);
        keyValidator.setKeyValidatorSettingsTemplate();
        FacesContext.getCurrentInstance().renderResponse();
    }

}
