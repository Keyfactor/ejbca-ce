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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
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
import org.apache.commons.lang.time.DateUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.validation.BaseKeyValidator;
import org.cesecore.keys.validation.ICustomKeyValidator;
import org.cesecore.keys.validation.IKeyValidator;
import org.cesecore.keys.validation.KeyGeneratorSources;
import org.cesecore.keys.validation.KeyValidationFailedActions;
import org.cesecore.keys.validation.KeyValidatorDateConditions;
import org.cesecore.keys.validation.KeyValidatorDoesntExistsException;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.keys.validation.KeyValidatorSettingsTemplate;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.keys.validation.AbstractCustomKeyValidator;
import org.ejbca.core.model.ca.keys.validation.CustomKeyValidatorTools;
import org.ejbca.core.model.ca.keys.validation.CustomKeyValidatorUiSupport;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JSF MBean backing the edit key validators page.
 *  
 * @version $Id$
 */
// Declarations in faces-config.xml
//@javax.faces.bean.SessionScoped
//@javax.faces.bean.ManagedBean(name="keyValidatorBean")
public class KeyValidatorBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = -2889613238729145716L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(KeyValidatorBean.class);

    /** List of accepted date formats for notBefore and notAfter filter. */
    private static final String[] DATE_FORMAT = new String[] { "y-M-d HH:m:sZZ", "y-M-d H:m:s", "y-M-d" };

    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;

    @EJB
    private KeyValidatorSessionLocal keyValidatorSession;

    // Declarations in faces-config.xml
    // @javax.faces.bean.ManagedProperty(value="#{certProfilesBean}")
    private KeyValidatorsBean keyValidatorsBean;

    /** Selected key validator id.*/
    private int currentKeyValidatorId = -1;

    /** Selected key validator. */
    private BaseKeyValidator keyValidator = null;

    /** Since this MBean is session scoped we need to reset all the values when needed. */
    private void reset() {
        currentKeyValidatorId = -1;
        keyValidator = null;
    }

    /**
     * Gets the KeyValidatorsBean reference.
     * @return the KeyValidatorsBean.
     */
    public KeyValidatorsBean getKeyValidatorsBean() {
        return keyValidatorsBean;
    }

    /**
     * Sets the KeyValidatorsBean reference.
     * @param bean
     */
    public void setKeyValidatorsBean(final KeyValidatorsBean bean) {
        this.keyValidatorsBean = bean;
    }

    /**
     * Gets the selected key validator id.
     * @return the id.
     */
    public Integer getSelectedKeyValidatorId() {
        return keyValidatorsBean.getSelectedKeyValidatorId();
    }

    /**
     * Gets the selected key validator name.
     * @return the name.
     */
    public String getSelectedKeyValidatorName() {
        return keyValidatorSession.getKeyValidatorName(getSelectedKeyValidatorId());
    }

    /**
     * Gets the selected key validator.
     * @return the key validator.
     */
    public BaseKeyValidator getKeyValidator() {
        if (currentKeyValidatorId != -1 && keyValidator != null && getSelectedKeyValidatorId().intValue() != currentKeyValidatorId) {
            reset();
        }
        if (keyValidator == null) {
            if (log.isDebugEnabled()) {
                log.debug("Request key validator with id " + getSelectedKeyValidatorId());
            }
            currentKeyValidatorId = getSelectedKeyValidatorId().intValue();
            keyValidator = keyValidatorSession.getKeyValidator(currentKeyValidatorId);
        }
        return keyValidator;
    }

    /**
     * Checks if the administrator is authorized the edit key validators.
     * 
     * @return true if the administrator is authorized.
     */
    public boolean hasEditRights() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_EDITKEYVALIDATOR);
    }

    /**
     * Processes the key validation type changed event and renders the concrete key validator view. 
     * 
     * @param e the event.
     */
    public void keyValdatorTypeChanged(AjaxBehaviorEvent e) {
        if (log.isDebugEnabled()) {
            log.debug("Setting key validator type " + ((HtmlSelectOneMenu) e.getComponent()).getValue());
        }
        final String value = (String) ((HtmlSelectOneMenu) e.getComponent()).getValue();
        int type;
        try {
            type = Integer.parseInt(value);
            getKeyValidator().setClasspath("");
        } catch (NumberFormatException ex) {
            // Must be custom type.
            final String classpath = value.substring(value.indexOf('-') + 1);
            type = AbstractCustomKeyValidator.KEY_VALIDATOR_TYPE;
            getKeyValidator().setClasspath(classpath);
        }
        getKeyValidator().setType(type);
        keyValidator = (BaseKeyValidator) keyValidatorSession.createKeyValidatorInstanceByData(getKeyValidator().getRawData());
        keyValidator.setKeyValidtorId(getSelectedKeyValidatorId());
        FacesContext.getCurrentInstance().renderResponse();
    }

    /**
     * Processes the key validation base parameter options changed event and renders the concrete key validator view. 
     * 
     * @param e the event.
     */
    public void keyValidatorTemplateChanged(AjaxBehaviorEvent e) {
        if (log.isDebugEnabled()) {
            log.debug("Setting key validator base parameter option " + ((HtmlSelectOneMenu) e.getComponent()).getValue());
        }
        final Integer value = (Integer) ((HtmlSelectOneMenu) e.getComponent()).getValue();
        final BaseKeyValidator keyValidator = getKeyValidator();
        keyValidator.setSettingsTemplate(value);
        keyValidator.setKeyValidatorSettingsTemplate();
        FacesContext.getCurrentInstance().renderResponse();
    }

    /**
     * Checks weather the custom key validator settings are enabled and the concerning fields (key size, key strength, more detailed attributes, etc.) are enabled.
     * @return true if customs settings are enabled.
     */
    public boolean isCustomBaseSettingsEnabled() {
        return KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption() == getKeyValidator().getSettingsTemplate();
    }

    /**
     * Gets the available key validators.
     * 
     * @return the available key validators as list
     */
    public List<SelectItem> getAvailableKeyValidators() {
        String classPath;
        String className;
        final List<SelectItem> result = new ArrayList<SelectItem>();
        final List<IKeyValidator> keyValidators = keyValidatorSession.getKeyValidatorImplementations();
        for (IKeyValidator keyValidator : keyValidators) {
            classPath = keyValidator.getClass().getName();
            className = classPath.substring(classPath.lastIndexOf('.') + 1);
            result.add(new SelectItem(Integer.toString(keyValidator.getType()), getEjbcaWebBean().getText(className.toUpperCase())));
        }
        final List<ICustomKeyValidator> customKeyValidators = keyValidatorSession.getCustomKeyValidatorImplementations();
        for (ICustomKeyValidator keyValidator : customKeyValidators) {
            classPath = keyValidator.getClasspath();
            className = classPath.substring(classPath.lastIndexOf('.') + 1);
            result.add(new SelectItem(Integer.toString(keyValidator.getType()) + "-" + classPath,
                    getEjbcaWebBean().getText(className.toUpperCase()) + " (" + getEjbcaWebBean().getText("CUSTOMKEYVALIDATOR") + ")"));
        }
        Collections.sort(result, new Comparator<SelectItem>() { // Sort by label.
            @Override
            public int compare(final SelectItem selectItem0, final SelectItem selectItem1) {
                return String.valueOf(selectItem0.getLabel()).compareTo(String.valueOf(selectItem1.getLabel()));
            }
        });
        return result;
    }

    /**
     * Gets a list of select items of the available base parameter options.
     * @return the list.
     */
    public List<SelectItem> getAvailableKeyValidatorSettingsTemplates() {
        final List<SelectItem> result = new ArrayList<SelectItem>();
        final KeyValidatorSettingsTemplate[] items = KeyValidatorSettingsTemplate.values();
        for (int i = 0, j = items.length; i < j; i++) {
            result.add(new SelectItem(items[i].getOption(), getEjbcaWebBean().getText(items[i].getLabel())));
        }
        return result;
    }

    /**
     * Gets the selected key validator type.
     * 
     * @return the selected type.
     */
    public String getKeyValidatorType() {
        final int type = getKeyValidator().getType();
        String result;
        if (AbstractCustomKeyValidator.KEY_VALIDATOR_TYPE == type) {
            result = Integer.toString(type) + "-" + getKeyValidator().getClasspath();
        } else {
            result = Integer.toString(type);
        }
        return result;
    }

    /**
     * Sets the selected key validator type.
     * @param value the type as string.
     */
    public void setKeyValidatorType(final String value) {
        int type;
        try {
            type = Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            // Must be custom type.
            final String classpath = value.substring(value.indexOf('-') + 1);
            type = AbstractCustomKeyValidator.KEY_VALIDATOR_TYPE;
            getKeyValidator().setClasspath(classpath);
        }
        getKeyValidator().setType(type);
    }

    /**
     * Validates the BaseKeyValildator description field, see {@link BaseKeyValidator#getDescription()}.
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
     * Validates the BaseKeyValildator type field, see {@link BaseKeyValidator#getType()}.
     * @param context the faces context.
     * @param component the events source component
     * @param value the source components value attribute
     * @throws ValidatorException if the validation fails.
     */
    public void validateKeyValdatorType(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        int type = -1;
        String message = null;
        final List<Integer> types = keyValidatorSession.getKeyValidatorTypes();
        try {
            type = Integer.parseInt((String) value);
            if (!types.contains(type)) {
                message = "Key validator type must be on of " + types;
            }
        } catch (NumberFormatException e) { // Must be a custom type: '0-<fullyQualifiedClassPath>'
            final String[] tokens = ((String) value).split("-");
            if (tokens.length > 1) {
                try {
                    type = Integer.parseInt(tokens[0]);
                    final String className = tokens[1];
                    if (AbstractCustomKeyValidator.KEY_VALIDATOR_TYPE != type) {
                        message = "Key validator type must be on of " + types;
                    }
                    if (StringUtils.isBlank(className) || !keyValidatorSession.getCustomKeyValidatorImplementationClasses().contains(className)) {
                        message = "Custom key validator class not found: " + className;
                    }
                } catch (NumberFormatException e2) {
                    message = "Could not parse key validator type (or custom type) index: " + value;
                }
            }
        }
        if (null != message) {
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
        }
    }

    /**
     * Validates the BaseKeyValildator notBefore field, see {@link BaseKeyValidator#getNotBefore()}.
     * @param context the faces context.
     * @param component the events source component
     * @param value the source components value attribute
     * @throws ValidatorException if the validation fails.
     */
    public void validateNotBefore(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        final String string = (String) value;
        if (StringUtils.isNotBlank(string) && null == parseDate((String) value)) {
            final String message = "Key validator not before must be a valid ISO 8601 date or time " + value;
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
        }
    }

    /**
     * Validates the BaseKeyValildator notBefore condition field, see {@link BaseKeyValidator#getNotBeforeCondition()}.
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
     * Validates the BaseKeyValildator notAfter field, see {@link BaseKeyValidator#getNotAfter()}.
     * @param context the faces context.
     * @param component the events source component
     * @param value the source components value attribute
     * @throws ValidatorException if the validation fails.
     */
    public void validateNotAfter(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        final String string = (String) value;
        if (StringUtils.isNotBlank(string) && null == parseDate((String) value)) {
            final String message = "Key validator not after must be a valid ISO 8601 date or time " + value;
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
        }
    }

    /**
     * Validates the BaseKeyValildator notAfter condition field, see {@link BaseKeyValidator#getNotAfterCondition()}.
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
     * Validates the BaseKeyValildator failedAction field, see {@link BaseKeyValidator#getFailedAction()}.
     * @param context the faces context.
     * @param component the events source component
     * @param value the source components value attribute
     * @throws ValidatorException if the validation fails.
     */
    public void validateFailedAction(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        final Integer index = (Integer) value;
        if (!KeyValidationFailedActions.index().contains(index)) {
            final String message = "Key validator failed action must be on of " + KeyValidatorDateConditions.index();
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
        }
    }

    /**
     * Validates the BaseKeyValildator certificateProfileIds field, see {@link BaseKeyValidator#getCertificateProfileIds()}.
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
     * Validates the BlacklistKeyValildator key generation sources index field.
     * @param context the faces context.
     * @param component the events source component
     * @param value the source components value attribute
     * @throws ValidatorException if the validation fails.
     */
    @SuppressWarnings("unchecked")
    public void validateKeyGenerationSource(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        final List<String> includesAll = new ArrayList<String>(KeyGeneratorSources.sourcesAsString());
        includesAll.add("-1");
        if (!includesAll.containsAll((ArrayList<String>) value)) {
            final String message = "Key generator source index must be on of " + includesAll;
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
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
        boolean success = true;
        try {
            // Perform last minute validations before saving
            //          final BaseKeyValidator keyValidator = getKeyValidator();
            //          if ( ... validate ...) {
            //                addErrorMessage("ONEAVAILABLEKEYALGORITHM");
            //                success = false;
            //          }
            // Workaround: Required for saving after first editing (keyValidator.getName() is null).
            final String name = getSelectedKeyValidatorName();
            if (success) { // Modify the key validator.
                if (keyValidator instanceof CustomKeyValidatorUiSupport) {
                    final String propertiesString = CustomKeyValidatorTools
                            .getString(((CustomKeyValidatorUiSupport) keyValidator).getCustomUiPropertyList());
                    if (log.isDebugEnabled()) {
                        log.debug("Store custom key validator properties for " + name + ": " + propertiesString);
                    }
                    ((AbstractCustomKeyValidator) keyValidator).setPropertyData(propertiesString);
                }
                keyValidatorSession.changeKeyValidator(getAdmin(), name, keyValidator);
                getEjbcaWebBean().getInformationMemory().keyValidatorsEdited();
                addInfoMessage("KEYVALIDATORSAVED");
                reset();
                return "done";
            }
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
        final Map<Integer, String> map = certificateProfileSession.getCertificateProfileIdToNameMap();
        final Iterator<Integer> iterator = map.keySet().iterator();
        Integer key;
        while (iterator.hasNext()) {
            key = iterator.next();
            result.add(new SelectItem(key, map.get(key)));
        }
        return result;
    }

    /**
     * Gets the BaseKeyValidator certificateProfileIds field.
     * @return the list
     */
    public List<Integer> getCertificateProfileIds() {
        return keyValidator.getCertificateProfileIds();
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
        keyValidator.setCertificateProfileIds(list);
    }

    /**
     * Gets a list of select items of the available notBefore conditions.
     * @return the list.
     */
    public List<SelectItem> getAvailableNotBeforeConditions() {
        return conditionsToSelectItems();
    }

    /**
     * Gets the BaseKeyValidator notBefore condition field.
     * @return the date condition index.
     */
    public Integer getNotBeforeCondition() {
        return keyValidator.getNotBeforeCondition();
    }

    /**
     * Sets the BaseKeyValidator notBefore condition field.
     * @param the date condition index.
     */
    public void setNotBeforeCondition(Integer index) {
        keyValidator.setNotBeforeCondition(index);
    }

    /**
     * Gets a list of select items of the available notAfter conditions.
     * @return the list.
     */
    public List<SelectItem> getAvailableNotAfterConditions() {
        return conditionsToSelectItems();
    }

    /**
     * Gets the BaseKeyValidator notAfter condition field.
     * @return the date condition index.
     */
    public Integer getNotAfterCondition() {
        return keyValidator.getNotAfterCondition();
    }

    /**
     * Sets the BaseKeyValidator notAfter condition field.
     * @param the date condition index.
     */
    public void setNotAfterCondition(Integer index) {
        keyValidator.setNotAfterCondition(index);
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
        return keyValidator.getFailedAction();
    }

    /**
     * Sets the BaseKeyValidator failedAction field.
     * @param index the failed action index.
     */
    public void setFailedAction(Integer index) {
        keyValidator.setFailedAction(index);
    }

    /**
     * Gets the BaseKeyValidator notBefore field.
     * @return the formatted date string.
     */
    public String getNotBefore() {
        return formatDate(keyValidator.getNotBefore());
    }

    /**
     * Sets the BaseKeyValidator notBefore field.
     * @param formattedDate the formatted date string.
     */
    public void setNotBefore(String formattedDate) {
        keyValidator.setNotBefore(parseDate(formattedDate));
    }

    /**
     * Gets the BaseKeyValidator notAfter field.
     * @return the formatted date string.
     */
    public String getNotAfter() {
        return formatDate(keyValidator.getNotAfter());
    }

    /**
     * Sets the BaseKeyValidator notAfter field.
     * @param formattedDate the formatted date string.
     */
    public void setNotAfter(String formattedDate) {
        keyValidator.setNotAfter(parseDate(formattedDate));
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
     * Gets a list of available items of public generator sources.
     * @return the list.
     */
    public List<SelectItem> getAvailableKeyGeneratorSources() {
        final List<SelectItem> result = new ArrayList<SelectItem>();
        final KeyGeneratorSources[] items = KeyGeneratorSources.values();
        result.add(new SelectItem(new Integer(-1), getEjbcaWebBean().getText("KEYGENERATORSOURCE_ALL")));
        for (int i = 0, j = items.length; i < j; i++) {
            result.add(new SelectItem(items[i].getSource(), getEjbcaWebBean().getText(items[i].getLabel())));
        }
        return result;
    }

    /**
     * Gets the available key algorithms.
     * @return the list
     */
    public List<SelectItem> getAvailableKeyAlgorithms() {
        final List<SelectItem> result = new ArrayList<SelectItem>();
        result.add(new SelectItem("-1", getEjbcaWebBean().getText("KEYGENERATORSOURCE_ALL")));
        for (final String current : AlgorithmTools.getAvailableKeyAlgorithms()) {
            result.add(new SelectItem(current));
        }
        return result;
    }

    /**
     * Formats a date.
     * @param date the date
     * @return the formatted date string.
     */
    private String formatDate(Date date) {
        String result = StringUtils.EMPTY;
        if (null != date) {
            result = new SimpleDateFormat(DATE_FORMAT[0]).format(date);
        }
        return result;
    }

    /**
     * Parses a date string with the date format list.
     * @param string the formatted date string.
     * @return the date or null, if the date could not be parsed.
     */
    private Date parseDate(String string) {
        Date result = null;
        if (StringUtils.isNotBlank(string)) {
            final String dateString = string.trim();
            try {
                result = DateUtils.parseDate(dateString, DATE_FORMAT);
                //            result = StringTools.tryParseDate(dateString, DATE_FORMAT);
            } catch (ParseException e) {
                log.debug("Could not parse Date: " + string);
            }
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

    //    /**
    //     * Redirect the client browser to the relevant section of key validator page.
    //     * 
    //     * @param componentId the target components id.
    //     * @throws IOException if the redirect fails.
    //     */
    //    private void redirectToComponent(final String componentId) throws IOException {
    //        final ExternalContext ec = FacesContext.getCurrentInstance().getExternalContext();
    //        ec.redirect(getEjbcaWebBean().getBaseUrl() + getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath()
    //                + "ca/editkeyvalidators/editkeyvalidator.xhmtl#kvf:" + componentId);
    //    }
}
