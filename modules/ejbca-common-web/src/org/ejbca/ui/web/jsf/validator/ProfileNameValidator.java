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
package org.ejbca.ui.web.jsf.validator;

import org.apache.commons.lang.StringUtils;
import org.cesecore.util.StringTools;
import org.ejbca.ui.web.configuration.EjbcaJSFHelper;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

/**
 * JSF validator for input parameter representing a profile name. This validator uses validation preconditions in priority order:
 * <ul>
 *     <li>no preconditions set - should validate;</li>
 *     <li>attribute 'validationCondition' - sets the explicit validation condition to true or false;</li>
 *     <li>attribute 'validationTriggerIds' - defines the binding button-action to validated html element.</li>
 * </ul>
 * An input profile name is validated for (if validation preconditions are met):
 * <ul>
 *     <li>Might be null;</li>
 *     <li>Not empty (eg. not '', ' ');</li>
 *     <li>Contains legal characters (eg. not '*');</li>
 *     <li>Less or equal to maximum length (attribute 'maximumLength'), if set.</li>
 * </ul>
 *
 * @see StringTools#checkFieldForLegalChars(String)
 * @see ValidationHelper#matchConditionalValidation(FacesContext, UIComponent)
 *
 * @version $Id: ProfileNameValidator.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
@FacesValidator("profileNameValidator")
public class ProfileNameValidator implements Validator {

    @Override
    public void validate(final FacesContext facesContext, final UIComponent uiComponent, final Object o) throws ValidatorException {

        if(o != null && ValidationHelper.matchConditionalValidation(facesContext, uiComponent)) {
            final String profileName = ((String) o).trim();
            // Is not blank
            if(StringUtils.isBlank(profileName)) {
                final String message = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("NAME_CANNOT_BE_EMPTY");
                throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, null));
            }
            // Contains legal characters
            if(!StringTools.checkFieldForLegalChars(profileName)) {
                final String message = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("ONLYCHARACTERS");
                throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, null));
            }
            // Has maximum length attribute
            final Object maximumLengthAttribute = uiComponent.getAttributes().get("maximumLength");
            if (maximumLengthAttribute != null) {
                int maximumLength = Integer.valueOf((String) maximumLengthAttribute);
                if (profileName.length() > maximumLength) {
                    final String message = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("MAXIMUMLENGTH_FIELD", false, maximumLength);
                    throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, null));
                }
            }
        }
    }

}
