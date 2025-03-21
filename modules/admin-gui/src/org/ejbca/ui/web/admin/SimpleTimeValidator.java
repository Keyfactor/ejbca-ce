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

package org.ejbca.ui.web.admin;

import jakarta.faces.application.FacesMessage;
import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;
import jakarta.faces.validator.FacesValidator;
import jakarta.faces.validator.Validator;
import jakarta.faces.validator.ValidatorException;

import org.apache.log4j.Logger;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.TimeUnitFormat;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

import com.keyfactor.util.StringTools;

/** JSF validator to check that the input does not contain any invalid characters and is a valid time unit format (i.e. '3y 6mo -10d 6h +30m 30s'). 
 * 
 */
@FacesValidator("simpleTimeValidator")
public class SimpleTimeValidator implements Validator<Object> {

    private static final Logger log = Logger.getLogger(SimpleTimeValidator.class);

    @Override
    public void validate(FacesContext facesContext, UIComponent component, Object object) throws ValidatorException {
        final String value = (String) object;
        final TimeUnitFormat format = SimpleTime.getTimeUnitFormatOrThrow( (String) component.getAttributes().get("precision"));
        long minimumValue = Long.MIN_VALUE;
        if (null != component.getAttributes().get("minimumValue")) {
            minimumValue = Long.parseLong((String) component.getAttributes().get("minimumValue")); 
        }
        long maximumValue = Long.MAX_VALUE;
        if (null != component.getAttributes().get("maximumValue")) {
            maximumValue = Long.parseLong((String) component.getAttributes().get("maximumValue")); 
        }
        boolean failed = true;
        if (StringTools.hasSqlStripChars(value).isEmpty()) {
            try {
                final long millis = format.parseMillis(value);
                if (minimumValue <= millis && millis <= maximumValue) {
                    failed = false;
                }
            } catch (NumberFormatException e) {
                // NOOP
            }
        }
        if (failed) {
            if (log.isDebugEnabled()) {
                log.debug("Validating component " + component.getClientId(facesContext) + " with value \"" + value + "\" failed.");
            }
            final String message = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("INVALIDTIMEFORMAT");
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, null));
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Validating component " + component.getClientId(facesContext) + " with value \"" + value + "\"");
            }
        }
    }
}
