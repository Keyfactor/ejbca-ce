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

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.apache.commons.lang.CharSetUtils;
import org.apache.log4j.Logger;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * JSF validator that check that fields do no contain any ASCII control characters.
 * Newlines are allowed, though. 
 *
 * @version $Id$
 */
public class MultiLineFreeTextValidator implements Validator {
    private static final Logger log = Logger.getLogger(MultiLineFreeTextValidator.class);

    private static final String CONTROL_CHARS = "\u0000-\u0009\u000B\u000C\u000E-\u001F"; // all characters from 0x00-0x1F except 0A (line feed) and 0D (carriage return)

    @Override
    public void validate(final FacesContext facesContext, final UIComponent uIComponent, final Object object) throws ValidatorException {
        final String textFieldValue = (String) object;
        if (log.isDebugEnabled()) {
            log.debug("Validating component " + uIComponent.getClientId(facesContext) + " with value \"" + textFieldValue + "\"");
        }
        if (textFieldValue != null && CharSetUtils.count(textFieldValue, CONTROL_CHARS) != 0) {
            final String msg = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("INVALIDCHARS") + "control characters (except for newlines) are not allowed";
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
        }
    }
}
