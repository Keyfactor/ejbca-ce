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

import java.math.BigInteger;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.apache.log4j.Logger;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * Validates hexadecimal serial numbers entered in the Admin GUI by constructing a BigInteger.
 * Like HexSerialNumberValidator, except that this one accepts an empty/null values
 * and that it doesn't support "matchValue" fields.
 * 
 * @version $Id$
 */
public class OptionalHexSerialNumberValidator implements Validator {
	private static final Logger log = Logger.getLogger(OptionalHexSerialNumberValidator.class);

    @Override
	public void validate(FacesContext facesContext, UIComponent textField, Object object) throws ValidatorException {
		if (log.isDebugEnabled()) {
			log.debug("Validating component " + textField.getClientId(facesContext) + " with value \"" + object + "\"");
		}
		if (object != null && !((String)object).trim().isEmpty()) {
            try {
                new BigInteger((String) object, 16);
            } catch (NumberFormatException e) {
                throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("HEXREQUIRED"), null));
            }
		}
	}
}
