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
import javax.faces.component.UIOutput;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.apache.log4j.Logger;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * Validates hexadecimal serial numbers entered in the Admin GUI by constructing a BigInteger.
 * 
 * @version $Id$
 */
public class HexSerialNumberValidator implements Validator {
	private static final Logger log = Logger.getLogger(HexSerialNumberValidator.class);

	public void validate(FacesContext facesContext, UIComponent textField, Object object) throws ValidatorException {
		if (log.isDebugEnabled()) {
			log.debug("Validating component " + textField.getClientId(facesContext) + " with value \"" + object + "\"");
		}
		if ("matchValue".equals(textField.getId())) {
	        // Special treatment of admin management for legacy reasons
		    final String matchWithType = (String) ((UIOutput) textField.findComponent("matchWith")).getValue();
		    // Check if the matchWithType is "CertificateAuthenticationToken:WITH_SERIALNUMBER"
            if ((X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getTokenType()+":"
                    +X500PrincipalAccessMatchValue.WITH_SERIALNUMBER).equals(matchWithType)) {
                try {
                    new BigInteger((String) object, 16);
                } catch (NumberFormatException e) {
                    throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("HEXREQUIRED"), null));
                }
            }
		} else {
		    // Work as a normal field validator for any other field
            try {
                new BigInteger((String) object, 16);
            } catch (NumberFormatException e) {
                throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("HEXREQUIRED"), null));
            }
		}
	}
}
