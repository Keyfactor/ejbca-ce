/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.admin.administratorprivileges;

import java.math.BigInteger;
import java.util.Map;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.apache.log4j.Logger;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/** Validates hexadecimal serial numbers entered in the admin-GUI. Does it by constructing a biginteger.
 * 
 * @version $Id$
 */
public class HexSerialNumberValidator implements Validator{
	private static final Logger log = Logger.getLogger(HexSerialNumberValidator.class);

	public void validate(FacesContext facesContext, UIComponent textField, Object object) throws ValidatorException {
		if (log.isDebugEnabled()) {
			log.debug("Validating component " + textField.getClientId(facesContext) + " with value \"" + object + "\"");
		}
		Map<String, String> map = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap();
		for(String key :  map.keySet()) {
			if (key.contains("matchWith") && X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.equals(X500PrincipalAccessMatchValue.matchFromName(map.get(key)))) {
				try {
					new BigInteger((String) object, 16);
				} catch (NumberFormatException e) {
					FacesMessage message = new FacesMessage();
					message.setSummary(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("HEXREQUIRED"));
					throw new ValidatorException(message);
				}
			}
		}
	}
}
