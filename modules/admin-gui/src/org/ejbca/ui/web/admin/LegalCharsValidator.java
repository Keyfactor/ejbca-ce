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

import org.apache.log4j.Logger;
import org.cesecore.util.StringTools;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/** JSF validator to check that input fields do not contain characters that might be dangerous for SQL queries 
 * (non parameterized queries that is).
 * 
 * @version $Id$
 */
public class LegalCharsValidator implements Validator {
	private static final Logger log = Logger.getLogger(LegalCharsValidator.class);

	public void validate(FacesContext facesContext, UIComponent uIComponent, Object object) throws ValidatorException {
		final String textFieldValue = (String)object;
		if (log.isDebugEnabled()) {
			log.debug("Validating component " + uIComponent.getClientId(facesContext) + " with value \"" + textFieldValue + "\"");
		}
		if (StringTools.hasSqlStripChars(textFieldValue)) {
		    final String msg = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("INVALIDCHARS");
			throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
		}
	}
}
