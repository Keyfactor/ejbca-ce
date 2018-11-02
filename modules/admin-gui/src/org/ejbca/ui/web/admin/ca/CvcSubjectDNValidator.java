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
package org.ejbca.ui.web.admin.ca;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.apache.commons.lang.StringUtils;

/**
 * Validator used in validating CVC subject dn field (create ca page).
 * 
 * @version $Id$
 *
 */
@FacesValidator("org.ejbca.ui.web.admin.ca.CvcSubjectDNValidator")
public class CvcSubjectDNValidator implements Validator {

    @Override
    public void validate(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        
        Matcher matchC = Pattern.compile("(^|,(\\s*))C=").matcher(value.toString());
        Matcher matchCN = Pattern.compile("(^|,(\\s*))CN=").matcher(value.toString());
        
        if (!value.toString().equals(StringUtils.EMPTY) && (!matchC.find() || !matchCN.find())) {
            FacesMessage msg = new FacesMessage("Invalid CVC subject dn format. Example is CN=Test,C=SE", "SubjectDN validation failed!");
            msg.setSeverity(FacesMessage.SEVERITY_ERROR);
            throw new ValidatorException(msg);
        }
    }

}
