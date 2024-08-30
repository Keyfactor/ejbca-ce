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
package org.ejbca.ui.web.admin.ca.validators;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.faces.application.FacesMessage;
import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;
import jakarta.faces.validator.FacesValidator;
import jakarta.faces.validator.Validator;
import jakarta.faces.validator.ValidatorException;

import org.apache.commons.lang.StringUtils;

/**
 * Validator used in validating new subject dn field (edit ca page).
 * 
 * @version $Id$
 *
 */
@FacesValidator("org.ejbca.ui.web.admin.ca.validators.NewSubjectDNValidator")
public class NewSubjectDNValidator implements Validator<Object> {

    @Override
    public void validate(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        String currentSubjectDN = (String) component.getValueExpression("currentSubjectDN").getValue(context.getELContext());
        
        Matcher matchCN = Pattern.compile("(^|,(\\s*))CN=", Pattern.CASE_INSENSITIVE).matcher(value.toString());
        
        if (!value.toString().equals(StringUtils.EMPTY) && currentSubjectDN.equals((String)value)) {
            FacesMessage msg = new FacesMessage("New subject dn is same as current subject dn!", "SubjectDN validation failed!");
            msg.setSeverity(FacesMessage.SEVERITY_ERROR);
            throw new ValidatorException(msg);
        }
        
        if ( !value.toString().equals(StringUtils.EMPTY) && !matchCN.find()) {
            FacesMessage msg = new FacesMessage("Invalid subject DN format(Example CN=Test).", "SubjectDN validation failed!");
            msg.setSeverity(FacesMessage.SEVERITY_ERROR);
            throw new ValidatorException(msg);
        }
    }
}
