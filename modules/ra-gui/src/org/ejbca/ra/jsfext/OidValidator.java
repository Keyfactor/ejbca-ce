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
 
 
package org.ejbca.ra.jsfext;

import jakarta.faces.application.FacesMessage;
import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;
import jakarta.faces.validator.FacesValidator;
import jakarta.faces.validator.Validator;
import jakarta.faces.validator.ValidatorException;

import org.apache.commons.lang.StringUtils;

import com.keyfactor.util.CertTools;

/**
 * Validator used to verify OID inputs. May be used to either validate a plain OID, e.g. "1.2.3.4"
 * or a string beginning with an OID such as "1.2.3.4.value = Test".
 * 
 * Usage: the attribute "beginsWith" should be set to "true" if the input string contains any
 * characters in addition to the plain OID.
 * 
 * Example usage: 
 * <f:validator validatorId="oidValidator"/>
 * <f:attribute name="beginsWith" value="true"/>
 * 
 * @version $Id$
 */
@FacesValidator("oidValidator")
public class OidValidator implements Validator<Object> {

    private static final String OID_PATTERN = "(\\.?\\d+)*";
    private static final String LINE_SEPARATOR = "\n";
    private static final String KEY_VALUE_SEPARATOR = "=";
    
    @Override
    public void validate(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        final String validationString = (String)value;
        final String beginswith = (String) component.getAttributes().get("beginsWith");
        
        if (!StringUtils.isEmpty(validationString)) {
            String[] oidStrings = validationString.split(LINE_SEPARATOR);
            final boolean beginsWith = beginswith.equals("true");
            for (String oidString : oidStrings) {
                String oid = oidString;
                if (beginsWith) {
                    oid = oidString.split(KEY_VALUE_SEPARATOR)[0];
                    oid = CertTools.getOidFromString(oid);
                }
                
                if (oid == null || !oid.matches(OID_PATTERN)) {
                    throw new ValidatorException(new FacesMessage("Incorrectly formatted OID(s)"));
                }
            }
        }
    }
}
