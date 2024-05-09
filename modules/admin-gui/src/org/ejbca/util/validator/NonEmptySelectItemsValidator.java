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
package org.ejbca.util.validator;

import java.util.List;

import jakarta.faces.application.FacesMessage;
import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;
import jakarta.faces.validator.FacesValidator;
import jakarta.faces.validator.Validator;
import jakarta.faces.validator.ValidatorException;
import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;

/**
 * Ensures that at least one item has been selected within the JSF's selectManyListbox field.
 */
@FacesValidator("nonEmptySelectItemsValidator")
public class NonEmptySelectItemsValidator implements Validator<List<Object>> {
    private static final Logger log = Logger.getLogger(NonEmptySelectItemsValidator.class);
    private static final InternalResources intres = InternalResources.getInstance();
    
	@Override
	public void validate(FacesContext facesContext, UIComponent selectCA, List<Object> value) throws ValidatorException {
	    if (log.isDebugEnabled()) {
            log.debug("Validating component " + selectCA.getClientId(facesContext) + " with value \"" + value + "\"");
	    }   
	    if(value.isEmpty())  {
	        final String message = intres.getLocalizedMessage("validator.error.empty_ca_select_items");
	        throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
	    }    
	        
	}
}
