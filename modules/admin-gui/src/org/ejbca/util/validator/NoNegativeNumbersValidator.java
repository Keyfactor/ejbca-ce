package org.ejbca.util.validator;

import java.math.BigInteger;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.cesecore.internal.InternalResources;


/**
 * Validates that no negative numbers can be set for a Rsa Key Validator
 * 
 */


public class NoNegativeNumbersValidator implements Validator {
    
    private static final InternalResources intres = InternalResources.getInstance();    
    
    /**
     * Validates RSA Key Validator fields, asserting that they are not negative
     * @param context the faces context.
     * @param component the events source component
     * @param value the source components value attribute
     * @throws ValidatorException if the validation fails.
     */
    @Override
    public void validate(FacesContext context, UIComponent component, Object object) throws ValidatorException {
        if (null != object){
            BigInteger intVal;
            if (object instanceof  Integer ){
                intVal = new BigInteger(object.toString());
            } else {
                intVal = (BigInteger) object; 
            }
            if (intVal.compareTo(BigInteger.ZERO ) == -1) {
                final String field = (String) component.getAttributes().get("fieldname");
                final String message = intres.getLocalizedMessage("validator.error.set_key_validator_values", intVal, field);
                throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
            }
        }
    }
}

