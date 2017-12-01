package org.ejbca.util.validator;

import java.math.BigInteger;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;


/**
 * Validates that no negative numbers can be set for a Rsa Key Validator.
 * 
 * @version 
 */

public class NoNegativeNumbersValidator implements Validator {
    
    /** Localization of log and error messages. */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /** Class logger. */
    private static final Logger log = Logger.getLogger(MinSmallerThanMaxValidator.class);
    
    @Override
    public void validate(FacesContext context, UIComponent component, Object object) throws ValidatorException {
        if (null != object){
            final BigInteger integerValue;
            if (object instanceof  Integer ){
                integerValue = BigInteger.valueOf(((Integer) object).intValue());
            } else {
                integerValue = (BigInteger) object; 
            }
            if (integerValue.compareTo(BigInteger.ZERO ) == -1) {
                final String field = (String) component.getAttributes().get("fieldName");
                final String message = intres.getLocalizedMessage("validator.error.set_key_validator_values_gui", integerValue, field);
                if (log.isDebugEnabled()) {
                    log.debug(message);
                }
                throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
            }
        }
    }
}

