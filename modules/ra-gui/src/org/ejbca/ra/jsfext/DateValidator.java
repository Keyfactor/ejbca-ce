package org.ejbca.ra.jsfext;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;

import java.text.ParseException;


@FacesValidator("dateValidator")
public class DateValidator implements Validator<Object> {

    private static final Logger log = Logger.getLogger(DateValidator.class);

    @Override
    public void validate(FacesContext context, UIComponent component, Object value) {
        
        String dateInString = (String) value;
        
        if (!StringUtils.isEmpty(dateInString)) {
            if (StringTools.hasSqlStripChars(dateInString).isEmpty()) {
                try {
                    ValidityDate.parseAsIso8601(dateInString);
                } catch (ParseException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Validating ISO8601 date component with value '" + value + "' failed.");
                    }        
                    throw new ValidatorException(new FacesMessage("Incorrectly formatted or invalid date!"));
                }            
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Date component contains offending SQL strip characters: '" + value + "'");
                }
                throw new ValidatorException(new FacesMessage("Invalid characters in the input date!"));
            }
        }
    }
}