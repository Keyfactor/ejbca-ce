package org.ejbca.ui.web.admin.ca.validators;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.apache.commons.lang.StringUtils;

@FacesValidator("org.ejbca.ui.web.admin.ca.validators.NewSubjectDNValidator")
public class NewSubjectDNValidator implements Validator {

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
