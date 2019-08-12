package org.ejbca.ui.web.admin;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * Validator used to validate the input for maximum number of operations that
 * a key on CP5 supported HSM can perform after authorization.
 * 
 * @version $Id$
 *
 */
public class CP5KeyMaxOperationsValidator implements Validator {
    private static final Logger log = Logger.getLogger(CP5KeyMaxOperationsValidator.class);
    
    @Override
    public void validate(FacesContext facesContext, UIComponent uIComponent, Object object) throws ValidatorException {
        String textFieldValue = null;
        if (object instanceof String) {
            textFieldValue = (String) object;
        }

        if (log.isDebugEnabled()) {
            log.debug("Validating component " + uIComponent.getClientId(facesContext) + " with value \"" + textFieldValue + "\"");
        }

        final String msg = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("INVALIDCP5MAXOPERATIONS") + textFieldValue;

        if (!StringUtils.isBlank(textFieldValue)) {
            try {
                final long textFieldLongValue = Long.parseLong(textFieldValue);
                if (textFieldLongValue < 0 || textFieldLongValue > 4294967295L) {
                    throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
                }
            } catch (NumberFormatException e) {
                throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
            }
        }
    }
}
