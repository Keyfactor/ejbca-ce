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

import java.io.UnsupportedEncodingException;
import java.util.Map;

import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.ejbca.ra.RaLocaleBean;

import nl.captcha.Captcha;

/**
 * Validated the CAPTCHA
 * @version $Id$
 *
 */
@FacesValidator(value = "captchaValidator")
public class CaptchaValidator implements Validator {

    private static final Logger log = Logger.getLogger(CaptchaValidator.class);
    
    @Override
    public void validate(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        Map<String, String> params = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap();
        String validationRequiredFromRequest = params.get("validationRequiredFromRequest");
        if(validationRequiredFromRequest == null || validationRequiredFromRequest.equalsIgnoreCase("false")){
            if(log.isTraceEnabled()){
                log.trace("Ignoring CaptchaValidator for component " + component.getClientId());
            }
            return;
        }
        
        String captchaEntered = (String) value;
        if(log.isTraceEnabled()){
            log.trace("Captcha entered: " + captchaEntered);
        }
        if (captchaEntered == null || captchaEntered.isEmpty()) {
            throw new IllegalStateException("Captcha value not entered");
        }else {
            HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            javax.servlet.http.HttpSession session = request.getSession();
            
            Captcha captcha = (Captcha) session.getAttribute(Captcha.NAME);
            if(log.isTraceEnabled()){
                log.trace("Captcha value: " + captcha.getAnswer());
            }
            try {
                request.setCharacterEncoding("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException(e);
            }
            if(!captcha.isCorrect(captchaEntered)){
                RaLocaleBean raLocaleBean = (RaLocaleBean) component.getValueExpression("raLocaleBean").getValue(context.getELContext());
                throw new ValidatorException(raLocaleBean.getFacesMessage("enroll_wrong_captcha_value_please_try_again"));
            }
        }
    }
}
