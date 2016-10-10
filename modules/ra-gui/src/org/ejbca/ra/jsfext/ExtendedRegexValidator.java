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

import java.util.Map;

import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.RegexValidator;
import javax.faces.validator.ValidatorException;

import org.apache.log4j.Logger;

/**
 * Extended variant of RegexValidator handy to be used when regex pattern value is going to be evaluated during
 * view render time, which is the use-case for many UI components like h:dataTable and ui:repeat. Also the validator
 * requires request parameter "validationRequiredFromRequest" set to true to
 * be sent alongside with request to perform validation. Use for component that validation is NOT needed
 * for ALL POST requests. 
 * 
 * Example usage:
<ui:repeat value="#{someBean.instances}" var="instance">
    <h:inputText id="id" value="#{instance.value}">
        <f:validator validatorId="extendedRegexValidator" />
        <f:attribute name="pattern" value="#{instance.required ? instance.regexPattern : ''}" />
        <f:ajax event="change" execute="@this" listener="#{someBean.someMethodThatDoesntInvokeExtendedRegexValidator}"
        render="..."/>
    </h:inputText>
</ui:repeat>
<h:commandButton 
    action="#{someBean.someMethodThatDoesntInvokeExtendedRegexValidator}">
</h:commandButton>
<h:commandButton 
    action="#{someBean.someMethodThatInvokesExtendedRegexValidator}">
    <f:param name="validationRequiredFromRequest" value="true" />
</h:commandButton>
 * 
 * @version $Id$
 */
@FacesValidator("extendedRegexValidator")
public class ExtendedRegexValidator extends RegexValidator {
    
    private static final Logger log = Logger.getLogger(ExtendedRegexValidator.class);

    @Override
    public void validate(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        String pattern = (String) component.getAttributes().get("pattern");
        Map<String, String> params = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap();
        String validationRequiredFromRequest = params.get("validationRequiredFromRequest");
        if (log.isTraceEnabled()) {
            log.trace("validationRequiredFromRequest=" + validationRequiredFromRequest + ", pattern=" + pattern + ", clientId="
                    + component.getClientId() + ", value=" + value);
        }
     
        if(validationRequiredFromRequest == null || validationRequiredFromRequest.equalsIgnoreCase("false")){
            if(log.isTraceEnabled()){
                log.trace("Ignoring extendedRegexValidator for component " + component.getClientId());
            }
            return;
        }
        
        //Applying regex pattern
        if (pattern != null && !pattern.isEmpty()) {
            setPattern(pattern);
            super.validate(context, component, value);
        }
    }
}
