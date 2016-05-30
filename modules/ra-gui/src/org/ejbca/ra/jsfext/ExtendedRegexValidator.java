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

import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.RegexValidator;
import javax.faces.validator.ValidatorException;

/**
 * Extended variant of RegexValidator handy to be used when regex pattern value is going to be evaluated during
 * view render time, which is the use-case for many UI components like h:dataTable and ui:repeat.
 * Example usage:
<ui:repeat value="#{someBean.getInstances()}" var="instance">
    <h:inputText id="id" value="#{instance.value}">
        <f:validator validatorId="extendedRegexValidator" />
        <f:attribute name="pattern" value="#{instance.getRegexPattern()}" />
    </h:inputText>
</ui:repeat>
 * 
 * @version $Id$
 */
@FacesValidator("extendedRegexValidator")
public class ExtendedRegexValidator extends RegexValidator {
    @Override
    public void validate(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        String pattern = (String) component.getAttributes().get("pattern");
        if (pattern != null) {
            setPattern(pattern);
            super.validate(context, component, value);
        }
    }
}
