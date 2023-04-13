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

package org.ejbca.ui.web.admin.ca.validators;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

import com.keyfactor.util.StringTools;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * JSF validator to check that input fields are valid urls while allowing for quotation marks
 */
@FacesValidator("org.ejbca.ui.web.admin.ca.validators.CrlDistributionPointUrlValidator")
public class CrlDistributionPointUrlValidator implements Validator<Object> {
    private static final Logger log = Logger.getLogger(CrlDistributionPointUrlValidator.class);

    @Override
    public void validate(FacesContext facesContext, UIComponent uiComponent, Object o) throws ValidatorException {
        if (o == null) {
            return;
        } else if (!(o instanceof String)) {
            log.warn("Wrong type passed to validator");
            throw makeException(uiComponent);
        }
        final String urlValue = (String) o;
        if (StringUtils.isEmpty(urlValue)) {
            return;
        }
        if (log.isDebugEnabled()) {
            log.debug("Validating component " + uiComponent.getClientId(facesContext) + " with value \"" + urlValue + "\"");
        }
        // There can be more than one URL.
        // In that case, they are separated by semicolon.
        // URLs with semicolons must be double-quoted.
        for (final String url : StringTools.splitURIs(urlValue)) {
            checkUrl(uiComponent, url);
        }
    }

    protected void checkUrl(final UIComponent uiComponent, final String url) {
        if (url.toString().indexOf(':') == -1) {
            if (log.isDebugEnabled()) {
                log.debug("CDP URL \"" + url + "\" is missing the colon!");
            }
            throw makeException(uiComponent);
        } else {
            try {
                new URI(url.toString());
            } catch (URISyntaxException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid syntax of CDP URL \"" + url + "\": " + e.getMessage(), e);
                }
                throw makeException(uiComponent);
            }
        }
    }

    public ValidatorException makeException(final UIComponent uiComponent) {
        String msg = (String) uiComponent.getAttributes().get("errorMessage");
        if (StringUtils.isEmpty(msg)) {
            msg = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("INVALIDURL");
        }
        throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
    }
}
