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

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * Validator used for validating CRL DP URLs with partition number placeholders (edit ca page).
 *
 * @version $Id$
 */
@FacesValidator("org.ejbca.ui.web.admin.ca.validators.PartitionedCrlUrlValidator")
public class PartitionedCrlUrlValidator implements Validator<Object> {

    @Override
    public void validate(FacesContext facesContext, UIComponent component, Object o) throws ValidatorException {
        final String crlDistributionPointUrl = (String) o;
        if (crlDistributionPointUrl == null || crlDistributionPointUrl.indexOf('*') == -1) {
            final String message = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("PARTITIONEDCRLS_WITHOUT_ASTERISK");
            FacesMessage msg = new FacesMessage(message, null/*"Use CRL partition validation failed!"*/);
            msg.setSeverity(FacesMessage.SEVERITY_ERROR);
            throw new ValidatorException(msg);
        }
    }
}
