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
public class PartitionedCrlUrlValidator extends CrlDistributionPointUrlValidator implements Validator<Object> {

    @Override
    protected void checkUrl(final UIComponent uiComponent, final String url) throws ValidatorException {
        super.checkUrl(uiComponent, url);
        if (url.indexOf('*') == -1) {
            final String message = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("PARTITIONEDCRLS_WITHOUT_ASTERISK");
            FacesMessage msg = new FacesMessage(message, null);
            msg.setSeverity(FacesMessage.SEVERITY_ERROR);
            throw new ValidatorException(msg);
        }
    }
}
