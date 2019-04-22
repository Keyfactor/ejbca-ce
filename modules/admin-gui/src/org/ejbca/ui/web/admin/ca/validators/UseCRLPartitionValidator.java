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

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.component.UIInput;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

/**
 * Validator used in validating useCrlPartition conditions (edit ca page).
 *
 * @version $Id$
 */
@FacesValidator("org.ejbca.ui.web.admin.ca.validators.UseCRLPartitionValidator")
public class UseCRLPartitionValidator implements Validator {

    @Override
    public void validate(FacesContext facesContext, UIComponent component, Object o) throws ValidatorException {
        Boolean usePartitionedCrl = (Boolean) o;
        if (usePartitionedCrl) {
            UIInput defaultCRLDistPointInput = (UIInput) component.getAttributes().get("defaultCRLDistPointInput");
            Object submittedValue = defaultCRLDistPointInput.getSubmittedValue();
            String defaultCRLDistPoint = submittedValue == null ? (String) defaultCRLDistPointInput.getValue() : submittedValue.toString();
            UIInput useCrlDistributiOnPointOnCrlInput = (UIInput) component.getAttributes().get("useCrlDistributiOnPointOnCrl");
            Boolean useCrlDistributiOnPointOnCrl = (Boolean) useCrlDistributiOnPointOnCrlInput.getValue();

            if (!useCrlDistributiOnPointOnCrl || StringUtils.isEmpty(defaultCRLDistPoint)) {
                FacesMessage msg = new FacesMessage("Partitioned CRLs are not allowed without 'Issuing Distribution Point' and 'Default CRL Distribution Point'.", "Use CRL partition validation failed!");
                msg.setSeverity(FacesMessage.SEVERITY_ERROR);
                throw new ValidatorException(msg);
            }
            if (!defaultCRLDistPoint.contains("*")) {
                FacesMessage msg = new FacesMessage("'Default CRL Distribution Point' should contain asterisk (*) with Partitioned CRLs .", "Use CRL partition validation failed!");
                msg.setSeverity(FacesMessage.SEVERITY_ERROR);
                throw new ValidatorException(msg);
            }
        }
    }
}
