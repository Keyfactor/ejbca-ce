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
package org.ejbca.ui.web.admin.keybind;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;
import javax.servlet.http.Part;

import org.apache.log4j.Logger;

@FacesValidator(value = "keyBindingFileUploadValidator")
public class KeyBindingFileUploadValidator implements Validator<Object> {

    private static final Logger log = Logger.getLogger(KeyBindingFileUploadValidator.class);

    private static final int MAX_FILE_SIZE = 10000000; // In bytes
    private static final int MAX_FILE_NAME_LENGTH = 256;

    @Override
    public void validate(FacesContext context, UIComponent component, Object value) throws ValidatorException {

        final Part uploadedFile = (Part) value;

        FacesMessage errorMessage = null;
        
        try {

            if (uploadedFile == null || uploadedFile.getSize() <= 0 || uploadedFile.getContentType().isEmpty()) {
                errorMessage = new FacesMessage("Select a valid file");
                if (log.isDebugEnabled()) {
                    log.debug("Null, empty or mallformed certificate file uploaded.");
                }
            } else if (uploadedFile.getName().length() > MAX_FILE_NAME_LENGTH) {
                errorMessage = new FacesMessage("Selected file name too long. Allowed file name is less than or equal to 256 characters.");
                if (log.isDebugEnabled()) {
                    log.debug("Certificate file uploaded has a name longer than allowed length (256 characters).");
                }
            } else if (uploadedFile.getSize() > MAX_FILE_SIZE) {
                errorMessage = new FacesMessage("Selected file is too big. Allowed file size is less than or equal to 10 MB.");
                if (log.isDebugEnabled()) {
                    log.debug("Certificate file uploaded is bigger than allowed max size (10 MB).");
                }
            }

            if (errorMessage != null && !errorMessage.getDetail().isEmpty()) {
                errorMessage.setSeverity(FacesMessage.SEVERITY_ERROR);
                throw new ValidatorException(errorMessage);
            }

        } catch (Exception ex) {
            throw new ValidatorException(new FacesMessage(ex.getMessage()));
        }
    }
}