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
package org.ejbca.ui.web.admin.ca;

import java.io.IOException;

import javax.faces.FacesException;
import javax.faces.context.FacesContext;

import org.apache.commons.lang.StringUtils;
import org.apache.myfaces.custom.fileupload.UploadedFile;

/**
 * 
 * @version $Id$
 *
 */
public final class EditCaUtil {
    
    public static final String MANAGE_CA_NAV = "managecas";
    public static final String EDIT_CA_NAV = "editcapage";
    public static final String SIGN_CERT_REQ_NAV = "recievefile";
    public static final String DISPLAY_RESULT_NAV = "displayresult";
    public static final int CERTREQGENMODE = 0;
    public static final int CERTGENMODE = 1;
    public static final String DEFAULT_KEY_SIZE = "2048";
    public static final String LINK_CERT_BASE_URI = "cacertreq?cmd=linkcert&";
    public static final String CA_EXPORT_PATH = "/ca/exportca";
    public static final String TEXTFIELD_EXPORTCA_PASSWORD = org.ejbca.ui.web.admin.cainterface.CAExportServlet.TEXTFIELD_EXPORTCA_PASSWORD;
    public static final String HIDDEN_CANAME = org.ejbca.ui.web.admin.cainterface.CAExportServlet.HIDDEN_CANAME;
    
    public static String getTrimmedName(final String name) {
        if (name != null && !name.isEmpty()) {
            return name.replaceAll("\\([^()]*\\)", StringUtils.EMPTY).replaceAll(", ", StringUtils.EMPTY);
        } else {
            return StringUtils.EMPTY;
        }
    }
    
    public static void navigateToManageCaPageIfNotPostBack() {
        if (!FacesContext.getCurrentInstance().isPostback()) {
            try {
                FacesContext.getCurrentInstance().getExternalContext().redirect(EditCaUtil.MANAGE_CA_NAV + ".xhtml");
            } catch (IOException e) {
                throw new FacesException("Cannot redirect to " + EditCaUtil.MANAGE_CA_NAV + " due to IO exception.", e);
            }
        }         
    }
    
    public static byte[] getUploadedFileBuffer(final UploadedFile uploadedFile) {
        byte[] fileBuffer = null;
        if (uploadedFile != null) {
            try {
                fileBuffer = uploadedFile.getBytes();
            } catch (IOException e) {
                throw new FacesException("Can not get uploaded file buffer due to IO exception.", e);
            }
        }
        return fileBuffer;
    }
}
