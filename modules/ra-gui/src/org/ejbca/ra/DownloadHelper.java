/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ra;

import java.io.IOException;
import java.io.OutputStream;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;

import com.keyfactor.util.StringTools;

/**
 * Helper function for sending downloads to the client.
 */
public class DownloadHelper {

    // Factored out from EnrollWithRequestId.downloadToken
    public static void sendFile(final byte[] contents, final String contentType, final String filename) throws IOException {
        final FacesContext fc = FacesContext.getCurrentInstance();
        final ExternalContext ec = fc.getExternalContext();
        ec.responseReset(); // Some JSF component library or some Filter might have set some headers in the buffer beforehand. We want to get rid of them, else it may collide.
        ec.setResponseContentType(contentType);
        ec.setResponseContentLength(contents.length);

        final String strippedFilename = StringTools.stripFilename(filename);
        ec.setResponseHeader("Content-Disposition", "attachment; filename=\"" + strippedFilename + "\""); // The Save As popup magic is done here. You can give it any file name you want, this only won't work in MSIE, it will use current request URL as file name instead.
        try (final OutputStream output = ec.getResponseOutputStream()) {
            output.write(contents);
            output.flush();
            fc.responseComplete(); // Important! Otherwise JSF will attempt to render the response which obviously will fail since it's already written with a file and closed.
        }
    }

}
