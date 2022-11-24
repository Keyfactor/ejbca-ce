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
package org.ejbca.ui.web.rest.api.io.request;

import static org.ejbca.ui.web.rest.api.config.JsonDateSerializer.DATE_FORMAT_ISO8601;

import java.text.ParseException;
import java.util.Date;

import javax.ws.rs.core.Response;

import org.ejbca.ui.web.rest.api.exception.RestException;

/**
 * Helper class for search certificates REST requests.
 */
public class SearchCertificatesRestRequestUtil {

    /**
     * Returns the date by the date string or throws a RestException if the string cannot be parsed.
     * 
     * @param dateString the ISO8601 date string.
     * @return the date object, never null.
     * @throws RestException if the date string cannot be parsed.
     */
    public static Date parseDateFromStringValue(final String dateString) throws RestException {
        try {
            return DATE_FORMAT_ISO8601.parse(dateString);
        }
        catch (ParseException pEx) {
            throw new RestException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "Cannot handle the request", pEx);
        }
    }

}
