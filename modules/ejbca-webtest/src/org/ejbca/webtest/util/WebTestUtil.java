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
package org.ejbca.webtest.util;

import java.time.ZoneId;
import java.time.ZonedDateTime;

/**
 * This class contains utility methods for web tests.
 *
 * @version $Id$
 */
public abstract class WebTestUtil {

    /**
     * Returns the request URI path (URI = scheme:[//authority]path[?query][#fragment]) without:
     * <ul>
     *     <li>Scheme and authority eg. 'https:localhost:8443';</li>
     *     <li>Duplicated slash eg. '//' (Temporary);</li>
     *     <li>Session identifier eg. ';jsessionid=1234567890';</li>
     *     <li>Query eg. '?param1=a&param2=b';</li>
     *     <li>Fragment eg. '#top';</li>
     * </ul>
     * <br/>
     * An example: <br/>
     * <ul>
     *     <li>'/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml' from 'https://localhost:8443/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml'</li>
     *     <li>'/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml' from 'https://localhost:8443/ejbca/adminweb//ca/editcertificateprofiles/editcertificateprofiles.xhtml;jsessionid=CwN+cVjtwFRVth+sm9SvU-CW'</li>
     *     <li>'/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml' from 'https://localhost:8443/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml;jsessionid=CwN+cVjtwFRVth+sm9SvU-CW?param1=a'</li>
     * </ul>
     *
     *
     * @param url a web URL.
     *
     * @return the URI path of web URL.
     */
    public static String getUriPathFromUrl(final String url) {
        // URI = scheme:[//authority]path[?query][#fragment]
        String uri = url;
        if(url != null && url.length() > 0) {
            final int ejbcaIndex = url.indexOf("/ejbca");
            if (ejbcaIndex != -1) {
                uri = url.substring(ejbcaIndex);
                // TODO Temporary
                uri = uri.replaceAll("//", "/");
                final int questionMarkIndex = uri.indexOf('?');
                uri = (questionMarkIndex == -1 ? uri : uri.substring(0, questionMarkIndex));
                final int semicolonIndex = uri.indexOf(';');
                uri = (semicolonIndex == -1 ? uri : uri.substring(0, semicolonIndex));
                final int numberSignIndex = uri.indexOf('#');
                uri = (numberSignIndex == -1 ? uri : uri.substring(0, numberSignIndex));
            }
        }
        return uri;
    }

    /**
     * Returns a UTC ZonedDateTime instance with possible offsets, eg:
     * <ul>
     *     <li>offsetYear = -1, minus 1 year from current date;</li>
     *     <li>offsetYear = 0, current year unchanged;</li>
     *     <li>offsetYear = 1, plus 1 year from current date;</li>
     *     <li>offsetMonth = -1, minus 1 month from current date;</li>
     *     <li>offsetMonth = 0, current month unchanged;</li>
     *     <li>offsetMonth = 1, plus 1 month from current date;</li>
     *     <li>offsetDay = -1, minus 1 day from current date;</li>
     *     <li>offsetDay = 0, current day unchanged;</li>
     *     <li>offsetDay = 1, plus 1 day from current date;</li>
     * </ul>
     * <br/>
     * <b>An example 1</b>:
     * <br/>
     * <pre>
     *     Current date is 2020-12-31T01:02:03.456Z:
     *     getLocalDate(0, 0, 0);
     *     will return 2020-12-31T01:02:03.456Z
     * </pre>
     * <b>An example 2</b>:
     * <br/>
     * <pre>
     *     Current date is 2020-12-31T01:02:03.456Z:
     *     getLocalDate(-1, 0, 0);
     *     will return 2019-12-31T01:02:03.456Z
     * </pre>
     * <b>An example 3</b>:
     * <br/>
     * <pre>
     *     Current date is 2020-12-31T01:02:03.456Z:
     *     getLocalDate(0, -13, 0);
     *     will return 2019-11-30T01:02:03.456Z
     * </pre>
     *
     * @param offsetYear year offset.
     * @param offsetMonth month offset.
     * @param offsetDay day offset.
     *
     * @return UTC ZonedDateTime instance.
     */
    public static ZonedDateTime getUtcLocalDateTime(int offsetYear, int offsetMonth, int offsetDay) {
        ZonedDateTime zonedDateTime = ZonedDateTime.now(ZoneId.of("UTC"));
        if(offsetYear != 0) {
            zonedDateTime = zonedDateTime.plusYears(offsetYear);
        }
        if(offsetMonth != 0) {
            zonedDateTime = zonedDateTime.plusMonths(offsetMonth);
        }
        if(offsetDay != 0) {
            zonedDateTime = zonedDateTime.plusDays(offsetDay);
        }
        return zonedDateTime;
    }
}
