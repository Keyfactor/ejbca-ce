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

}
