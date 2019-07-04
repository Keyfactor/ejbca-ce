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
package org.ejbca.util;

/**
 * This class contains URI manipulation methods.
 *
 * @version $Id$
 */
public class URIUtil {

    /**
     * Returns the base URI of the application as 'URI = scheme:[//authority]path/', where authority = [userinfo@]host[:port].
     *
     * @param scheme A connection scheme, eg. http, https.
     * @param host A host, consisting of either a registered name (including but not limited to a hostname), or an IP address.
     *             IPv4 addresses must be in dot-decimal notation, and IPv6 addresses might be enclosed in brackets ([]).
     * @param port A port number, eg. 80, 443, 8080, 8443.
     * @param path An application name (path).
     *
     * @return The server URI, eg. https://my-domain-does-not-exist.abc:443/my-application-path/
     */
    public static String getApplicationUri(final String scheme, final String host, final int port, final String path) {
        return scheme + "://" + getIPv6CompatibleHostIp(host) + ":" + port + "/" + path + "/";
    }

    /**
     * Checks an input host whether it is an IPv6 IP address and return it with square brackets if needed,
     * otherwise returns the unchanged host.
     *
     * @param host A host, consisting of either a registered name (including but not limited to a hostname), or an IP address.
     *             IPv4 addresses must be in dot-decimal notation, and IPv6 addresses might be enclosed in brackets ([]).
     *
     * @return The host compatible with IPv6.
     */
    public static String getIPv6CompatibleHostIp(final String host) {
        if(isIPv6HostIp(host)) {
            return getIPv6HostIp(host);
        }
        return host;
    }

    // Checks whether a host has a colon, means this host is presented as an IPv6 IP address.
    private static boolean isIPv6HostIp(final String host) {
        return host != null && host.contains(":");
    }

    // Encloses the host (IP) with square brackets (to have IPv6 compatible IP) if an input does not have opening and closing bracket.
    // Reference: https://tools.ietf.org/html/rfc3986#section-3.2.2
    private static String getIPv6HostIp(final String host) {
        if(host != null && !host.startsWith("[") && !host.endsWith("]")) {
            return "[" + host + "]";
        }
        return host;
    }

}
