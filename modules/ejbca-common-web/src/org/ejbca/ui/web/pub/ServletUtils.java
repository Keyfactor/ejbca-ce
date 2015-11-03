package org.ejbca.ui.web.pub;

import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

/** 
 * A class containing some helpful functions used in more than one Servlet, avoiding code duplication.
 * 
 * @version $Id$
 */
public class ServletUtils {

    private static final Logger log = Logger.getLogger(ServletUtils.class);

    /** Helper methods that removes no-cache headers from a response. No-cache headers 
     * makes IE refuse to save a file that is sent (for example a certificate). 
     * No-cache headers are also automatically added by Tomcat by default, so we better
     * make sure they are set to a harmless value.
     * 
     * @param res HttpServletResponse parameter as taken from the doGet, doPost methods in a Servlet.
     */
    public static void removeCacheHeaders(final HttpServletResponse res) {
        if (res.containsHeader("Pragma")) {
            if (log.isDebugEnabled()) {
                log.debug("Removing Pragma header to avoid caching issues in IE");
            }
            res.setHeader("Pragma","null");
        }
        if (res.containsHeader("Cache-Control")) {
            if (log.isDebugEnabled()) {
                log.debug("Removing Cache-Control header to avoid caching issues in IE");
            }
            res.setHeader("Cache-Control","null");
        }
    }

    /** Helper methods that adds no-cache headers to a response. 
     * 
     * @param res HttpServletResponse parameter as taken from the doGet, doPost methods in a Servlet.
     */
    public static void addCacheHeaders(final HttpServletResponse res) {
        if (!res.containsHeader("Pragma")) {
            if (log.isDebugEnabled()) {
                log.debug("Adding Pragma header");
            }
            res.setHeader("Pragma","no-cache");
        }
        if (!res.containsHeader("Cache-Control")) {
            if (log.isDebugEnabled()) {
                log.debug("Adding Cache-Control header");
            }
            res.setHeader("Cache-Control","no-cache");
        }
    }
}
