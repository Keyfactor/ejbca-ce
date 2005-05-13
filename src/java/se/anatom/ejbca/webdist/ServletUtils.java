package se.anatom.ejbca.webdist;

import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;

/** 
 * A class containing some helpful functions used in more than one servlet, avoiding code duplication.
 * 
 * @author tomasg
 * @version $Id: ServletUtils.java,v 1.1 2005-05-13 06:51:47 anatom Exp $
 */
public class ServletUtils {

    private static Logger log = Logger.getLogger(ServletUtils.class);

    /** Helper methods that removes no-cache headers from a response. No-cache headers 
     * makes IE refuse to save a file that is sent (for exmaple a certificate). 
     * No-cache headers are also autmatically added by Tomcat by default, so we better
     * make sure they are set to a harmless value.
     * 
     * @param res HttpServletResponse parameter as taken from the doGet, doPost methods in a Servlet.
     */
    public static void removeCacheHeaders(HttpServletResponse res) {
        if (res.containsHeader("Pragma")) {
            log.debug("Removing Pragma header to avoid caching issues in IE");
            res.setHeader("Pragma","null");
        }
        if (res.containsHeader("Cache-Control")) {
            log.debug("Removing Cache-Control header to avoid caching issues in IE");
            res.setHeader("Cache-Control","null");
        }
    }
}
