
package se.anatom.ejbca.util;

import java.io.*;

/** This class implements some utility functions that are useful when handling Strings.
 *
 * @version $Id: StringTools.java,v 1.3 2002-09-25 11:39:44 anatom Exp $
 */
public class StringTools {

    static public final char stripChars[] = {
        '\'','\"','\n','\r','/','\\',';','&','|','!','\0','%','`','´','<','>','?','$',':','~'
    };

    /** Strips all specialsigns from a String by replacing them with a forward slash, '/'.
     *
     *
     *@param str the string whose contents will be stripped.
     *@return the stripped version of the input string.
     *@see strip
     **/
    public static String strip(String str) {
        if (str == null)
            return null;
        String ret = str;
        for (int i=0; i<stripChars.length; i++) {
            if (ret.indexOf(stripChars[i]) > -1) {
                ret = ret.replace(stripChars[i], '/');
            }
        }
        return ret;
    }

} // StringTools

