
package se.anatom.ejbca.util;


/** This class implements some utility functions that are useful when handling Strings.
 *
 * @version $Id: StringTools.java,v 1.7 2003-03-15 22:38:02 herrvendil Exp $
 */
public class StringTools {

    static public final char stripChars[] = {
        '\'','\"','\n','\r','/','\\',';','&','|','!','\0','%','`','?','<','>','?','$',':','~'
    };

    /** Strips all special signs from a String by replacing them with a forward slash, '/'.
     *@param str the string whose contents will be stripped.
     *@return the stripped version of the input string.
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

