
package se.anatom.ejbca.util;


/** This class implements some utility functions that are useful when handling Strings.
 *
 * @version $Id: StringTools.java,v 1.6 2003-03-15 21:54:30 herrvendil Exp $
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
                ret = ret.replace(stripChars[i], '_');
            }
        }
        return ret;
    }

} // StringTools

