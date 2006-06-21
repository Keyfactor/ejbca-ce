package org.ejbca.util;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;


/** An implementation of HashMap that base64 decodes all String's that you 'get', 
 * if they start with 'B64', i.e. it base64 decodes string of form "B64:<base64 encoded string>".
 * It only tries to decode objects of type String.
 *  
 * @author tomasg
 * @version $Id: Base64GetHashMap.java,v 1.2 2006-06-21 10:46:44 anatom Exp $
 */
public class Base64GetHashMap extends HashMap {
    public Base64GetHashMap() {
        super();
    }
    public Base64GetHashMap(Map m) {
        super(m);
    }
    
    public Object get(Object key) {
        Object o = super.get(key);
        if (o == null) {
            return o;
        }
        if (o instanceof String) {
            String s = (String) o;
            if (StringUtils.isEmpty(s)) {
                return o;
            }
            String s1 = null;
            if (s.startsWith("B64:")) {
                s1 = s.substring(4);
                String n = null;
                try {
                    n = new String(Base64.decode(s1.getBytes("UTF-8")));
                } catch (UnsupportedEncodingException e) {
                    n = s;
                } catch (ArrayIndexOutOfBoundsException e) {
                    // We get this if we try to decode something that is not base 64
                    n = s;
                }
                return n;
            }
            return s;                       
        }
        return o;
    }
}
