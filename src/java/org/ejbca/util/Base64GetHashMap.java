package org.ejbca.util;

import java.util.HashMap;
import java.util.Map;


/** An implementation of HashMap that base64 decodes all String's that you 'get', 
 * if they start with 'B64', i.e. it base64 decodes string of form "B64:<base64 encoded string>".
 * It only tries to decode objects of type String.
 *  
 * @author tomasg
 * @version $Id: Base64GetHashMap.java,v 1.3 2006-06-21 14:54:56 anatom Exp $
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
            return StringTools.getBase64String(s);                       
        }
        return o;
    }
    
}
