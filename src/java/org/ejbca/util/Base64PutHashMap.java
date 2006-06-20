package org.ejbca.util;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;


/** An implementation of HashMap that base64 encodes all String's that you 'put', 
 * it encodes them to form "B64:<base64 encoded string>". It only encodes objects of type String.
 * 
 * @author tomasg
 * @version $Id: Base64PutHashMap.java,v 1.1 2006-06-20 13:06:43 anatom Exp $
 */
public class Base64PutHashMap extends HashMap {
    public Base64PutHashMap() {
        super();
    }
    public Base64PutHashMap(Map m) {
        super(m);
    }
    public Object put(Object key, Object value) {
        if (value instanceof String) {
            String s = (String) value;
            if (s.startsWith("B64:")) {
                // Only encode once
                return super.put(key, value);
            }
            String n = null;
            try {
                n="B64:"+new String(Base64.encode(s.getBytes("UTF-8"), false));
            } catch (UnsupportedEncodingException e) {
                // Do nothing
                n=s;
            }
            return super.put(key,n);
        }
        return super.put(key, value);
    }
}
