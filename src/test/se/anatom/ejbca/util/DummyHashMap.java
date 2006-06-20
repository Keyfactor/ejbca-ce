package se.anatom.ejbca.util;

import java.util.HashMap;

/**
 * @author tomasg
 * @version $Id: DummyHashMap.java,v 1.2 2006-06-20 13:06:43 anatom Exp $
 */
public class DummyHashMap extends HashMap {
    public Object get(Object key) {
        return "dummy";
    }
}
