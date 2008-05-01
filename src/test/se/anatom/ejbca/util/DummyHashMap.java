package se.anatom.ejbca.util;

import java.util.HashMap;

/**
 * @author tomasg
 * @version $Id$
 */
public class DummyHashMap extends HashMap {
    public Object get(Object key) {
        return "dummy";
    }
}
