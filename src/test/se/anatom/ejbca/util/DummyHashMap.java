/*
 * Created on 2005-mar-08
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package se.anatom.ejbca.util;

import java.util.HashMap;

/**
 * @author tomasg
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class DummyHashMap extends HashMap {
    public Object get(Object key) {
        return "dummy";
    }
}
