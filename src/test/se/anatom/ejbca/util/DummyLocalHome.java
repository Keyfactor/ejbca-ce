/*
 * Created on 2005-mar-08
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package se.anatom.ejbca.util;

import java.util.HashMap;

import javax.ejb.EJBException;
import javax.ejb.EJBLocalHome;
import javax.ejb.FinderException;
import javax.ejb.RemoveException;

/**
 * @author tomasg
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class DummyLocalHome implements EJBLocalHome{
    private HashMap map;
    public DummyLocalHome(HashMap map){
        this.map = map;
    }
    public DummyLocalHome(){
        this.map = null;
    }
    public Object findByPrimaryKey(Integer pk) throws FinderException {
        if (map == null) {
            return "";
        }
        Object o = map.get(pk);
        if (o == null) throw new FinderException("thrown on purpose to simulate non existing object");
        return o;
    }
    public void remove(Object o) throws RemoveException, EJBException {
    }
}
