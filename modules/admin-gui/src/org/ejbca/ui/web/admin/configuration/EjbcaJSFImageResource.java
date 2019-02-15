package org.ejbca.ui.web.admin.configuration;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJBException;

/**
 * Class used to retrieve EJBCA image resources in JSF views
 * 
 * Implements a Map used for retrieving resources.
 * @version $Id$
 * @see org.ejbca.ui.web.admin.configuration.EjbcaWebBean#getImagefileInfix(String)
 */
public class EjbcaJSFImageResource implements org.ejbca.ui.web.jsf.configuration.EjbcaJSFImageResource {

    private org.ejbca.ui.web.jsf.configuration.EjbcaWebBean ejbcawebbean;
    
    public EjbcaJSFImageResource(org.ejbca.ui.web.jsf.configuration.EjbcaWebBean ejbcawebbean){
        this.ejbcawebbean = ejbcawebbean;
    }
    
    @Override
    public void clear() {
        throw new EJBException("Method clear not supported");
    }

    @Override
    public boolean containsKey(Object arg0) {      
        return ejbcawebbean.getImagefileInfix((String) arg0) != null;
    }

    @Override
    public boolean containsValue(Object arg0) {
        throw new EJBException("Method containsValue not supported");
    }

    @Override
    public Set<Entry<String, String>> entrySet() {
        throw new EJBException("Method entrySet not supported");
    }

    @Override
    public String get(Object arg0) {
        return ejbcawebbean.getImagefileInfix((String) arg0);
    }

    @Override
    public boolean isEmpty() {
        throw new EJBException("Method isEmpty not supported");
    }

    @Override
    public Set<String> keySet() {
        throw new EJBException("Method keySet not supported");
    }

    @Override
    public String put(String arg0, String arg1) {
        throw new EJBException("Method put not supported");
    }

    @Override
    public void putAll(Map<? extends String, ? extends String> arg0) {
        throw new EJBException("Method putAll not supported");
    }

    @Override
    public String remove(Object arg0) {
        throw new EJBException("Method remove not supported");
    }

    @Override
    public int size() {
        throw new EJBException("Method size not supported");
    }

    @Override
    public Collection<String> values() {
        throw new EJBException("Method values not supported");
    }

}
