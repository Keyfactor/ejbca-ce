/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.admin.configuration;

import org.ejbca.ui.web.jsf.configuration.EjbcaJSFImageResource;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJBException;

/**
 * Class used to retrieve EJBCA image resources in JSF views
 * 
 * Implements a Map used for retrieving resources.
 * @version $Id$
 * @see org.ejbca.ui.web.jsf.configuration.EjbcaWebBean#getImagefileInfix(String)
 */
public class EjbcaJSFImageResourceImpl implements EjbcaJSFImageResource {

    private EjbcaWebBean ejbcawebbean;
    
    public EjbcaJSFImageResourceImpl(EjbcaWebBean ejbcawebbean){
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
