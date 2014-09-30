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
package org.ejbca.ui.web;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

/**
 * A map of parameters that implements the usual HttpServletRequest methods.
 * Used by HttpUploads.
 * 
 * @version $Id$
 */
public class ParameterMap extends HashMap<String,String[]> {

    private static final long serialVersionUID = 1L;
    
    public ParameterMap() {
        super();
    }
    
    public ParameterMap(Map<String,String[]> map) {
        super(map);
    }
    
    public String getParameter(String name) {
        String[] values = get(name);
        if (values == null || values.length == 0) {
            return null;
        }
        
        return StringUtils.join(values, ";");
    }
    
    public String[] getParameterValues(String name) {
        return get(name);
    }
    
    public boolean contains(String name) {
        return containsKey(name);
    }
    
}
