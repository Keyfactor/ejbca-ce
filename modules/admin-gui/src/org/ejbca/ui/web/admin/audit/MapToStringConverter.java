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
package org.ejbca.ui.web.admin.audit;

import java.util.Map;

import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.convert.Converter;
import javax.faces.convert.FacesConverter;

/**
 * One way converter from Map<Object,Object> to String.
 */
@FacesConverter("mapToStringConverter")
public class MapToStringConverter implements Converter<Object> {

	@Override
	public Object getAsObject(final FacesContext facesContext, final UIComponent uiComponent, final String value) {
		return value;
	}

	@SuppressWarnings("unchecked")
    @Override
	public String getAsString(final FacesContext facesContext, final UIComponent uiComponent, final Object value) {
	    if (value instanceof String) {
            return (String)value;
        }
		return getAsString((Map<String, Object>)value);
	}
	
    public static String getAsString(final Map<String,Object> map) {
        final StringBuilder sb = new StringBuilder();
        if (map.size() == 1 && map.containsKey("msg")) {
            final String ret = (String) map.get("msg");
            if (ret != null) {
                return ret;
            }
        }
        for (final Object key : map.keySet()) {
            if (sb.length()!=0) {
                sb.append("; ");
            }
            sb.append(key).append('=').append(map.get(key));
        }
        return sb.toString();
    }
}
