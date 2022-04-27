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
package org.ejbca.ra;

import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.convert.Converter;
import javax.faces.convert.ConverterException;
import javax.faces.convert.FacesConverter;
import org.cesecore.util.ui.MultiLineString;
import org.cesecore.util.ui.UrlString;

/**
 * When using dynamic properties, JSF can't handle String conversions for some strange reason. This converter takes care of that. 
 * 
 * @version $Id$
 *
 */
@FacesConverter("stringConverter")
public class StringConverter implements Converter<Object> {

    @Override
    public Object getAsObject(FacesContext context, UIComponent component, String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        return value;
    }

    @Override
    public String getAsString(FacesContext context, UIComponent component, Object value) throws ConverterException {
        if (value == null) {
            return "";
        }
        if (value instanceof MultiLineString) {
            return ((MultiLineString) value).getValue();
        }
        if (value instanceof UrlString) {
            return ((UrlString) value).getValue();
        }
        return (String) value;
    }

}