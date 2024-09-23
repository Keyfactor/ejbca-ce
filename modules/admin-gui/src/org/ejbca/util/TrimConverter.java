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
package org.ejbca.util;

import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;
import jakarta.faces.convert.Converter;
import jakarta.faces.convert.ConverterException;
import jakarta.faces.convert.FacesConverter;

import org.apache.commons.lang.StringUtils;

/**
 * JSF converter that trims strings  
 * 
 * @version $Id$
 */
@FacesConverter("trimConverter")
public class TrimConverter implements Converter<Object> {

    @Override
    public Object getAsObject(final FacesContext context, final UIComponent component, final String value) {
        return StringUtils.trim(value);
    }

    @Override
    public String getAsString(final FacesContext context, final UIComponent component, final Object value) throws ConverterException {
        if (value == null) {
            return "";
        }
        return (String) value;
    }
}

