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

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.convert.Converter;
import javax.faces.convert.ConverterException;
import javax.faces.convert.FacesConverter;


/**
 * A JSF converter that makes it possible to input a comma separated list of Oids Strings (2.5.29.15,2.5.29.37,2.5.29.32,etc) and store it into an LinkedHashSet<String>.
 * The converter makes validation that it is Oids Strings that are input.
 * 
 * To Use:
 * <h:inputText ... converter="org.ejbca.OidsObjectLinkedHashSetConverter"/>
 *  
 * @version $Id$
 */
@FacesConverter(value="org.ejbca.OidsObjectLinkedHashSetConverter")
public class OidsObjectLinkedHashSetConverter implements Converter {
    final String oid_pattern = "^[0-9]+(\\.?[0-9]+)*$";
    
    @Override
    public Object getAsObject(final FacesContext context, final UIComponent component, final String values) {

        final LinkedHashSet<String> result = new LinkedHashSet<String>(); 
        for (String value : values.split(",", 0)) {           
            final String trimmedValue = value.trim();
            if (!trimmedValue.isEmpty()) {
                // Validate the OID object here, as this is called when we save the value from the GUI
                if(!trimmedValue.matches(oid_pattern)){                
                    throw new ConverterException(new FacesMessage(FacesMessage.SEVERITY_ERROR, "The value '" + value + "' is not a valid OID object.",""));                
                }
                result.add(trimmedValue);
            }
        }       
        return result;
    }

    @Override
    public String getAsString(final FacesContext context, final UIComponent component, final Object value) {
        if (value instanceof LinkedHashSet<?>) {
            final StringBuffer result = new StringBuffer();

            final LinkedHashSet<String> lhs = (LinkedHashSet<String>) value;
            final List<?> list = new ArrayList<String>(lhs);

            for (int i = 0; i < list.size(); i++) {               
                if (list.get(i) instanceof String) {
                    result.append(list.get(i));
                    if (i < list.size()-1) {
                        result.append(", ");
                    }
                } else {
                    throw new IllegalArgumentException( "Cannot convert " + value + " object to String in OidsObjectLinkedHashSetConverter." );
                }
            }
            return result.toString();
        } else {
            throw new IllegalArgumentException( "Cannot convert " + value + " object to List in OidsObjectLinkedHashSetConverter." );
        }
    }
}