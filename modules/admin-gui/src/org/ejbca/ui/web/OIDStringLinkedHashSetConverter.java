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

import java.util.LinkedHashSet;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.convert.Converter;
import javax.faces.convert.ConverterException;
import javax.faces.convert.FacesConverter;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;


/**
 * A JSF converter that converts a comma separated list of strings with OIDs (2.5.29.15,2.5.29.37,2.5.29.32,etc) into a LinkedHashSet<String>,
 * which is what is stored in CertificateProfiles
 * The converter makes validation on the OID inputs when converting String input to LinkedHashSet.
 * 
 * To Use:
 * <h:inputText ... converter="org.ejbca.OIDStringLinkedHashSetConverter"/>
 *  
 * @version $Id$
 */
@FacesConverter(value="org.ejbca.OIDStringLinkedHashSetConverter")
public class OIDStringLinkedHashSetConverter implements Converter<Object> {
    
    private static final Logger log = Logger.getLogger(OIDStringLinkedHashSetConverter.class);

    
    /** Input in the JSF page, convert to LinkedHashSet, which is what is used in the CertificateProfile to store in the database
     * 
     * @param values comma separated OIDs "1.1.1.1, 2.2.2.2", etc.
     * @return LinkedHashSet with the OID strings
     * @throws ConverterException if an input OID is not a valid OID, i.e. "1", or "3.3.3.3", etc
     */
    @Override
    public Object getAsObject(final FacesContext context, final UIComponent component, final String values) {
        return getSetFromString(values);
    }
    static Object getSetFromString(final String values) {
        // LinkedHashSet is the object used in CertificateProfile for these types of lists, must be Linked to maintain order
        // Null or empty input returned empty list
        if (StringUtils.isNotEmpty(values)) { 
            // Split on ',', remove null items, trim the values, check that each item is a valid OID, finally create a List
            final List<String> l = Stream.of(values.split(",", 0)).filter(e -> StringUtils.isNotBlank(e)).map(String::trim).filter(e -> isValidOID(e.trim())).collect(Collectors.toList());
            return new LinkedHashSet<String>(l);
        }
        return new LinkedHashSet<String>(); // never return null
    }
    private static boolean isValidOID(final String o) {
        try {
            // Just call constructor to make validation
            new ASN1ObjectIdentifier(o);
        } catch (IllegalArgumentException e) {
            if (log.isDebugEnabled()) {
                log.debug("'" + o + "' is not a valid OID: " + e.getMessage());
            }
            throw new ConverterException(new FacesMessage(FacesMessage.SEVERITY_ERROR, "The value '" + o + "' is not a valid OID.",""));                                        
        }
        return true;
    }

    /** Convert data that is stored in the CertificateProfile in the database, as a LinkedHashMap to regular String that is shown in the JSF page
     * 
     * @param value LinkedHashSet with the OID strings
     * @return String with comma separated OIDs "1.1.1.1, 2.2.2.2", etc.
     * @throws IllegalArgumentException if the contents of the database does not have the right objects "LinkedHashMap<String>"
     */
    @Override
    public String getAsString(final FacesContext context, final UIComponent component, final Object value) {
        return getStringFromSet(value);
    }
    // We don't do validation of the OID in this method, because the Set comes from our database and we don't want to break the Admin UI
    // because an admin put something bad in the database
    static String getStringFromSet(final Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof LinkedHashSet<?>) {
            final LinkedHashSet<?> oidSet = (LinkedHashSet<?>) value;
            // Allow non String values, for example if the database would contain LinkedHashSet<Integer>,
            // give it back to the Admin UI nicely, and it should be converted into the right type on next save, 
            // or throw a ConverterException prompting the user to enter a valid OID 
            return StringUtils.join(oidSet, ",");
        } else {
            throw new IllegalArgumentException( "Cannot convert " + value.getClass() + " object to LinkedHashSet in OIDStringLinkedHashSetConverter." );                
        }
    }
}