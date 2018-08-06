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

import java.io.Serializable;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Set;

import javax.faces.model.SelectItem;

import org.apache.commons.lang.ObjectUtils;
import org.apache.log4j.Logger;

/**
 * Comparator for sorting select items by displayed name.  
 * @version $Id$
 */
public class SelectItemComparator implements Comparator<SelectItem>, Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(SelectItemComparator.class);
    
    private final Set<Object> specialObjects;
    
    public SelectItemComparator() {
        this(new Object[0]);
    }
    
    /** specialObjects will be placed first. Typically these will be IDs */ 
    public SelectItemComparator(Object... specialObjects) {
        this.specialObjects = new HashSet<>(Arrays.asList(specialObjects));
    }

    @Override
    public int compare(SelectItem o1, SelectItem o2) {
        final boolean special1 = specialObjects.contains(o1.getValue());
        final boolean special2 = specialObjects.contains(o2.getValue());
        if (log.isTraceEnabled()) {
            log.trace("compare(" + o1.getLabel() + "," + o2.getLabel() + "). 1 is special: " + special1 + ",  2 is special: " + special2 + ",  value comparison: " + ObjectUtils.compare(o1.getLabel(), o2.getLabel()));
        }
        if (special1 == special2) {
            if (o1.getLabel() == null && o2.getLabel() == null) { return 0; }
            else if (o1.getLabel() == null) { return -1; }
            else if (o2.getLabel() == null) { return 1; }
            else { return o1.getLabel().compareToIgnoreCase(o2.getLabel()); }
        } else if (special1) {
            return -1;
        } else {
            return 1;
        }
    }
    
}
