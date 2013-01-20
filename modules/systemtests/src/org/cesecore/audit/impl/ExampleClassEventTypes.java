/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.audit.impl;

import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypeHolder;

/**
 * 
 * @version $Id$
 *
 */
public class ExampleClassEventTypes implements EventType {
    
    private static final long serialVersionUID = 1937482572926091659L;
    public static final EventType NEW_EVENT_TYPE_CLASS = new EventTypeHolder("NEW_EVENT_TYPE_CLASS");
    
    @Override
    public boolean equals(EventType value) {
        if(value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }
}
