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
