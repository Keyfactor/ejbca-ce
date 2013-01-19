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

/**
 * Example class on how EventTypes can be extended.
 * 
 * @version $Id$
 */
public enum ExampleEnumEventTypes implements EventType {

	NEW_EVENT_TYPE;

    @Override
    public boolean equals(EventType value) {
        if(value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }
	
}
