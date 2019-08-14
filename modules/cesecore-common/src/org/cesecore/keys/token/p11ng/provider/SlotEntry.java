/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng.provider;

/**
 * Represents an entry in the HSM Slot with an alias and a type.
 *
 * @version $Id$
 */
public class SlotEntry {

    private final String alias;
    private final String type;

    public SlotEntry(String alias, String type) {
        this.alias = alias;
        this.type = type;
    }

    public String getType() {
        return this.type;
    }

    public String getAlias() {
        return this.alias;
    }    
}
