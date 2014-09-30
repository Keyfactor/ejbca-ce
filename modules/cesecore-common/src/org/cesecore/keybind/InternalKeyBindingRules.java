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

package org.cesecore.keybind;

import java.util.HashMap;
import java.util.Map;

/**
 * Authorization Rules for InternalKeyBindings.
 * 
 * @version $Id$
 */
public enum InternalKeyBindingRules {
    BASE("/internalkeybinding", ""),
    DELETE(BASE.resource() + "/delete", "DELETE"),
    MODIFY(BASE.resource() + "/modify", "MODIFY"),
    VIEW(BASE.resource() + "/view", "VIEW");

    private static final Map<String, InternalKeyBindingRules> reverseResourceLookup;
    
    static {
        reverseResourceLookup = new HashMap<String, InternalKeyBindingRules>();
        for(InternalKeyBindingRules rule : InternalKeyBindingRules.values()) {
            reverseResourceLookup.put(rule.resource(), rule);
        }
    }
    
    private final String resource;
    private final String reference;
    
    private InternalKeyBindingRules(String resource, String reference) {
        this.resource = resource;
        this.reference = reference;
    }

    public String resource() {
        return this.resource;
    }

    public String toString() {
        return this.resource;
    }
    
    public String getReference() {
        return reference;
    }
    
    public static InternalKeyBindingRules getFromResource(String resource) {
        return reverseResourceLookup.get(resource);
    }
}
