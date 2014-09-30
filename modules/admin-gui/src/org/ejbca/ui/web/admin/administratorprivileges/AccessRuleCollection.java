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

package org.ejbca.ui.web.admin.administratorprivileges;

import java.util.List;

import org.cesecore.authorization.rules.AccessRuleData;

/**
 * 
 * @version $Id$
 *
 */

public class AccessRuleCollection {

    private String name;
    private List<AccessRuleData> collection;

    public AccessRuleCollection(String name, List<AccessRuleData> collection) {
        this.name = name;
        this.collection = collection;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<AccessRuleData> getCollection() {
        return collection;
    }

    public void setCollection(List<AccessRuleData> collection) {
        this.collection = collection;
    }
}
