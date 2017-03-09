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
package org.cesecore.authorization.rules;

import java.util.Map;

/**
 * Marker interface to allow access rules to be plugged in. 
 * 
 * @version $Id$
 */
public interface AccessRulePlugin {

    /** @return a map of resources (rules) as map keys and their human readable counterpart as value (if available or otherwise the resource again) */
    Map<String,String> getRules();
    
    /** @return a category key this rule set belongs to */
    String getCategory();
}
