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
package org.cesecore.authorization.control;

import java.util.Map;

import org.cesecore.authorization.rules.AccessRulePlugin;

/**
 * Dynamically defined access rules for the security events audit log.
 * 
 * @version $Id$
 */
public class AuditLogRulesReference implements AccessRulePlugin{

    @Override
    public Map<String,String> getRules() {
        return AuditLogRules.getAllResources();
    }

    @Override
    public String getCategory() {
        return "AUDITLOGRULES";
    }

}
