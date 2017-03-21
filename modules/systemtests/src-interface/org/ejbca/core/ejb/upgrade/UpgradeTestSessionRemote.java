/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.upgrade;

import java.util.List;

import javax.ejb.Remote;

import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.user.AccessUserAspectData;

/**
 * Interface for the bean helping with setup from tests of upgrade functionality.
 * 
 * @version $Id$
 */
@SuppressWarnings("deprecation")
@Remote
public interface UpgradeTestSessionRemote {

    void createRole(String roleName, List<AccessRuleData> accessRules, List<AccessUserAspectData> accessUserAspectDatas);

    void deleteRole(String roleName);

    List<AccessRuleData> getAccessRuleDatas(String roleName);

}
