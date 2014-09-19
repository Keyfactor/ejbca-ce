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
package org.ejbca.core.ejb.keybind;

import java.util.ArrayList;
import java.util.List;

import org.cesecore.authorization.rules.AccessRulePlugin;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * @version $Id$
 *
 */
public class InternalKeybindingRulesReference implements AccessRulePlugin {

    @Override
    public List<String> getRules() {
        List<String> allRules = new ArrayList<String>();
        for(InternalKeyBindingRules rule : InternalKeyBindingRules.values()) {
            allRules.add(rule.resource());
            
        }
        InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession =  new EjbLocalHelper().getInternalKeyBindingMgmtSession();
        for (String type : internalKeyBindingMgmtSession.getAvailableTypesAndProperties().keySet()) {
            for (InternalKeyBinding keyBinding : internalKeyBindingMgmtSession.getAllInternalKeyBindingInfos(type)) {
                int id = keyBinding.getId();
                for (InternalKeyBindingRules rule : InternalKeyBindingRules.values()) {
                    if (rule != InternalKeyBindingRules.BASE) {
                        allRules.add(rule.resource() + "/" + id);
                    }
                }
            }
        }
        return allRules;
    }

    @Override
    public String getCategory() {
        return "INTERNALKEYBINDINGRULES";
    }

}
