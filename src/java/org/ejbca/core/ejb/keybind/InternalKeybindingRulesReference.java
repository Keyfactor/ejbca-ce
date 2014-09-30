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
package org.ejbca.core.ejb.keybind;

import java.util.ArrayList;
import java.util.List;

import org.cesecore.authorization.rules.AccessRulePlugin;
import org.cesecore.keybind.InternalKeyBindingMgmtSession;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.core.model.util.LocalLookupException;

/**
 * @version $Id$
 *
 */
public class InternalKeybindingRulesReference implements AccessRulePlugin {

    @Override
    public List<String> getRules() {
        List<String> allRules = new ArrayList<String>();
        for (InternalKeyBindingRules rule : InternalKeyBindingRules.values()) {
            allRules.add(rule.resource());

        }
        InternalKeyBindingMgmtSession internalKeyBindingMgmtSession = null;
        try {
            internalKeyBindingMgmtSession = new EjbLocalHelper().getInternalKeyBindingMgmtSession();
        } catch (LocalLookupException e) {
            //Possibly we're not local, then use the remote interface instead
            internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        }
        if(internalKeyBindingMgmtSession == null) {
            //Fail state, can't continue
            throw new IllegalStateException("Can't perform lookup of internal keybindings, can't continue.");
        }
        for (String type : internalKeyBindingMgmtSession.getAvailableTypesAndProperties().keySet()) {
            for (int id : internalKeyBindingMgmtSession.getInternalKeyBindingIds(type)) {
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
