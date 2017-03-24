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

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.cesecore.authorization.rules.AccessRulePlugin;
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
import org.cesecore.keybind.InternalKeyBindingMgmtSession;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.core.model.util.LocalLookupException;

/**
 * Dynamically defined access rules for InternalKeyBindings.
 * 
 * @version $Id$
 */
public class InternalKeyBindingRulesReference implements AccessRulePlugin {

    @Override
    public Map<String,String> getRules() {
        final Map<String,String> allRules = new HashMap<String,String>();
        for (final InternalKeyBindingRules rule : InternalKeyBindingRules.values()) {
            allRules.put(rule.resource(), rule.resource());
        }
        try {
            final InternalKeyBindingDataSessionLocal internalKeyBindingDataSession = new EjbLocalHelper().getInternalKeyBindingDataSession();
            for (final Entry<String,Integer> entry : internalKeyBindingDataSession.getCachedNameToIdMap().entrySet()) {
                for (final InternalKeyBindingRules rule : InternalKeyBindingRules.values()) {
                    if (!InternalKeyBindingRules.BASE.equals(rule)) {
                        allRules.put(rule.resource() + "/" + entry.getValue(), rule.resource() + "/" + entry.getKey());
                    }
                }
                
            }
        } catch (LocalLookupException e) {
            //Possibly we're not local, then use the remote interface instead
            InternalKeyBindingMgmtSession internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
            if(internalKeyBindingMgmtSession == null) {
                //Fail state, can't continue
                throw new IllegalStateException("Can't perform lookup of internal keybindings, can't continue.");
            }
            for (String type : internalKeyBindingMgmtSession.getAvailableTypesAndProperties().keySet()) {
                for (int id : internalKeyBindingMgmtSession.getInternalKeyBindingIds(type)) {
                    for (InternalKeyBindingRules rule : InternalKeyBindingRules.values()) {
                        if (rule != InternalKeyBindingRules.BASE) {
                            // Don't make the name available remotely
                            allRules.put(rule.resource() + "/" + id, rule.resource() + "/" + id);
                        }
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
