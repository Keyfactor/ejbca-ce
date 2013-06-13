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
package org.ejbca.ui.cli.keybind;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.ejbca.core.ejb.keybind.InternalKeyBindingMgmtSessionRemote;
import org.ejbca.core.ejb.keybind.InternalKeyBindingProperty;
import org.ejbca.core.ejb.keybind.InternalKeyBindingStatus;
import org.ejbca.ui.cli.BaseCommand;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Base class for the InternalKeyBinding API access.
 * 
 * @version $Id$
 */
public abstract class BaseInternalKeyBindingCommand extends BaseCommand {

    @Override
    public String getMainCommand() {
        return "keybind";
    }

    /**
     * Overridable InternalKeyBinding-specific execution methods that will parse and interpret the first parameter
     * (when present) as the name of a InternalKeyBinding and lookup its InternalKeyBindingId.
     */
    public abstract void executeCommand(Integer internalKeyBindingId, String[] args) throws AuthorizationDeniedException, Exception;
    
    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        Integer internalKeyBindingId = null;
        if (failIfInternalKeyBindIsMissing() && args.length>=2) {
            final String internalKeyBindingName = args[1];
            internalKeyBindingId = ejb.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class).getIdFromName(internalKeyBindingName);
            if (internalKeyBindingId==null) {
                getLogger().info("Unknown InternalKeyBinding: " + internalKeyBindingName);
                return;
            }
        }
        try {
            executeCommand(internalKeyBindingId, args);
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
        } catch (Exception e) {
            getLogger().info("Operation failed: " + e.getMessage());
            getLogger().debug("", e);
        }
    }
    
    /** Lists available types and their properties */
    protected void showTypesProperties() {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = ejb.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        Map<String, List<InternalKeyBindingProperty<? extends Serializable>>> typesAndProperties = internalKeyBindingMgmtSession.getAvailableTypesAndProperties(getAdmin());
        getLogger().info("Registered implementation types and implemention specific properties:");
        for (Entry<String, List<InternalKeyBindingProperty<? extends Serializable>>> entry : typesAndProperties.entrySet()) {
            final StringBuilder sb = new StringBuilder();
            sb.append("  ").append(entry.getKey()).append(" {");
            for (InternalKeyBindingProperty<? extends Serializable> property : entry.getValue()) {
                sb.append(property.getName()).append(",");
            }
            sb.deleteCharAt(sb.length()-1).append("}");
            getLogger().info(sb.toString());
        }
    }
    
    protected void showStatuses() {
        final StringBuilder sb = new StringBuilder("Status is one of ");
        for (InternalKeyBindingStatus internalKeyBindingStatus : InternalKeyBindingStatus.values()) {
            sb.append(internalKeyBindingStatus.name()).append(",");
        }
        sb.deleteCharAt(sb.length()-1);
        getLogger().info(sb.toString());
    }
    
    protected void showSigAlgs() {
        final StringBuilder sbAlg = new StringBuilder("Signature algorithm is one of ");
        for (final String algorithm : AlgorithmConstants.AVAILABLE_SIGALGS) {
            if (AlgorithmTools.isSigAlgEnabled(algorithm)) {
                sbAlg.append(algorithm).append(',');
            }
        }
        sbAlg.deleteCharAt(sbAlg.length()-1);
        getLogger().info(sbAlg.toString());
    }
    
    protected boolean failIfInternalKeyBindIsMissing() {
        return true;
    }
    
    /** @return the EJB CLI admin */
    protected AuthenticationToken getAdmin() {
        return getAdmin(cliUserName, cliPassword);
    }
}
