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
package org.ejbca.ui.cli.keybind;

import java.io.Serializable;
import java.util.Map;
import java.util.Map.Entry;

import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keybind.InternalKeyBindingFactory;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingProperty;
import org.cesecore.keybind.InternalKeyBindingPropertyValidationWrapper;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * @version $Id$
 *
 */
public abstract class BaseInternalKeyBindingCommand extends EjbcaCliUserCommandBase {

    protected static final String KEYBINDING_NAME_KEY = "--name";

    {
        registerParameter(new Parameter(KEYBINDING_NAME_KEY, "Internal Keybinding Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Name of the key binding."));
    }
    
    @Override
    public String[] getCommandPath() {
        return new String[] { "keybind" };
    }

    protected Map<String, Serializable> validateProperties(String type, Map<String, String> dataMap) {
        InternalKeyBindingPropertyValidationWrapper validatedProperties = InternalKeyBindingFactory.INSTANCE.validateProperties(type, dataMap);
        if (!validatedProperties.arePropertiesValid()) {
            StringBuffer stringBuffer = new StringBuffer();
            stringBuffer.append('\n');
            stringBuffer.append("ERROR: Could not parse properties\n");
            stringBuffer.append('\n');
            if (validatedProperties.getUnknownProperties().size() > 0) {
                stringBuffer.append("The following properties were unknown for the type: " + type + "\n");
                for (String propertyName : validatedProperties.getUnknownProperties()) {
                    stringBuffer.append("    * '" + propertyName + "'\n");
                }
                stringBuffer.append('\n');
            }
            if (validatedProperties.getInvalidValues().size() > 0) {
                stringBuffer.append("The following values were invalid:\n");
                for (Entry<String, Class<?>> entry : validatedProperties.getInvalidValues().entrySet()) {
                    stringBuffer.append("Value '" + dataMap.get(entry.getKey()) + "' for property '" + entry.getKey() + "' was not of type "
                            + entry.getValue().getSimpleName() + "\n");
                }
                stringBuffer.append('\n');
            }
            getLogger().error(stringBuffer);
            return null;
        }
        return validatedProperties.getPropertiesCopy();
    }
    
    /** Lists available types and their properties */
    protected String showTypesProperties() {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        Map<String, Map<String, InternalKeyBindingProperty<? extends Serializable>>> typesAndProperties = internalKeyBindingMgmtSession
                .getAvailableTypesAndProperties();
        final StringBuilder sb = new StringBuilder();
        sb.append("Registered implementation types and implemention specific properties:\n");
        for (Entry<String, Map<String, InternalKeyBindingProperty<? extends Serializable>>> entry : typesAndProperties.entrySet()) {
            sb.append(' ').append(entry.getKey()).append(":\n");
            for (InternalKeyBindingProperty<? extends Serializable> property : entry.getValue().values()) {
                sb.append("    " + property.getName()).append(",\n");
            }
            if (sb.charAt(sb.length() - 2) == ',') {
                sb.deleteCharAt(sb.length() - 2);
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    protected String showStatuses() {
        final StringBuilder sb = new StringBuilder("Status is one of ");
        for (InternalKeyBindingStatus internalKeyBindingStatus : InternalKeyBindingStatus.values()) {
            sb.append(internalKeyBindingStatus.name()).append(',');
        }
        sb.deleteCharAt(sb.length() - 1);
        return  sb.append('\n').toString();
    }

    protected String showSigAlgs() {
        final StringBuilder sbAlg = new StringBuilder("Signature algorithm is one of ");
        for (final String algorithm : AlgorithmConstants.AVAILABLE_SIGALGS) {
            if (AlgorithmTools.isSigAlgEnabled(algorithm)) {
                sbAlg.append(algorithm).append(',');
            }
        }
        return sbAlg.deleteCharAt(sbAlg.length() - 1).append('\n').toString();
    }
}
