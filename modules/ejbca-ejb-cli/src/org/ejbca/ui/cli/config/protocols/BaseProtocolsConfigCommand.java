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
package org.ejbca.ui.cli.config.protocols;

import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Objects;

import org.apache.log4j.Logger;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.ejbca.ui.cli.config.ConfigBaseCommand;

/**
 * Base class for controlling enabled protocols.
 * 
 * @version $Id$
 */
public abstract class BaseProtocolsConfigCommand extends ConfigBaseCommand {

    protected final Logger log = Logger.getLogger(this.getClass());

    protected static final String KEY_NAME = "--name";

    @Override
    public String[] getCommandPath() {
        return new String[] { super.getCommandPath()[0] , "protocols" };
    }

    /** @return the a fresh copy from the running instance */
    protected AvailableProtocolsConfiguration getAvailableProtocolsConfiguration() {
        return (AvailableProtocolsConfiguration) getGlobalConfigurationSession().getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
    }
    
    protected void showProtocolStatus(final LinkedHashMap<String, Boolean> availableProtocolStatusMap, final String protocolName, final int padding) {
        final Boolean status = availableProtocolStatusMap.get(protocolName);
        final String statusString = (status==null ? "Unknown" : (status ? "Enabled" : "Disabled"));
        log.info(String.format("%1$-"+(padding+1)+ "s", protocolName+":") + " " + statusString);
    }

    /** @return the length of the longest String in the provided Collection or 0 if no Strings are provided */
    protected int getMaxStringLength(final Collection<String> collection) {
        if (collection==null) {
            return 0;
        }
        return collection.stream().filter(Objects::nonNull).max(Comparator.comparingInt(String::length)).orElse("").length();
    }

    /** @return the matching AvailableProtocols from input by case-insensitive search by both enum name and human readable name or null */
    protected AvailableProtocols getAvailableProtocolFromParameter(final String requestedProtocolName) {
        if (requestedProtocolName==null) {
            return null;
        }
        return Arrays.asList(AvailableProtocols.values()).stream()
                .filter(x -> x.name().equalsIgnoreCase(requestedProtocolName) || x.getName().equalsIgnoreCase(requestedProtocolName))
                .findFirst().orElse(null);
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
