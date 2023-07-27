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

package org.ejbca.ui.cli.ca;

import java.util.Collection;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

import com.keyfactor.util.CryptoProviderTools;

/**
 * List Publishers in the system.
 * 
 * @version $Id$
 */
public class CaListPublishersCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaListPublishersCommand.class);
    

    @Override
    public String getMainCommand() {
        return "listpublishers";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        final PublisherSessionRemote pubsession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
        // Get the publisher named
        CryptoProviderTools.installBCProviderIfNotAvailable();
        Map<Integer,String> map = pubsession.getPublisherIdToNameMap();
        Collection<Integer> ids = map.keySet();
        for (Integer id: ids) {
            getLogger().info("Publisher ID: " + id);
            getLogger().info(" Name: " + map.get(id));
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "List the names of all available publishers.";
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
