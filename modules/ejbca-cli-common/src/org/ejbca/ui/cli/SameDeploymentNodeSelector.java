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
package org.ejbca.ui.cli;

import java.util.concurrent.atomic.AtomicReference;

import org.apache.log4j.Logger;
import org.jboss.ejb.client.DeploymentNodeSelector;

/**
 * When configured in an jboss-ejb-client.properties file, I attempt to 
 * always connect to the same node.  This is required with EJBCA because
 * EJBCA uses an in-memory authentication nonce system 
 * (see {@link CliAuthenticationTokenReferenceRegistry}).  If the usual 
 * round-robin node selection algorithm is used, the nonce will not be present
 * in the destination EJBCA instance in the second call.
 * <p>
 * I work together with {@link SameClusterNodeSelector}
 * <p>
 * I should be configured in jboss-ejb-client.properties like:
 * <pre>
 * deployment.node.selector=org.ejbca.ui.cli.SameDeploymentNodeSelector
 * </pre>
 */
public class SameDeploymentNodeSelector implements DeploymentNodeSelector {
    private static final Logger log = Logger.getLogger(SameDeploymentNodeSelector.class);

    static AtomicReference<String> lastSelectedNode = new AtomicReference<>();

    @Override
    public String selectNode(final String[] eligibleNodes, final String appName, final String moduleName, final String distinctName) {

        // try to use the last one we used
        String lastSelectedNodeString = lastSelectedNode.get();
        for (var eligibleNode : eligibleNodes) {
            if (eligibleNode.equals(lastSelectedNodeString)) {
                if (log.isDebugEnabled()) {
                    log.debug("Selecting remote EJBCA deployment node: " + eligibleNode);
                }
                return eligibleNode;
            }
        }

        // just grab the first one
        String selectedNode = eligibleNodes[0];
        lastSelectedNode.set(selectedNode);
        if (log.isDebugEnabled()) {
            log.debug("Selecting remote EJBCA deployment node: " + selectedNode);
        }

        return selectedNode;
    }

}
