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

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationTokenReferenceRegistry;
import org.jboss.ejb.client.ClusterNodeSelector;

/**
 * When configured in an jboss-ejb-client.properties file, I attempt to 
 * always connect to the same node.  This is required with EJBCA because
 * EJBCA uses an in-memory authentication nonce system 
 * (see {@link CliAuthenticationTokenReferenceRegistry}).  If the usual 
 * round-robin node selection algorithm is used, the nonce will not be present
 * in the destination EJBCA instance in the second call.
 * <p>
 * I work together with {@link SameDeploymentNodeSelector}.
 * <p>
 * I should be configured in jboss-ejb-client.properties like:
 * <pre>
 * remote.clusters=ejb
 * remote.cluster.ejb.clusternode.selector=org.ejbca.ui.cli.SameClusterNodeSelector
 * </pre>
 */
public class SameClusterNodeSelector implements ClusterNodeSelector {
    private static final Logger log = Logger.getLogger(SameClusterNodeSelector.class);

    @Override
    public String selectNode(final String clusterName, final String[] connectedNodes, final String[] totalAvailableNodes) {
        // try to use the last one we got
        String lastSelectedNode = SameDeploymentNodeSelector.lastSelectedNode.get();
        for (String node : totalAvailableNodes) {
            if (node.equals(lastSelectedNode)) {
                if (log.isDebugEnabled()) {
                    log.debug("Selecting remote EJBCA cluster node: " + node);
                }
                return node;
            }
        }

        // just take the first available
        String selectedNode = totalAvailableNodes[0];
        SameDeploymentNodeSelector.lastSelectedNode.set(selectedNode);
        if (log.isDebugEnabled()) {
            log.debug("Selecting remote EJBCA cluster node: " + selectedNode);
        }
        return selectedNode;
    }

}
