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
package org.ejbca.core.model.approval.profile;

/**
 * The approval work flow state is an indication of the current progress and used for triggering actions.
 * 
 * @version $Id$
 */
public enum ApprovalPartitionWorkflowState {
    /** The partition has been approved and no longer requires any action */
    APPROVED,
    /** The partition has been approved, but still requires additional approvals */
    APPROVED_PARTIALLY,
    /** The partition has been rejected and no longer requires any action */
    REJECTED,
    /** The partition requires an action from admin */
    REQUIRES_ACTION,
    /** The partition (and also currently the whole approval) has expired and no longer requires any action */
    EXPIRED,
}
