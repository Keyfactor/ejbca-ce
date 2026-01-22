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

package org.ejbca.core.model.approval;

public enum ApprovalRequestStatus {
    PENDING,
    APPROVED,
    REJECTED,
    EXPIRED,
    EXPIRED_AND_NOTIFIED,
    EXECUTED,
    EXECUTION_FAILED,
    EXECUTION_DENIED,
    UNKNOWN;

    public String getValue() {
        return this.name();
    }

    public static ApprovalRequestStatus fromInt(final int status) {
        switch (status) {
            case ApprovalDataVO.STATUS_WAITINGFORAPPROVAL:
                return PENDING;
            case ApprovalDataVO.STATUS_APPROVED:
                return APPROVED;
            case ApprovalDataVO.STATUS_REJECTED:
                return REJECTED;
            case ApprovalDataVO.STATUS_EXPIRED:
            case ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED:
                return EXPIRED;
            case ApprovalDataVO.STATUS_EXECUTED:
                return EXECUTED;
            case ApprovalDataVO.STATUS_EXECUTIONFAILED:
                return EXECUTION_FAILED;
            case ApprovalDataVO.STATUS_EXECUTIONDENIED:
                return EXECUTION_DENIED;
            default:
                return UNKNOWN;
        }
    }


    /**
     * Translates status into the combined {@code ApprovalRequestStatus} states, to match GUI behavior.
     *
     * @param status        the integer representation of the status
     * @return              the corresponding {@code ApprovalRequestStatus} enum value
     */
    public static ApprovalRequestStatus fromIntWithCombinedStates(final int status) {
        switch (status) {
            case ApprovalDataVO.STATUS_WAITINGFORAPPROVAL:
                return PENDING;
            case ApprovalDataVO.STATUS_APPROVED:
            case ApprovalDataVO.STATUS_EXECUTED:
                return APPROVED;
            case ApprovalDataVO.STATUS_REJECTED:
            case ApprovalDataVO.STATUS_EXECUTIONFAILED:
            case ApprovalDataVO.STATUS_EXECUTIONDENIED:
                return REJECTED;
            case ApprovalDataVO.STATUS_EXPIRED:
            case ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED:
                return EXPIRED;
            default:
                return UNKNOWN;
        }
    }
}
