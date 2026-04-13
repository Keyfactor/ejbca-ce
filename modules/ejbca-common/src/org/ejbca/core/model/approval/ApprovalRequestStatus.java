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


/**
 * Represents the status of an approval request in the system.
 * The statuses include various states such as pending, approved, rejected etc and
 * mapped from ApprovalDataVO.STATUS_* constants.
 */
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

    /**
     * Translates status from ApprovalDataVO.STATUS_* constants into
     * the {@code ApprovalRequestStatus} enum value.
     *
     * @param status    the integer representation of the status
     * @return          the corresponding {@code ApprovalRequestStatus} enum value
     */
    public static ApprovalRequestStatus fromInt(final int status) {
        return switch (status) {
            case ApprovalDataVO.STATUS_WAITINGFORAPPROVAL -> PENDING;
            case ApprovalDataVO.STATUS_APPROVED -> APPROVED;
            case ApprovalDataVO.STATUS_REJECTED -> REJECTED;
            case ApprovalDataVO.STATUS_EXPIRED, ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED -> EXPIRED;
            case ApprovalDataVO.STATUS_EXECUTED -> EXECUTED;
            case ApprovalDataVO.STATUS_EXECUTIONFAILED -> EXECUTION_FAILED;
            case ApprovalDataVO.STATUS_EXECUTIONDENIED -> EXECUTION_DENIED;
            default -> UNKNOWN;
        };
    }


    /**
     * Translates status into the combined {@code ApprovalRequestStatus} states, to match GUI behavior.
     *
     * @param status        the integer representation of the status
     * @return              the corresponding {@code ApprovalRequestStatus} enum value
     */
    public static ApprovalRequestStatus fromIntWithCombinedStates(final int status) {
        return switch (status) {
            case ApprovalDataVO.STATUS_WAITINGFORAPPROVAL -> PENDING;
            case ApprovalDataVO.STATUS_APPROVED, ApprovalDataVO.STATUS_EXECUTED -> APPROVED;
            case ApprovalDataVO.STATUS_REJECTED, ApprovalDataVO.STATUS_EXECUTIONFAILED,
                 ApprovalDataVO.STATUS_EXECUTIONDENIED -> REJECTED;
            case ApprovalDataVO.STATUS_EXPIRED, ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED -> EXPIRED;
            default -> UNKNOWN;
        };
    }
}
