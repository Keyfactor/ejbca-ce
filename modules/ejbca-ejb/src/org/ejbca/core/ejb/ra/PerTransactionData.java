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
package org.ejbca.core.ejb.ra;

import java.util.Objects;

import javax.transaction.Status;
import javax.transaction.TransactionSynchronizationRegistry;

/**
 * Used for storing information in the JPA transaction, in the Registry resource.
 * This is in turn used suppressing unnecessary changes to the UserData table,
 * as well as moving "non-important" changes to separate transactions.
 *
 * @see EndEntityManagementSessionBean#classifyUserDataChanges
 */
public final class PerTransactionData {

    private static enum ItemKind {
        /**
         * Used to store information about the original end entity for an end entity in a transaction.
         * Used together with {@link #ORIGINAL_END_EMTITY} to avoid transaction
         * conflicts and unnecessary updates.
         */
        ORIGINAL_END_EMTITY,
        /**
         * Used to store a pending, unpersisted, UserData for an end entity in a transaction.
         * Used together with {@link #ORIGINAL_END_EMTITY} to avoid transaction
         * conflicts and unnecessary updates.
         */
        PENDING_USERDATA,
    }

    private final static class TransactionKey {
        private final ItemKind itemKind;
        private final String identifier;

        public TransactionKey(final ItemKind itemKind, final String identifier) {
            this.identifier = identifier;
            this.itemKind = itemKind;
        }

        @Override
        public int hashCode() {
            return Objects.hash(identifier, itemKind);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (!(obj instanceof TransactionKey))
                return false;
            final TransactionKey other = (TransactionKey) obj;
            return Objects.equals(identifier, other.identifier) && itemKind == other.itemKind;
        }
    }

    private final TransactionSynchronizationRegistry registry;

    public PerTransactionData(final TransactionSynchronizationRegistry registry) {
        this.registry = registry;
    }

    public boolean isInTransaction() {
        return registry.getTransactionStatus() != Status.STATUS_NO_TRANSACTION && registry.getTransactionStatus() != Status.STATUS_UNKNOWN;
    }

    public void setPendingUserData(final UserData userdata) {
        registry.putResource(new TransactionKey(ItemKind.PENDING_USERDATA, userdata.getUsername()), userdata);
    }

    public UserData getPendingUserData(final String username) {
        return (UserData) registry.getResource(new TransactionKey(ItemKind.PENDING_USERDATA, username));
    }

    public void clearEndEntityTransactionInfo(final String username) {
        registry.putResource(new TransactionKey(ItemKind.ORIGINAL_END_EMTITY, username), null);
        registry.putResource(new TransactionKey(ItemKind.PENDING_USERDATA, username), null);
    }

    public boolean couldSuppressUserDataModification(final String username) {
        return registry.getResource(new TransactionKey(ItemKind.ORIGINAL_END_EMTITY, username)) != null;
    }

    public OriginalEndEntity getOriginalEndEntity(final String username) {
        return (OriginalEndEntity) registry.getResource(new TransactionKey(ItemKind.ORIGINAL_END_EMTITY, username));
    }

    public void setOriginalEndEntity(final String username, final OriginalEndEntity originalInfo) {
        registry.putResource(new TransactionKey(ItemKind.ORIGINAL_END_EMTITY, username), originalInfo);
    }
}