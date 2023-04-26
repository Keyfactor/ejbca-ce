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
package org.ejbca.core.ejb;

import javax.annotation.Resource;
import javax.ejb.Stateless;
import javax.ejb.TransactionManagement;
import javax.ejb.TransactionManagementType;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.OptimisticLockException;
import javax.persistence.PersistenceUnit;
import javax.transaction.HeuristicMixedException;
import javax.transaction.HeuristicRollbackException;
import javax.transaction.NotSupportedException;
import javax.transaction.RollbackException;
import javax.transaction.SystemException;
import javax.transaction.UserTransaction;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ra.UserData;

/**
 * Methods for performing database operations without involving the application server.
 * <p>
 * This is necessary to suppress errors in insertions/updates that are prone to fail, but where failure is not a problem.
 * I.e. "best-effort" mode.
 */
@Stateless
@TransactionManagement(TransactionManagementType.BEAN)
public class ApplicationManagedTransactionsBean {

    private static final Logger log = Logger.getLogger(ApplicationManagedTransactionsBean.class);

    @PersistenceUnit
    private EntityManagerFactory entityManagerFactory;

    @Resource
    private UserTransaction userTransaction;

    /**
     * Edits/adds an end entity in a separate transaction, and ignores any transaction conflicts.
     * <p>
     * Note: This will not be rolled back if the outer transaction gets rolled back.
     *
     * @param newUserData User data.
     * @param isNew Whether the end entity should be inserted (true) or updated (false).
     */
    public void changeUserIfNoConflict(final UserData newUserData, final boolean isNew) {
        final EntityManager em = entityManagerFactory.createEntityManager();
        try {
            userTransaction.begin();
            if (isNew) {
                em.persist(newUserData);
            } else {
                em.merge(newUserData);
            }
            userTransaction.commit();
        } catch (RollbackException | HeuristicRollbackException | HeuristicMixedException | OptimisticLockException e) {
            if (log.isTraceEnabled()) {
                log.trace("Caught rollback exception: " + e.getMessage(), e);
            }
            log.info("Skipped update of '" + newUserData.getUsername() + "' due to concurrent transaction.");
            try {
                userTransaction.rollback();
            } catch (IllegalStateException | SecurityException | SystemException rollbackException) {
                log.warn("An exception happened during transaction rollback: " + rollbackException.getClass() + ": " + rollbackException.getMessage());
                log.debug("Rollback exception stacktrace: ", rollbackException);
            }
        } catch (SecurityException | SystemException | NotSupportedException e) {
            throw new IllegalStateException(e);
        } finally {
            em.close();
        }
    }
    
}
