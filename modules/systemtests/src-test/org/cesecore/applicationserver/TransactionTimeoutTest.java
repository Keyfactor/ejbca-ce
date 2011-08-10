/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.applicationserver;

import javax.ejb.EJBTransactionRolledbackException;

import junit.framework.Assert;

import org.cesecore.jndi.JndiHelper;
import org.junit.Test;

/**
 * This class tests transaction timeouts via the application server.
 * 
 * @version $Id: TransactionTimeoutTest.java 770 2011-05-11 08:08:47Z tomas $
 * 
 */
public class TransactionTimeoutTest {

    public TransactionTimeoutSessionRemote transactionTimeoutTestSession = JndiHelper.getRemoteSession(TransactionTimeoutSessionRemote.class);

    @Test
    public void testTimeout() throws InterruptedException {

        /*
         * This method is known to time out after 3s  
         */
        try {
            transactionTimeoutTestSession.timeout(500L);
        } catch (EJBTransactionRolledbackException e) {
            Assert.fail("A transaction timed incorrectly.");
        }

        //Force the AS to time out the transaction.
        try {
            transactionTimeoutTestSession.timeout(4000L);
        } catch (EJBTransactionRolledbackException e) {
            return;
        }
        Assert.fail("Timeout did not occur.");
    }

}
