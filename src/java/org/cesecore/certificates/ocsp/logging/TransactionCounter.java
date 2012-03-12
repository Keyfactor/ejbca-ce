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
package org.cesecore.certificates.ocsp.logging;


/**
 * An enum based singleton which returns transaction numbers. Not a static volatile value, because these are forbidden by the EJB standard.
 * 
 * @version $Id$
 * 
 */
public enum TransactionCounter {
    INSTANCE;

    private TransactionCounter() {
        transactionNumber = 0;
    }

    public synchronized int getTransactionNumber() {
        return transactionNumber++;
    }

    private int transactionNumber;

}
