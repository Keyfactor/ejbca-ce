/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb;

import org.ejbca.core.protocol.acme.AcmeAccountDataSession;

import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.ejb.Stateless;
import javax.ejb.TransactionManagement;
import javax.ejb.TransactionManagementType;
import java.util.LinkedHashMap;

/**
 * Class that receives a Acme message and passes it on to the correct message handler.
 * Not available in Community Edition
 *
 * @version $Id: AcmeAccountDataSessionBean.java 27609 2017-12-20 15:55:45Z mikekushner $
 */
@Stateless
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
@TransactionManagement(TransactionManagementType.BEAN)
public class AcmeAccountDataSessionBean implements AcmeAccountDataSession {
    @Override
    public LinkedHashMap<Object, Object> getAccountDataById(String accountId) throws UnsupportedOperationException {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public String getAccountIdByPublicKeyStorageId(String publicKeyStorageId) throws UnsupportedOperationException{
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public String persist(String accountIdParam, String currentKeyId, LinkedHashMap<Object, Object> dataMap) throws UnsupportedOperationException{
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
}
