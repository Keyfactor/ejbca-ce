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
package org.ejbca.core.ejb.ra;

import java.util.Collection;

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Remote interface to allow access to local methods from system tests
 * 
 * @version $Id$
 *
 */
@Remote
public interface EndEntityManagementProxySessionRemote {

    /**
     * Decreases (the optional) request counter by 1, until it reaches 0.
     * Returns the new value. If the value is already 0, -1 is returned, but the
     * -1 is not stored in the database. Also sets status of user to generated
     * once the request counter reaches zero.
     * 
     * @param username the unique username.
     * @param status the new status, from 'UserData'.
     * @throws NoSuchEndEntityException if user does not exist
     */
    public int decRequestCounter(String username) throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException, NoSuchEndEntityException;
    
    /**
     * Method to execute a customized query on the ra user data. The parameter
     * query should be a legal Query object.
     * 
     * @param query a number of statements compiled by query class to a SQL
     *            'WHERE'-clause statement.
     * @param caauthorizationstring is a string placed in the where clause of
     *            SQL query indication which CA:s the administrator is
     *            authorized to view.
     * @param endentityprofilestring is a string placed in the where clause of
     *            SQL query indication which endentityprofiles the
     *            administrator is authorized to view.
     * @param numberofrows the number of rows to fetch, use 0 for value from the global configuration. 
     * @param endentityAccessRule The end entity access rule that is necessary 
     *            to execute the query
     * @return a collection of EndEntityInformation.
     * @throws IllegalQueryException when query parameters internal rules isn't
     *            fulfilled.
     * @see org.ejbca.util.query.Query
     */
    Collection<EndEntityInformation> query(AuthenticationToken admin, Query query, String caauthorizationstring,
            String endentityprofilestring, int numberofrows, final String endentityAccessRule) throws IllegalQueryException;
}
