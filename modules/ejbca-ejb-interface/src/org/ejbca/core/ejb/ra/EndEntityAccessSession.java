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

import java.security.cert.CertificateEncodingException;
import java.util.Collection;
import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.EjbcaException;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

import com.keyfactor.util.certificate.CertificateWrapper;

/**
 * Provides find methods for EndEntityInformation objects. 
 * 
 * @version $Id$
 *
 */
public interface EndEntityAccessSession {

    /**
     * Finds a user by username.
     * 
     * @param admin the administrator performing the action
     * @return EndEntityInformation or null if the user is not found.
     * 
     * @throws AuthorizationDeniedException if the admin was not authorized to the end entity profile or issuing CA
     */
    EndEntityInformation findUser(AuthenticationToken admin, String username) throws AuthorizationDeniedException;
    
    /**
     * Finds a user by username for the creation of a certificate.
     * 
     * @param admin the administrator performing the action
     * @return EndEntityInformation or null if the user is not found.
     * 
     * @throws AuthorizationDeniedException if the admin was not authorized to the end entity profile or issuing CA
     */
    EndEntityInformation findUserWithoutViewEndEntityAccessRule(AuthenticationToken admin, String username) throws AuthorizationDeniedException;

    /**
     * Find users by their subject and issuer DN.
     * @return A list of all EndEntityInformations found matching those DNs, or an empty list
     */
     List<EndEntityInformation> findUserBySubjectAndIssuerDN(AuthenticationToken admin, String subjectdn, String issuerdn) throws AuthorizationDeniedException;

    /**
     * Find users by their subject DN.
     * @return A list of all EndEntityInformations matching the given DN, or an empty list
     * 
     * @throws AuthorizationDeniedException if the admin was not authorized to the end entity profile or issuing CA
     */
     List<EndEntityInformation> findUserBySubjectDN(AuthenticationToken admin, String subjectdn) throws AuthorizationDeniedException;

    /**
     * Finds a users by subject email.
     * @return List of all matching EndEntityInformation, never null
     * 
     * @throws AuthorizationDeniedException if the admin was not authorized to the end entity profile or issuing CA
     */
     List<EndEntityInformation> findUserByEmail(AuthenticationToken admin, String email) throws AuthorizationDeniedException;
    
     /**
      * Finds all users with a specified status.
      * 
      * @param status the status to look for, from 'UserData'.
      * @return Collection of EndEntityInformation
      */
     Collection<EndEntityInformation> findAllUsersByStatus(AuthenticationToken admin, int status);

     /**
      * Finds all users registered to a specified CA.
      * 
      * @param caid the caid of the CA, from 'UserData'.
      * @return Collection of EndEntityInformation, or empty collection if the query is
      *         illegal or no users exist
      */
     Collection<EndEntityInformation> findAllUsersByCaId(AuthenticationToken admin, int caid);

     /**
      * Finds all batch users with a specified status. Limited by the maximum query count define in the global configuration.
      * 
      * @param status the status, from 'UserData'.
      * @return all EndEntityInformation objects or an empty list
      */
     List<EndEntityInformation> findAllBatchUsersByStatusWithLimit(int status);
     
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
      * @param numberofrows the number of rows to fetch, use 0 for the maximum query count define in the global configuration.
      * @param endentityAccessRule The end entity access rule that is necessary 
      *            to execute the query
      * @return a collection of EndEntityInformation.
      * @throws IllegalQueryException when query parameters internal rules isn't
      *            fulfilled.
      * @see org.ejbca.util.query.Query
      */
     Collection<EndEntityInformation> query(AuthenticationToken admin, Query query, String caauthorizationstring,
             String endentityprofilestring, int numberofrows, String endentityAccessRule) throws IllegalQueryException;

     /**
      * This method executes an optimized query on the ra user data.
      * The difference with the query method is that it does not pass CA authorization and EEP authorization
      * strings to the query down to the database. Instead it applies those constraints later on the returned
      * results from db. This way the performance would be improved.
      * Note that it is only used in case the subjectDN or serialNumber are used for querying the users.
      * 
      * @param admin
      * @param query
      * @param numberOfRows
      * @param endentityAccessRule
      * @return
      * @throws IllegalQueryException
      */
     Collection<EndEntityInformation> queryOptimized(AuthenticationToken admin, Query query, int numberOfRows, String endentityAccessRule) throws IllegalQueryException;
     
     /**
      * Retrieves a collection of certificates as byte array generated for a user.
      * 
      * Authorization requirements:<pre>
      * - /administrator
      * - /ra_functionality/view_end_entity
      * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
      * - /ca/&lt;ca of user&gt;
      * </pre>
      *
      * @param username a unique username.
      * @param onlyValid only return valid certificates not revoked or expired ones.
      * @param now the current time as long value since epoch.
      * @return a collection of certificate wrappers or an empty list if no certificates, or no user, could be found.
      * @throws AuthorizationDeniedException if client isn't authorized to request.
      * @throws CertificateEncodingException if a certificate could not be encoded.
      */
     Collection<CertificateWrapper> findCertificatesByUsername(AuthenticationToken authenticationToken, String username, boolean onlyValid, long now)
             throws AuthorizationDeniedException, CertificateEncodingException;
     
     /**
      * Fetches an issued certificate.
      *
      * Authorization requirements:<pre>
      * - A valid certificate
      * - /ca_functionality/view_certificate
      * - /ca/&lt;of the issing CA&gt;
      * </pre>
      *
      * @param authenticationToken the administrator performing the action.
      * @param certSNinHex the certificate serial number in hexadecimal representation.
      * @param issuerDN the issuer of the certificate.
      * @return the certificate wrapper or null if certificate couldn't be found.
      * @throws AuthorizationDeniedException if the calling administrator isn't authorized to view the certificate.
      * @throws CADoesntExistsException if a referenced CA does not exist.
      * @throws EjbcaException any EjbcaException.
      */
     public CertificateWrapper getCertificate(AuthenticationToken authenticationToken, String certSNinHex, String issuerDN)
             throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException;
}
