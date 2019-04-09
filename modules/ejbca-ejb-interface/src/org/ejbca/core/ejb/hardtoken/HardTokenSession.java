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
package org.ejbca.core.ejb.hardtoken;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.TreeMap;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.core.model.hardtoken.types.HardToken;

/** Session bean for managing hard tokens, hard token profiles and hard token issuers. 
 * A hard token is a smart card, usb token and similar. A generic thing actually.
 * 
 * @version $Id$
 */
public interface HardTokenSession {
    
    /**
     * Adds a hard token issuer to the database.
     * @return false if hard token issuer already exists.
     * @throws AuthorizationDeniedException 
     */
    boolean addHardTokenIssuer(AuthenticationToken admin, String alias, int roleId, HardTokenIssuer issuerdata) throws AuthorizationDeniedException;

    /**
     * Updates hard token issuer data
     * @return false if alias does not exist
     * @throws AuthorizationDeniedException 
     */
    boolean changeHardTokenIssuer(AuthenticationToken admin, String alias, HardTokenIssuer issuerdata) throws AuthorizationDeniedException;

    /**
     * Adds a hard token issuer with the same content as the original issuer,
     * @return false if the new alias or certificatesn already exists (???)
     * @throws AuthorizationDeniedException 
     */
    boolean cloneHardTokenIssuer(AuthenticationToken admin, String oldalias, String newalias, int roleId) throws AuthorizationDeniedException;

    /** Removes a hard token issuer from the database. 
     * @throws AuthorizationDeniedException */
    void removeHardTokenIssuer(AuthenticationToken admin, String alias) throws AuthorizationDeniedException;

    /**
     * Renames a hard token issuer
     * @return false if new alias or certificatesn already exists (???)
     * @throws AuthorizationDeniedException 
     */
    boolean renameHardTokenIssuer(AuthenticationToken admin, String oldalias, String newalias, int roleId) throws AuthorizationDeniedException;

    /**
     * Checks if the provided token is authorized to the issuer identified by the alias, 
     * and if she is authorized to edit hard token issuers.
     * 
     * @param token An AuthenticationToken
     * @param alias The alias of the hard token being checked against
     * @return true if the token is authorized to edit the issuer identified by the alias.
     */
    boolean isAuthorizedToEditHardTokenIssuer(AuthenticationToken token, String alias);
    
    /**
     * Method to check if an administrator is authorized to issue hard tokens
     * for the given alias.
     * 
     * @param admin administrator to check
     * @param alias alias of hardtoken issuer.
     * @return true if administrator is authorized to issue hardtoken with given
     *         alias.
     */
    boolean isAuthorizedToHardTokenIssuer(AuthenticationToken admin, String alias);

    /**
     * Returns the available hard token issuers authorized to the administrator.
     * @return A collection of available HardTokenIssuerData.
     */
    Collection<HardTokenIssuerInformation> getHardTokenIssuerDatas(AuthenticationToken admin);

    /**
     * Returns the available hard token issuer aliases authorized to the
     * administrator.
     * 
     * @return A collection of available hard token issuer aliases.
     */
    Collection<String> getHardTokenIssuerAliases(AuthenticationToken admin);

    /**
     * Returns the available hard token issuers authorized to the administrator.
     * @return A TreeMap of available hard token issuers.
     */
    TreeMap<String, HardTokenIssuerInformation> getHardTokenIssuers(AuthenticationToken admin);

    /** @return the hard token issuer data or null if it doesn't exist. */
    org.ejbca.core.model.hardtoken.HardTokenIssuerInformation getHardTokenIssuerInformation(String alias);

    /** @return the hard token issuer data or null if it doesn't exist. */
    org.ejbca.core.model.hardtoken.HardTokenIssuerInformation getHardTokenIssuerInformation(int id);

    /** @return the number of available hard token issuers. */
    int getNumberOfHardTokenIssuers(AuthenticationToken admin);

    /** @return a hard token issuer id given its alias. */
    int getHardTokenIssuerId(String alias);

    /** @return the alias or null if id doesn't exist. */
    String getHardTokenIssuerAlias(int id);
    
    /**
     * Adds a hard token to the database
     * 
     * @param admin the administrator calling the function
     * @param tokensn The serial number of token.
     * @param username the user owning the token.
     * @param significantissuerdn indicates which CA the hard token should belong to.
     * @param hardtokendata the hard token data
     * @param certificates a collection of certificates places in the hard token
     * @param copyof indicates if the newly created token is a copy of an existing
     *            token. Use null if token is an original.
     * @throws HardTokenExistsException if tokensn already exists in database.
     */
    void addHardToken(AuthenticationToken admin, String tokensn, String username, String significantissuerdn,
            HardToken hardtokendata, Collection<Certificate> certificates, String copyof)
            throws HardTokenExistsException;

    /**
     * Changes a hard token data in the database.
     * 
     * @param admin the administrator calling the function
     * @param tokensn The serial number of token.
     * @param hardtokendata the hard token data
     * @throws HardTokenDoesntExistsException
     *             if tokensn does not exist in database.
     */
    void changeHardToken(AuthenticationToken admin, String tokensn, HardToken hardtokendata) throws HardTokenDoesntExistsException;

    /**
     * Removes a hard token data from the database.
     * 
     * @param admin the administrator calling the function
     * @param tokensn The serial number of token.
     * @throws HardTokenDoesntExistsException
     *             if tokensn does not exist in database.
     */
    void removeHardToken(AuthenticationToken admin, String tokensn) throws HardTokenDoesntExistsException;

    /**
     * Checks if a hard token serial number exists in the database
     * 
     * @param tokensn The serial number of token.
     * @return true if it exists or false otherwise.
     */
    boolean existsHardToken(String tokensn);

    /**
     * Returns hard token data for the specified tokensn.
     * 
     * @param admin the administrator calling the function
     * @param tokensn The serial number of token.
     * @return the hard token data or null if tokensn does not exist in database.
     */
    HardTokenInformation getHardToken(AuthenticationToken admin, String tokensn, boolean includePUK) throws AuthorizationDeniedException;

    /**
     * Returns hard token data for the specified user.
     * 
     * @param admin the administrator calling the function
     * @param username The username owning the tokens.
     * @return a Collection of all hard token user data.
     */
    Collection<HardTokenInformation> getHardTokens(AuthenticationToken admin, String username, boolean includePUK);

    /**
     * Method that searches the database for a tokensn. It returns all
     * HardTokens with a serial number that begins with the given search-pattern.
     * 
     * @param searchpattern of beginning of hard token sn
     * @return a Collection of username(String) matching the search string
     */
    Collection<String> matchHardTokenByTokenSerialNumber(String searchpattern);

    /**
     * Adds a mapping between a hard token and a certificate.
     * 
     * @param admin the administrator calling the function
     * @param tokensn The serialnumber of token.
     * @param certificate the certificate to map to.
     */
    void addHardTokenCertificateMapping(AuthenticationToken admin, String tokensn, Certificate certificate);

    /**
     * Removes a mapping between a hard token and a certificate.
     * 
     * @param admin the administrator calling the function
     * @param certificate the certificate to map to.
     */
    void removeHardTokenCertificateMapping(AuthenticationToken admin, Certificate certificate);

    /**
     * Returns all the X509Certificates places in a hard token.
     * 
     * @param tokensn The serialnumber of token.
     * @return a collection of X509Certificates
     */
    Collection<Certificate> findCertificatesInHardToken(String tokensn);

    /**
     * Returns the tokensn that belongs to a given certificatesn and
     * tokensn.
     * 
     * @param certificatesn The serial number of certificate.
     * @param issuerdn the issuerdn of the certificate.
     * @return the serial number or null if no tokensn could be found.
     */
    String findHardTokenByCertificateSNIssuerDN(BigInteger certificatesn, String issuerdn);

    /**
     * Method used to signal to the log that token was generated successfully.
     * 
     * @param admin administrator performing action
     * @param tokensn tokensn of token generated
     * @param username username of user token was generated for.
     * @param significantissuerdn
     *            indicates which CA the hard token should belong to.
     */
    void tokenGenerated(AuthenticationToken admin, String tokensn, String username, String significantissuerdn);

    /**
     * Method used to signal to the log that error occurred when generating
     * token.
     * 
     * @param admin administrator performing action
     * @param tokensn tokensn of token.
     * @param username username of user token was generated for.
     * @param significantissuerdn
     *            indicates which CA the hard token should belong to.
     */
    void errorWhenGeneratingToken(AuthenticationToken admin, String tokensn, String username, String significantissuerdn);
    
}
