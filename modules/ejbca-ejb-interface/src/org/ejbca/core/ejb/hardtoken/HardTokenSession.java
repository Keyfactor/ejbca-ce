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
package org.ejbca.core.ejb.hardtoken;

public interface HardTokenSession {
    /**
     * Adds a hard token profile to the database.
     * 
     * @throws HardTokenProfileExistsException
     *             if hard token already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void addHardTokenProfile(org.ejbca.core.model.log.Admin admin, java.lang.String name,
            org.ejbca.core.model.hardtoken.profiles.HardTokenProfile profile) throws org.ejbca.core.model.hardtoken.HardTokenProfileExistsException;

    /**
     * Adds a hard token profile to the database. Used for importing and
     * exporting profiles from xml-files.
     * 
     * @throws HardTokenProfileExistsException
     *             if hard token already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void addHardTokenProfile(org.ejbca.core.model.log.Admin admin, int profileid, java.lang.String name,
            org.ejbca.core.model.hardtoken.profiles.HardTokenProfile profile) throws org.ejbca.core.model.hardtoken.HardTokenProfileExistsException;

    /**
     * Updates hard token profile data
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void changeHardTokenProfile(org.ejbca.core.model.log.Admin admin, java.lang.String name,
            org.ejbca.core.model.hardtoken.profiles.HardTokenProfile profile);

    /**
     * Adds a hard token profile with the same content as the original profile,
     * 
     * @throws HardTokenProfileExistsException
     *             if hard token already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void cloneHardTokenProfile(org.ejbca.core.model.log.Admin admin, java.lang.String oldname, java.lang.String newname)
            throws org.ejbca.core.model.hardtoken.HardTokenProfileExistsException;

    /**
     * Removes a hard token profile from the database.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void removeHardTokenProfile(org.ejbca.core.model.log.Admin admin, java.lang.String name);

    /**
     * Renames a hard token profile
     * 
     * @throws HardTokenProfileExistsException
     *             if hard token already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void renameHardTokenProfile(org.ejbca.core.model.log.Admin admin, java.lang.String oldname, java.lang.String newname)
            throws org.ejbca.core.model.hardtoken.HardTokenProfileExistsException;

    /**
     * Retrives a Collection of id:s (Integer) to authorized profiles.
     * Authorized hard token profiles are profiles containing only authorized
     * certificate profiles and caids.
     * 
     * @return Collection of id:s (Integer)
     */
    public java.util.Collection getAuthorizedHardTokenProfileIds(org.ejbca.core.model.log.Admin admin);

    /**
     * Method creating a hashmap mapping profile id (Integer) to profile name
     * (String).
     */
    public java.util.HashMap getHardTokenProfileIdToNameMap(org.ejbca.core.model.log.Admin admin);

    /**
     * Retrives a named hard token profile.
     */
    public org.ejbca.core.model.hardtoken.profiles.HardTokenProfile getHardTokenProfile(org.ejbca.core.model.log.Admin admin, java.lang.String name);

    /**
     * Finds a hard token profile by id.
     */
    public org.ejbca.core.model.hardtoken.profiles.HardTokenProfile getHardTokenProfile(org.ejbca.core.model.log.Admin admin, int id);

    /**
     * Help method used by hard token profile proxys to indicate if it is time
     * to update it's profile data.
     */
    public int getHardTokenProfileUpdateCount(org.ejbca.core.model.log.Admin admin, int hardtokenprofileid);

    /**
     * Returns a hard token profile id, given it's hard token profile name
     * 
     * @return the id or 0 if hardtokenprofile cannot be found.
     */
    public int getHardTokenProfileId(org.ejbca.core.model.log.Admin admin, java.lang.String name);

    /**
     * Returns a hard token profile name given its id.
     * 
     * @return the name or null if id noesnt exists
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public java.lang.String getHardTokenProfileName(org.ejbca.core.model.log.Admin admin, int id);

    /**
     * Adds a hard token issuer to the database.
     * 
     * @return false if hard token issuer already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public boolean addHardTokenIssuer(org.ejbca.core.model.log.Admin admin, java.lang.String alias, int admingroupid,
            org.ejbca.core.model.hardtoken.HardTokenIssuer issuerdata);

    /**
     * Updates hard token issuer data
     * 
     * @return false if alias doesn't exists
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public boolean changeHardTokenIssuer(org.ejbca.core.model.log.Admin admin, java.lang.String alias, org.ejbca.core.model.hardtoken.HardTokenIssuer issuerdata);

    /**
     * Adds a hard token issuer with the same content as the original issuer,
     * 
     * @return false if the new alias or certificatesn already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public boolean cloneHardTokenIssuer(org.ejbca.core.model.log.Admin admin, java.lang.String oldalias, java.lang.String newalias, int admingroupid);

    /**
     * Removes a hard token issuer from the database.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void removeHardTokenIssuer(org.ejbca.core.model.log.Admin admin, java.lang.String alias);

    /**
     * Renames a hard token issuer
     * 
     * @return false if new alias or certificatesn already exists
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public boolean renameHardTokenIssuer(org.ejbca.core.model.log.Admin admin, java.lang.String oldalias, java.lang.String newalias, int newadmingroupid);

    /**
     * Method to check if an administrator is authorized to issue hard tokens
     * for the given alias.
     * 
     * @param admin
     *            administrator to check
     * @param alias
     *            alias of hardtoken issuer.
     * @return true if administrator is authorized to issue hardtoken with given
     *         alias.
     */
    public boolean getAuthorizedToHardTokenIssuer(org.ejbca.core.model.log.Admin admin, java.lang.String alias);

    /**
     * Returns the available hard token issuers authorized to the administrator.
     * 
     * @return A collection of available HardTokenIssuerData.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public java.util.Collection getHardTokenIssuerDatas(org.ejbca.core.model.log.Admin admin);

    /**
     * Returns the available hard token issuer alliases authorized to the
     * administrator.
     * 
     * @return A collection of available hard token issuer aliases.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public java.util.Collection getHardTokenIssuerAliases(org.ejbca.core.model.log.Admin admin);

    /**
     * Returns the available hard token issuers authorized to the administrator.
     * 
     * @return A treemap of available hard token issuers.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public java.util.TreeMap getHardTokenIssuers(org.ejbca.core.model.log.Admin admin);

    /**
     * Returns the specified hard token issuer.
     * 
     * @return the hard token issuer data or null if hard token issuer doesn't
     *         exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public org.ejbca.core.model.hardtoken.HardTokenIssuerData getHardTokenIssuerData(org.ejbca.core.model.log.Admin admin, java.lang.String alias);

    /**
     * Returns the specified hard token issuer.
     * 
     * @return the hard token issuer data or null if hard token issuer doesn't
     *         exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public org.ejbca.core.model.hardtoken.HardTokenIssuerData getHardTokenIssuerData(org.ejbca.core.model.log.Admin admin, int id);

    /**
     * Returns the number of available hard token issuer.
     * 
     * @return the number of available hard token issuer.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public int getNumberOfHardTokenIssuers(org.ejbca.core.model.log.Admin admin);

    /**
     * Returns a hard token issuer id given its alias.
     * 
     * @return id number of hard token issuer.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public int getHardTokenIssuerId(org.ejbca.core.model.log.Admin admin, java.lang.String alias);

    /**
     * Returns a hard token issuer alias given its id.
     * 
     * @return the alias or null if id noesnt exists
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public java.lang.String getHardTokenIssuerAlias(org.ejbca.core.model.log.Admin admin, int id);

    /**
     * Checks if a hard token profile is among a hard tokens issuers available
     * token types.
     * 
     * @param admin
     *            the administrator calling the function
     * @param issuerid
     *            the id of the issuer to check.
     * @param userdata
     *            the data of user about to be generated
     * @throws UnavailableTokenException
     *             if users tokentype isn't among hard token issuers available
     *             tokentypes.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void getIsHardTokenProfileAvailableToIssuer(org.ejbca.core.model.log.Admin admin, int issuerid, org.ejbca.core.model.ra.UserDataVO userdata)
            throws org.ejbca.core.model.hardtoken.UnavailableTokenException;

    /**
     * Adds a hard token to the database
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * @param username
     *            the user owning the token.
     * @param significantissuerdn
     *            indicates which CA the hard token should belong to.
     * @param hardtokendata
     *            the hard token data
     * @param certificates
     *            a collection of certificates places in the hard token
     * @param copyof
     *            indicates if the newly created token is a copy of an existing
     *            token. Use null if token is an original
     * @throws EJBException
     *             if a communication or other error occurs.
     * @throws HardTokenExistsException
     *             if tokensn already exists in databas.
     */
    public void addHardToken(org.ejbca.core.model.log.Admin admin, java.lang.String tokensn, java.lang.String username, java.lang.String significantissuerdn,
            int tokentype, org.ejbca.core.model.hardtoken.types.HardToken hardtokendata, java.util.Collection certificates, java.lang.String copyof)
            throws org.ejbca.core.model.hardtoken.HardTokenExistsException;

    /**
     * changes a hard token data in the database
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * @param hardtokendata
     *            the hard token data
     * @throws EJBException
     *             if a communication or other error occurs.
     * @throws HardTokenDoesntExistsException
     *             if tokensn doesn't exists in databas.
     */
    public void changeHardToken(org.ejbca.core.model.log.Admin admin, java.lang.String tokensn, int tokentype,
            org.ejbca.core.model.hardtoken.types.HardToken hardtokendata) throws org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;

    /**
     * removes a hard token data from the database
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * @throws EJBException
     *             if a communication or other error occurs.
     * @throws HardTokenDoesntExistsException
     *             if tokensn doesn't exists in databas.
     */
    public void removeHardToken(org.ejbca.core.model.log.Admin admin, java.lang.String tokensn)
            throws org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;

    /**
     * Checks if a hard token serialnumber exists in the database
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * @return true if it exists or false otherwise.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public boolean existsHardToken(org.ejbca.core.model.log.Admin admin, java.lang.String tokensn);

    /**
     * returns hard token data for the specified tokensn
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * @return the hard token data or NULL if tokensn doesnt exists in database.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public org.ejbca.core.model.hardtoken.HardTokenData getHardToken(org.ejbca.core.model.log.Admin admin, java.lang.String tokensn, boolean includePUK)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException;

    /**
     * returns hard token data for the specified user
     * 
     * @param admin
     *            the administrator calling the function
     * @param username
     *            The username owning the tokens.
     * @return a Collection of all hard token user data.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public java.util.Collection getHardTokens(org.ejbca.core.model.log.Admin admin, java.lang.String username, boolean includePUK);

    /**
     * Method that searches the database for a tokensn. It returns all
     * hardtokens with a serialnumber that begins with the given searchpattern.
     * 
     * @param admin
     *            the administrator calling the function
     * @param searchpattern
     *            of begining of hard token sn
     * @return a Collection of username(String) matching the search string
     */
    public java.util.Collection findHardTokenByTokenSerialNumber(org.ejbca.core.model.log.Admin admin, java.lang.String searchpattern);

    /**
     * Adds a mapping between a hard token and a certificate
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * @param certificate
     *            the certificate to map to.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void addHardTokenCertificateMapping(org.ejbca.core.model.log.Admin admin, java.lang.String tokensn, java.security.cert.Certificate certificate);

    /**
     * Removes a mapping between a hard token and a certificate
     * 
     * @param admin
     *            the administrator calling the function
     * @param certificate
     *            the certificate to map to.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void removeHardTokenCertificateMapping(org.ejbca.core.model.log.Admin admin, java.security.cert.Certificate certificate);

    /**
     * Returns all the X509Certificates places in a hard token.
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * @return a collection of X509Certificates
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public java.util.Collection findCertificatesInHardToken(org.ejbca.core.model.log.Admin admin, java.lang.String tokensn);

    /**
     * Returns the tokensn that the have blongs to a given certificatesn and
     * tokensn.
     * 
     * @param admin
     *            the administrator calling the function
     * @param certificatesn
     *            The serialnumber of certificate.
     * @param issuerdn
     *            the issuerdn of the certificate.
     * @return the serialnumber or null if no tokensn could be found.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public java.lang.String findHardTokenByCertificateSNIssuerDN(org.ejbca.core.model.log.Admin admin, java.math.BigInteger certificatesn,
            java.lang.String issuerdn);

    /**
     * Method used to signal to the log that token was generated successfully.
     * 
     * @param admin
     *            administrator performing action
     * @param tokensn
     *            tokensn of token generated
     * @param username
     *            username of user token was generated for.
     * @param significantissuerdn
     *            indicates which CA the hard token should belong to.
     */
    public void tokenGenerated(org.ejbca.core.model.log.Admin admin, java.lang.String tokensn, java.lang.String username, java.lang.String significantissuerdn);

    /**
     * Method used to signal to the log that error occured when generating
     * token.
     * 
     * @param admin
     *            administrator performing action
     * @param tokensn
     *            tokensn of token.
     * @param username
     *            username of user token was generated for.
     * @param significantissuerdn
     *            indicates which CA the hard token should belong to.
     */
    public void errorWhenGeneratingToken(org.ejbca.core.model.log.Admin admin, java.lang.String tokensn, java.lang.String username,
            java.lang.String significantissuerdn);

    /**
     * Method to check if a certificate profile exists in any of the hard token
     * profiles. Used to avoid desyncronization of certificate profile data.
     * 
     * @param id
     *            the certificateprofileid to search for.
     * @return true if certificateprofileid exists in any of the hard token
     *         profiles.
     */
    public boolean existsCertificateProfileInHardTokenProfiles(org.ejbca.core.model.log.Admin admin, int id);

    /**
     * Method to check if a hard token profile exists in any of the hard token
     * issuers. Used to avoid desyncronization of hard token profile data.
     * 
     * @param id
     *            the hard token profileid to search for.
     * @return true if hard token profileid exists in any of the hard token
     *         issuers.
     */
    public boolean existsHardTokenProfileInHardTokenIssuer(org.ejbca.core.model.log.Admin admin, int id);
}
