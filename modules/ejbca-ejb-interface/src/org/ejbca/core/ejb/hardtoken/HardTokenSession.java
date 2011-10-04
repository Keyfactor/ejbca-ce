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

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.TreeMap;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.model.hardtoken.HardTokenData;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.HardTokenIssuerData;
import org.ejbca.core.model.hardtoken.HardTokenProfileExistsException;
import org.ejbca.core.model.hardtoken.UnavailableTokenException;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfile;
import org.ejbca.core.model.hardtoken.types.HardToken;

/** Session bean for managing hard tokens, hard token profiles and hard token issuers. 
 * A hard token is a smart card, usb token and similar. A generic thing actually.
 * 
 * @version $Id$
 */
public interface HardTokenSession {

	/**
     * Adds a hard token profile to the database.
     * @throws HardTokenProfileExistsException if hard token already exists.
     */
    public void addHardTokenProfile(AuthenticationToken admin, String name, HardTokenProfile profile) throws HardTokenProfileExistsException;

    /**
     * Adds a hard token profile to the database. Used for importing and
     * exporting profiles from xml-files.
     * 
     * @throws HardTokenProfileExistsException if hard token already exists.
     */
    public void addHardTokenProfile(AuthenticationToken admin, int profileid, String name, HardTokenProfile profile) throws HardTokenProfileExistsException;

    /** Updates hard token profile data. */
    public void changeHardTokenProfile(AuthenticationToken admin, String name, HardTokenProfile profile);

    /**
     * Adds a hard token profile with the same content as the original profile,
     * @throws HardTokenProfileExistsException if hard token already exists.
     */
    public void cloneHardTokenProfile(AuthenticationToken admin, String oldname, String newname) throws HardTokenProfileExistsException;

    /** Removes a hard token profile from the database. */
    public void removeHardTokenProfile(AuthenticationToken admin, String name);

    /**
     * Renames a hard token profile
     * @throws HardTokenProfileExistsException if hard token already exists.
     */
    public void renameHardTokenProfile(AuthenticationToken admin, String oldname, String newname) throws HardTokenProfileExistsException;

    /**
     * Retrieves a Collection of id:s (Integer) to authorized profiles.
     * Authorized hard token profiles are profiles containing only authorized
     * certificate profiles and caids.
     * 
     * @return Collection of id:s (Integer)
     */
    public Collection<Integer> getAuthorizedHardTokenProfileIds(AuthenticationToken admin);

    /** @return a mapping of profile id (Integer) to profile name (String). */
    public HashMap<Integer, String> getHardTokenProfileIdToNameMap(AuthenticationToken admin);

    /** Retrieves a named hard token profile. */
    public HardTokenProfile getHardTokenProfile(AuthenticationToken admin, String name);

    /** Finds a hard token profile by id. */
    public HardTokenProfile getHardTokenProfile(AuthenticationToken admin, int id);

    /**
     * Help method used by hard token profile proxys to indicate if it is time
     * to update it's profile data.
     */
    public int getHardTokenProfileUpdateCount(AuthenticationToken admin, int hardtokenprofileid);

    /** @return a hard token profile id from it's name or 0 if it can't be found. */
    public int getHardTokenProfileId(AuthenticationToken admin, String name);

    /**
     * Returns a hard token profile name given its id.
     * @return the name or null if id doesn't exist
     */
    public String getHardTokenProfileName(AuthenticationToken admin, int id);

    /**
     * Adds a hard token issuer to the database.
     * @return false if hard token issuer already exists.
     */
    public boolean addHardTokenIssuer(AuthenticationToken admin, String alias, int admingroupid, HardTokenIssuer issuerdata);

    /**
     * Updates hard token issuer data
     * @return false if alias does not exist
     */
    public boolean changeHardTokenIssuer(AuthenticationToken admin, String alias, HardTokenIssuer issuerdata);

    /**
     * Adds a hard token issuer with the same content as the original issuer,
     * @return false if the new alias or certificatesn already exists (???)
     */
    public boolean cloneHardTokenIssuer(AuthenticationToken admin, String oldalias, String newalias, int admingroupid);

    /** Removes a hard token issuer from the database. */
    public void removeHardTokenIssuer(AuthenticationToken admin, String alias);

    /**
     * Renames a hard token issuer
     * @return false if new alias or certificatesn already exists (???)
     */
    public boolean renameHardTokenIssuer(AuthenticationToken admin, String oldalias, String newalias, int newadmingroupid);

    /**
     * Method to check if an administrator is authorized to issue hard tokens
     * for the given alias.
     * 
     * @param admin administrator to check
     * @param alias alias of hardtoken issuer.
     * @return true if administrator is authorized to issue hardtoken with given
     *         alias.
     */
    public boolean isAuthorizedToHardTokenIssuer(AuthenticationToken admin, String alias);

    /**
     * Returns the available hard token issuers authorized to the administrator.
     * @return A collection of available HardTokenIssuerData.
     */
    public Collection<HardTokenIssuerData> getHardTokenIssuerDatas(AuthenticationToken admin);

    /**
     * Returns the available hard token issuer aliases authorized to the
     * administrator.
     * 
     * @return A collection of available hard token issuer aliases.
     */
    public Collection<String> getHardTokenIssuerAliases(AuthenticationToken admin);

    /**
     * Returns the available hard token issuers authorized to the administrator.
     * @return A TreeMap of available hard token issuers.
     */
    public TreeMap<String, HardTokenIssuerData> getHardTokenIssuers(AuthenticationToken admin);

    /** @return the hard token issuer data or null if it doesn't exist. */
    public org.ejbca.core.model.hardtoken.HardTokenIssuerData getHardTokenIssuerData(AuthenticationToken admin, java.lang.String alias);

    /** @return the hard token issuer data or null if it doesn't exist. */
    public org.ejbca.core.model.hardtoken.HardTokenIssuerData getHardTokenIssuerData(AuthenticationToken admin, int id);

    /** @return the number of available hard token issuers. */
    public int getNumberOfHardTokenIssuers(AuthenticationToken admin);

    /** @return a hard token issuer id given its alias. */
    public int getHardTokenIssuerId(AuthenticationToken admin, String alias);

    /** @return the alias or null if id doesn't exist. */
    public String getHardTokenIssuerAlias(AuthenticationToken admin, int id);

    /**
     * Checks if a hard token profile is among a hard tokens issuers available
     * token types.
     * 
     * @param admin the administrator calling the function
     * @param issuerid the id of the issuer to check.
     * @param userdata the data of user about to be generated
     * @throws UnavailableTokenException
     *             if users tokentype isn't among hard token issuers available
     *             tokentypes.
     */
    public void getIsHardTokenProfileAvailableToIssuer(AuthenticationToken admin, int issuerid, EndEntityInformation userdata) throws UnavailableTokenException;

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
    public void addHardToken(AuthenticationToken admin, String tokensn, String username, String significantissuerdn,
            int tokentype, HardToken hardtokendata, Collection<Certificate> certificates, String copyof)
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
    public void changeHardToken(AuthenticationToken admin, String tokensn, int tokentype, HardToken hardtokendata) throws HardTokenDoesntExistsException;

    /**
     * Removes a hard token data from the database.
     * 
     * @param admin the administrator calling the function
     * @param tokensn The serial number of token.
     * @throws HardTokenDoesntExistsException
     *             if tokensn does not exist in database.
     */
    public void removeHardToken(AuthenticationToken admin, String tokensn) throws HardTokenDoesntExistsException;

    /**
     * Checks if a hard token serial number exists in the database
     * 
     * @param admin the administrator calling the function
     * @param tokensn The serial number of token.
     * @return true if it exists or false otherwise.
     */
    public boolean existsHardToken(AuthenticationToken admin, String tokensn);

    /**
     * Returns hard token data for the specified tokensn.
     * 
     * @param admin the administrator calling the function
     * @param tokensn The serial number of token.
     * @return the hard token data or null if tokensn does not exist in database.
     */
    public HardTokenData getHardToken(AuthenticationToken admin, String tokensn, boolean includePUK) throws AuthorizationDeniedException;

    /**
     * Returns hard token data for the specified user.
     * 
     * @param admin the administrator calling the function
     * @param username The username owning the tokens.
     * @return a Collection of all hard token user data.
     */
    public Collection<HardTokenData> getHardTokens(AuthenticationToken admin, String username, boolean includePUK);

    /**
     * Method that searches the database for a tokensn. It returns all
     * HardTokens with a serial number that begins with the given search-pattern.
     * 
     * @param admin the administrator calling the function
     * @param searchpattern of beginning of hard token sn
     * @return a Collection of username(String) matching the search string
     */
    public Collection<String> matchHardTokenByTokenSerialNumber(AuthenticationToken admin, String searchpattern);

    /**
     * Adds a mapping between a hard token and a certificate.
     * 
     * @param admin the administrator calling the function
     * @param tokensn The serialnumber of token.
     * @param certificate the certificate to map to.
     */
    public void addHardTokenCertificateMapping(AuthenticationToken admin, String tokensn, Certificate certificate);

    /**
     * Removes a mapping between a hard token and a certificate.
     * 
     * @param admin the administrator calling the function
     * @param certificate the certificate to map to.
     */
    public void removeHardTokenCertificateMapping(AuthenticationToken admin, Certificate certificate);

    /**
     * Returns all the X509Certificates places in a hard token.
     * 
     * @param admin the administrator calling the function
     * @param tokensn The serialnumber of token.
     * @return a collection of X509Certificates
     */
    public Collection<Certificate> findCertificatesInHardToken(AuthenticationToken admin, String tokensn);

    /**
     * Returns the tokensn that belongs to a given certificatesn and
     * tokensn.
     * 
     * @param admin the administrator calling the function
     * @param certificatesn The serial number of certificate.
     * @param issuerdn the issuerdn of the certificate.
     * @return the serial number or null if no tokensn could be found.
     */
    public String findHardTokenByCertificateSNIssuerDN(AuthenticationToken admin, BigInteger certificatesn, String issuerdn);

    /**
     * Method used to signal to the log that token was generated successfully.
     * 
     * @param admin administrator performing action
     * @param tokensn tokensn of token generated
     * @param username username of user token was generated for.
     * @param significantissuerdn
     *            indicates which CA the hard token should belong to.
     */
    public void tokenGenerated(AuthenticationToken admin, String tokensn, String username, String significantissuerdn);

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
    public void errorWhenGeneratingToken(AuthenticationToken admin, String tokensn, String username, String significantissuerdn);

    /**
     * Method to check if a certificate profile exists in any of the hard token
     * profiles. Used to avoid desynchronization of certificate profile data.
     * 
     * @param id the CertificateProfile id to search for.
     * @return true if CertificateProfile id exists in any of the hard token
     *         profiles.
     */
    public boolean existsCertificateProfileInHardTokenProfiles(AuthenticationToken admin, int id);

    /**
     * Method to check if a hard token profile exists in any of the hard token
     * issuers. Used to avoid desynchronization of hard token profile data.
     * 
     * @param id the hard token profile id to search for.
     * @return true if hard token profile id exists in any of the hard token
     *         issuers.
     */
    public boolean existsHardTokenProfileInHardTokenIssuer(AuthenticationToken admin, int id);
}
