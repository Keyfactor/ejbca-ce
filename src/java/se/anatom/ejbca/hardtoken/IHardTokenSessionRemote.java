package se.anatom.ejbca.hardtoken;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.TreeMap;

import se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile;
import se.anatom.ejbca.hardtoken.hardtokentypes.HardToken;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.UserAdminData;

/**
 *
 * @version $Id: IHardTokenSessionRemote.java,v 1.7 2004-01-08 14:31:26 herrvendil Exp $
 */
public interface IHardTokenSessionRemote extends javax.ejb.EJBObject {
    
    public final static int NO_ISSUER = 0;

	/**
	 * Adds a hard token profile to the database.
	 *
	 * @throws HardTokenExistsException if hard token profile already exists.
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void addHardTokenProfile(Admin admin, String name, HardTokenProfile profile) throws HardTokenProfileExistsException, RemoteException;


	/**
	 * Adds a hard token profile to the database with a given id.
	 * Should only be used when importing and exporting profiles to xml-files. 
	 *
	 * @throws HardTokenExistsException if hard token profile already exists.
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void addHardTokenProfile(Admin admin, int profileid, String name, HardTokenProfile profile) throws HardTokenProfileExistsException, RemoteException;
	
	/**
	 * Updates hard token profile data
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void changeHardTokenProfile(Admin admin, String name, HardTokenProfile profile) throws RemoteException;

	 /**
	 * Adds a hard token profile with the same content as the original profile,
	 *
     * @throws HardTokenExistsException if hard token profile already exists.
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void cloneHardTokenProfile(Admin admin, String oldname, String newname) throws HardTokenProfileExistsException, RemoteException;
	 /**
	 * Removes a hard token profile from the database.
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void removeHardTokenProfile(Admin admin, String name) throws RemoteException;
	 /**
	 * Renames a hard token profile
	 *
	 * @throws HardTokenExistsException if hard token profile already exists.
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void renameHardTokenProfile(Admin admin, String oldname, String newname) throws HardTokenProfileExistsException, RemoteException;
	
	/**
	 * Retrives a Collection of id:s (Integer) to authorized profiles.
	 *
	 * @return Collection of id:s (Integer)
	 */
	public Collection getAuthorizedHardTokenProfileIds(Admin admin) throws RemoteException;
	
	/**
	 * Method creating a hashmap mapping profile id (Integer) to profile name (String).
	 */    
	public HashMap getHardTokenProfileIdToNameMap(Admin admin) throws RemoteException;

	/**
	 * Retrives a named hard token profile.
	 */
	public HardTokenProfile getHardTokenProfile(Admin admin, String name) throws RemoteException;
	
	 /**
	  * Finds a hard token profile by id.
	  *
	  *
	  */
	public HardTokenProfile getHardTokenProfile(Admin admin, int id) throws RemoteException;
	
	/**
	 * Help method used by hard token profile proxys to indicate if it is time to
	 * update it's profile data.
	 *	 
	 */
	
	public int getHardTokenProfileUpdateCount(Admin admin, int hardtokenprofileid) throws RemoteException;

	 /**
	 * Returns a hard token profile id, given it's hard token profile name
	 *	 
	 *
	 * @return the id or 0 if hardtokenprofile cannot be found.
	 */
	public int getHardTokenProfileId(Admin admin, String name) throws RemoteException;
	
	 /**
	  * Returns a hard token profile name given its id.
	  *
	  * @return the name or null if id noesnt exists
	  * @throws EJBException if a communication or other error occurs.
	  */
	public String getHardTokenProfileName(Admin admin, int id) throws RemoteException;

	/**
	* Method to check if a certificate profile exists in any of the hard token profiles. 
	* Used to avoid desyncronization of certificate profile data.
	*
	* @param certificateprofileid the certificateprofileid to search for.
	* @return true if certificateprofileid exists in any of the hard token profiles.
	*/
   public boolean existsCertificateProfileInHardTokenProfiles(Admin admin, int id) throws RemoteException;
           
    /**
     * Adds a hard token issuer to the database.
     *
     * @return false if hard token issuer already exists. 
     * @throws EJBException if a communication or other error occurs.
     */        
    
    public boolean addHardTokenIssuer(Admin admin, String alias, int admingroupid, HardTokenIssuer issuerdata) throws RemoteException;   
    
    /**
     * Updates hard token issuer data
     *
     * @return false if  alias doesn't exists
     * @throws EJBException if a communication or other error occurs.
     */     
    
    public boolean changeHardTokenIssuer(Admin admin, String alias, HardTokenIssuer issuerdata) throws RemoteException;    
    
     /**
     * Adds a hard token issuer with the same content as the original issuer, 
     *  
     * @return false if the new alias or certificatesn already exists.
     * @throws EJBException if a communication or other error occurs.     
     */ 
    public boolean cloneHardTokenIssuer(Admin admin, String oldalias, String newalias, 
	                                    int admingroupid) throws RemoteException;
    
     /**
     * Removes a hard token issuer from the database. 
     * 
     * @throws EJBException if a communication or other error occurs.   
     */ 
    public void removeHardTokenIssuer(Admin admin, String alias) throws RemoteException;
    
     /**
     * Renames a hard token issuer
     *
     * @return false if new alias or certificatesn already exists
     * @throws EJBException if a communication or other error occurs.           
     */ 
    public boolean renameHardTokenIssuer(Admin admin, String oldalias, String newalias, 
	                                     int newadmingroupid) throws RemoteException;   
    
	/**
	 * Method to check if an administrator is authorized to issue hard tokens for
	 * the given alias.
	 * 
	 * @param admin administrator to check
	 * @param alias alias of hardtoken issuer. 
	 * @return true if administrator is authorized to issue hardtoken with given alias.
	 */
	public boolean getAuthorizedToHardTokenIssuer(Admin admin, String alias) throws RemoteException;
    
    
      /**
       * Returns the available hard token issuers.
       *
       * @return A collection of available HardTokenIssuerData.
       * @throws EJBException if a communication or other error occurs.
       */      
    public Collection getHardTokenIssuerDatas(Admin admin) throws RemoteException;
    
      /**
       * Returns the available hard token issuer alliases.
       *
       * @return A collection of available hard token issuer aliases.
       * @throws EJBException if a communication or other error occurs.
       */      
    public Collection getHardTokenIssuerAliases(Admin admin) throws RemoteException;    
    
      /**
       * Returns the available hard token issuers.
       *
       * @return A treemap of available hard token issuers.
       * @throws EJBException if a communication or other error occurs.
       */        
    public TreeMap getHardTokenIssuers(Admin admin) throws RemoteException;
    
      /**
       * Returns the specified hard token issuer.
       *
       * @return the hard token issuer data or null if hard token issuer doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */      
    public HardTokenIssuerData getHardTokenIssuerData(Admin admin, String alias) throws RemoteException;
    
       /**
       * Returns the specified  hard token issuer.
       *
       * @return the  hard token issuer data or null if  hard token issuer doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */         
    public HardTokenIssuerData getHardTokenIssuerData(Admin admin, int id) throws RemoteException;

      /**
       * Returns the number of available hard token issuer.
       *
       * @return the number of available hard token issuer.
       * @throws EJBException if a communication or other error occurs.
       */             
    public int getNumberOfHardTokenIssuers(Admin admin) throws RemoteException;
    
      /**
       * Returns a hard token issuer id given its alias.
       *
       * @return id number of hard token issuer.
       * @throws EJBException if a communication or other error occurs.
       */    
    public int getHardTokenIssuerId(Admin admin, String alias) throws RemoteException;
    
    
       /**
       * Returns a hard token issuer alias given its id.
       *
       * @return the alias or null if id noesnt exists
       * @throws EJBException if a communication or other error occurs.
       */    
    public String getHardTokenIssuerAlias(Admin admin, int id) throws RemoteException;  
    
      /**
       * Checks if a hardtoken profile is among a hard tokens issuers available token types.
       *
       * @param admin, the administrator calling the function
       * @param isserid, the id of the issuer to check.
       * @param userdata, the data of user about to be generated
       *
       * @throws UnavalableTokenException if users tokentype isn't among hard token issuers available tokentypes.
       * @throws EJBException if a communication or other error occurs.
       */    
    
    public void getIsHardTokenProfileAvailableToIssuer(Admin admin, int issuerid, UserAdminData userdata) throws UnavailableTokenException, RemoteException;
       
       /**
       * Adds a hard token to the database
       *
       * @param admin, the administrator calling the function
       * @param tokensn, The serialnumber of token.
       * @param username, the user owning the token.
       * @param significantissuerdn, indicates which CA the hard token should belong to.
       * @param hardtoken, the hard token data
       * @param certificates,  a collection of certificates places in the hard token
       * 
       * @throws EJBException if a communication or other error occurs.
       * @throws HardTokenExistsException if tokensn already exists in databas.
       */    
    public void addHardToken(Admin admin, String tokensn, String username, String significantissuerdn, int tokentype, HardToken hardtokendata, Collection certificates) throws HardTokenExistsException, RemoteException;      
  
       /**
       * changes a hard token data in the database
       *
       * @param admin, the administrator calling the function
       * @param tokensn, The serialnumber of token.
       * @param hardtoken, the hard token data
       * 
       * @throws EJBException if a communication or other error occurs.
       * @throws HardTokenDoesntExistsException if tokensn doesn't exists in databas.
       */    
    public void changeHardToken(Admin admin, String tokensn, int tokentype, HardToken hardtokendata) throws HardTokenDoesntExistsException, RemoteException;  
    
       /**
       * removes a hard token data from the database, observe the certificate to tokensn mappings isn't removed with this function.
       * the certificate mappings have to be removed separately.
       *
       * @param admin, the administrator calling the function
       * @param tokensn, The serialnumber of token.
       * 
       * @throws EJBException if a communication or other error occurs.
       * @throws HardTokenDoesntExistsException if tokensn doesn't exists in databas.
       */    
    public void removeHardToken(Admin admin, String tokensn) throws HardTokenDoesntExistsException, RemoteException;      
   
      /**
       * returns hard token data for the specified tokensn
       *
       * @param admin, the administrator calling the function
       * @param tokensn, The serialnumber of token.
       * 
       * @return the hard token data or NULL if tokensn doesnt exists in database.
       * @throws EJBException if a communication or other error occurs.
       */    
    public HardTokenData getHardToken(Admin admin, String tokensn) throws RemoteException;

      /**
       * returns hard token data for the specified user
       *
       * @param admin, the administrator calling the function
       * @param username, The username owning the tokens.
       * 
       * @return a Collection of all hard token user data.
       * @throws EJBException if a communication or other error occurs.
       */        
    public Collection getHardTokens(Admin admin, String username) throws RemoteException;    
    
       /**
       * Checks if a hard token serialnumber exists in the database
       *
       * @param admin, the administrator calling the function
       * @param tokensn, The serialnumber of token.
       * 
       * @return true if it exists or false otherwise.
       * @throws EJBException if a communication or other error occurs.
       */    
    public boolean existsHardToken(Admin admin, String tokensn) throws RemoteException;     
    
       /**
       * Adds a mapping between a hard token and a certificate
       *
       * @param admin, the administrator calling the function
       * @param tokensn, The serialnumber of token.
       * @param certificate, the certificate to map to.
       * 
       * @return true if addition went successful. False if map already exists.
       * @throws EJBException if a communication or other error occurs.
       */    
    public void addHardTokenCertificateMapping(Admin admin, String tokensn, X509Certificate Certificate) throws RemoteException;      
  
      /**
       * Removes a mapping between a hard token and a certificate
       *
       * @param admin, the administrator calling the function
       * @param certificate, the certificate to map to.
       * 
       * @return true if removal went successful. 
       * @throws EJBException if a communication or other error occurs.
       */    
    public void removeHardTokenCertificateMapping(Admin admin, X509Certificate Certificate) throws RemoteException;     
    
       /**
       * Returns all the X509Certificates places in a hard token.
       *
       * @param admin, the administrator calling the function
       * @param tokensn, The serialnumber of token.
       * 
       * @throws EJBException if a communication or other error occurs.
       */    
    public Collection findCertificatesInHardToken(Admin admin, String tokensn) throws RemoteException;      
    
    
    /** 
     * Method used to signal to the log that token was generated successfully.
     *
     * @param admin, administrator performing action
     * @param tokensn, tokensn of token generated
     * @param username, username of user token was generated for.
     * @param significantissuerdn, indicates which CA the hard token should belong to.
     *
     */
    public void tokenGenerated(Admin admin, String tokensn, String username, String significantissuerdn) throws RemoteException;
    
    /** 
     * Method used to signal to the log that error occured when generating token.
     *
     * @param admin, administrator performing action
     * @param tokensn, tokensn of token 
     * @param username, username of user token was generated for.
     * @param significantissuerdn, indicates which CA the hard token should belong to.
     *
     */
    public void errorWhenGeneratingToken(Admin admin, String tokensn, String username, String significantissuerdn) throws RemoteException;     
     
}

