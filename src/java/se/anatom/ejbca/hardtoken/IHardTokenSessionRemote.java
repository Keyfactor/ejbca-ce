package se.anatom.ejbca.hardtoken;
import java.util.Collection;
import java.util.TreeMap;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.rmi.RemoteException;
import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.hardtoken.hardtokentypes.*;

/**
 *
 * @version $Id: IHardTokenSessionRemote.java,v 1.1 2003-02-06 15:35:46 herrvendil Exp $
 */
public interface IHardTokenSessionRemote extends javax.ejb.EJBObject {
    
    public final static int NO_ISSUER = 0;

           
    /**
     * Adds a hard token issuer to the database.
     *
     * @return false if hard token issuer already exists. 
     * @throws EJBException if a communication or other error occurs.
     */        
    
    public boolean addHardTokenIssuer(Admin admin, String alias, BigInteger certificatesn, String certissuerdn, HardTokenIssuer issuerdata) throws RemoteException;   
    
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
                                        BigInteger newcertificatesn, String newcertissuerdn) throws RemoteException;
    
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
                                         BigInteger newcertificatesn, String newcertissuerdn) throws RemoteException;   
    
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
       * Returns a hard token issuer id given the issuers certificate.
       *
       * @return id number of hard token issuer.
       * @throws EJBException if a communication or other error occurs.
       */    
    public int getHardTokenIssuerId(Admin admin, X509Certificate issuercertificate) throws RemoteException;    
    
       /**
       * Returns a hard token issuer alias given its id.
       *
       * @return the alias or null if id noesnt exists
       * @throws EJBException if a communication or other error occurs.
       */    
    public String getHardTokenIssuerAlias(Admin admin, int id) throws RemoteException;  
    
        /**
       * Checks if a tokentype is among a hard tokens issuers available token types.
       *
       * @param admin, the administrator calling the function
       * @param isserid, the id of the issuer to check.
       * @param userdata, the data of user about to be generated
       *
       * @throws UnavalableTokenException if users tokentype isn't among hard token issuers available tokentypes.
       * @throws EJBException if a communication or other error occurs.
       */    
    
    public void getIsTokenTypeAvailableToIssuer(Admin admin, int issuerid, UserAdminData userdata) throws UnavailableTokenException, RemoteException;
       
       /**
       * Adds a hard token to the database
       *
       * @param admin, the administrator calling the function
       * @param tokensn, The serialnumber of token.
       * @param username, the user owning the token.
       * @param hardtoken, the hard token data
       * @param certificates,  a collection of certificates places in the hard token
       * 
       * @throws EJBException if a communication or other error occurs.
       * @throws HardTokenExistsException if tokensn already exists in databas.
       */    
    public void addHardToken(Admin admin, String tokensn, String username, int tokentype, HardToken hardtokendata, Collection certificates) throws HardTokenExistsException, RemoteException;      
  
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
       * Retrieves an array of to the system avaliable hardware tokens defines in the hard token modules ejb-jar.XML
       *
       *
       * @return an array of to the system available hard tokens.  
       * @throws EJBException if a communication or other error occurs.
       */     
    public AvailableHardToken[] getAvailableHardTokens() throws RemoteException;
     
}

