package se.anatom.ejbca.hardtoken;

import java.math.BigInteger;
import java.util.Collection;
import java.util.TreeMap;
import java.security.cert.X509Certificate;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.hardtoken.hardtokentypes.*;

/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: IHardTokenSessionLocal.java,v 1.2 2003-03-01 20:53:59 herrvendil Exp $
 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
 */

public interface IHardTokenSessionLocal extends javax.ejb.EJBLocalObject

{

    public final static int NO_ISSUER = IHardTokenSessionRemote.NO_ISSUER;
    
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */      
    
    public boolean addHardTokenIssuer(Admin admin, String alias, BigInteger certificatesn, String certissuerdn, HardTokenIssuer issuerdata);   
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public boolean changeHardTokenIssuer(Admin admin, String alias, HardTokenIssuer issuerdata);    
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public boolean cloneHardTokenIssuer(Admin admin, String oldalias, String newalias, 
                                        BigInteger newcertificatesn, String newcertissuerdn);
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public void removeHardTokenIssuer(Admin admin, String alias);
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public boolean renameHardTokenIssuer(Admin admin, String oldalias, String newalias,
                                         BigInteger newcertificatesn, String newcertissuerdn);   
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public Collection getHardTokenIssuerDatas(Admin admin);
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public Collection getHardTokenIssuerAliases(Admin admin);   

    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */      
    
    public TreeMap getHardTokenIssuers(Admin admin);
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public HardTokenIssuerData getHardTokenIssuerData(Admin admin, String alias);
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public HardTokenIssuerData getHardTokenIssuerData(Admin admin, int id);

    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public int getNumberOfHardTokenIssuers(Admin admin);
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public int getHardTokenIssuerId(Admin admin, String alias);
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public int getHardTokenIssuerId(Admin admin, X509Certificate issuercertificate);    
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public String getHardTokenIssuerAlias(Admin admin, int id);  
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public void getIsTokenTypeAvailableToIssuer(Admin admin, int issuerid, UserAdminData userdata) throws UnavailableTokenException;
       
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public void addHardToken(Admin admin, String tokensn, String username, int tokentype, HardToken hardtokendata, Collection certificates) throws HardTokenExistsException;      
  
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public void changeHardToken(Admin admin, String tokensn, int tokentype, HardToken hardtokendata) throws HardTokenDoesntExistsException;  
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public void removeHardToken(Admin admin, String tokensn) throws HardTokenDoesntExistsException;      
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public HardTokenData getHardToken(Admin admin, String tokensn);
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */     
    
    public Collection getHardTokens(Admin admin, String username);        
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public boolean existsHardToken(Admin admin, String tokensn);     
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public void addHardTokenCertificateMapping(Admin admin, String tokensn, X509Certificate Certificate);      
  
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public void removeHardTokenCertificateMapping(Admin admin, X509Certificate Certificate);     
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public Collection findCertificatesInHardToken(Admin admin, String tokensn);      
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public AvailableHardToken[] getAvailableHardTokens();
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public void tokenGenerated(Admin admin, String tokensn, String username);
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public void errorWhenGeneratingToken(Admin admin, String tokensn, String username);     
}

