package se.anatom.ejbca.hardtoken;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.TreeMap;

import se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile;
import se.anatom.ejbca.hardtoken.hardtokentypes.HardToken;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.UserAdminData;

/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: IHardTokenSessionLocal.java,v 1.7 2004-01-25 09:37:10 herrvendil Exp $
 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
 */

public interface IHardTokenSessionLocal extends javax.ejb.EJBLocalObject

{

    public final static int NO_ISSUER = IHardTokenSessionRemote.NO_ISSUER;
    
        
    
	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public void addHardTokenProfile(Admin admin, String name, HardTokenProfile profile) throws HardTokenProfileExistsException;

	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public void addHardTokenProfile(Admin admin, int hardtokenprofileid, String name, HardTokenProfile profile)  throws HardTokenProfileExistsException;

	
	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public void changeHardTokenProfile(Admin admin, String name, HardTokenProfile profile);

	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public void cloneHardTokenProfile(Admin admin, String oldname, String newname) throws HardTokenProfileExistsException;
	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public void removeHardTokenProfile(Admin admin, String name);
	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public void renameHardTokenProfile(Admin admin, String oldname, String newname) throws HardTokenProfileExistsException;
	
	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public Collection getAuthorizedHardTokenProfileIds(Admin admin);
	
	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public HashMap getHardTokenProfileIdToNameMap(Admin admin);

	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public HardTokenProfile getHardTokenProfile(Admin admin, String name);
	
	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public HardTokenProfile getHardTokenProfile(Admin admin, int id);
	
	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public int getHardTokenProfileUpdateCount(Admin admin, int hardtokenprofileid);

	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public int getHardTokenProfileId(Admin admin, String name);
	
	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public String getHardTokenProfileName(Admin admin, int id);

	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public boolean existsCertificateProfileInHardTokenProfiles(Admin admin, int id);
    
    
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */      
    
    public boolean addHardTokenIssuer(Admin admin, String alias, int admingroupid, HardTokenIssuer issuerdata);   
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public boolean changeHardTokenIssuer(Admin admin, String alias, HardTokenIssuer issuerdata);    
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public boolean cloneHardTokenIssuer(Admin admin, String oldalias, String newalias, 
                                        int newadmingroupid);
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public void removeHardTokenIssuer(Admin admin, String alias);
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public boolean renameHardTokenIssuer(Admin admin, String oldalias, String newalias,
                                         int newadmingroupid);   

	/**
	 * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
	 */
	public boolean getAuthorizedToHardTokenIssuer(Admin admin, String alias);
    
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
    
    public String getHardTokenIssuerAlias(Admin admin, int id);  
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public void getIsHardTokenProfileAvailableToIssuer(Admin admin, int issuerid, UserAdminData userdata) throws UnavailableTokenException;
       
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public void addHardToken(Admin admin, String tokensn, String username, String significantissuerdn, int tokentype, HardToken hardtokendata, Collection certificates, String copyof	) throws HardTokenExistsException;      
  
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
    
    public Collection findHardTokenByTokenSerialNumber(Admin admin, String searchstring);
    
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
    
    public void tokenGenerated(Admin admin, String tokensn, String username, String significantissuerdn);
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenSessionRemote
     */
    
    public void errorWhenGeneratingToken(Admin admin, String tokensn, String username, String significantissuerdn);     
}

