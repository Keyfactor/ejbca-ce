package se.anatom.ejbca.hardtoken;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Random;
import java.util.TreeMap;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BasePropertyDataLocal;
import se.anatom.ejbca.BasePropertyDataLocalHome;
import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.EIDProfile;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile;
import se.anatom.ejbca.hardtoken.hardtokentypes.EnhancedEIDHardToken;
import se.anatom.ejbca.hardtoken.hardtokentypes.HardToken;
import se.anatom.ejbca.hardtoken.hardtokentypes.SwedishEIDHardToken;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.util.CertTools;

/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalHardTokenSessionBean.java,v 1.19 2004-01-25 09:37:08 herrvendil Exp $
 */
public class LocalHardTokenSessionBean extends BaseSessionBean  {

    private static Logger log = Logger.getLogger(LocalHardTokenSessionBean.class);

    /** Var holding JNDI name of datasource */
    private String dataSource = "";

    /** The local home interface of hard token issuer entity bean. */
    private HardTokenIssuerDataLocalHome hardtokenissuerhome = null;

    /** The local home interface of hard token entity bean. */
    private HardTokenDataLocalHome hardtokendatahome = null;

	/** The local home interface of hard token entity bean. */
	private HardTokenProfileDataLocalHome hardtokenprofilehome = null;

    /** The local home interface of hard token certificate map entity bean. */
    private HardTokenCertificateMapLocalHome hardtokencertificatemaphome = null;
    
    /** The local home interface of hard token property entity bean. */
    private BasePropertyDataLocalHome hardtokenpropertyhome = null;

    /** The local interface of authorization session bean */
    private IAuthorizationSessionLocal authorizationsession = null;

    /** The local interface of certificate store session bean */
    private ICertificateStoreSessionLocal certificatestoresession = null;

    /** The remote interface of  log session bean */
    private ILogSessionLocal logsession = null;




     /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */


    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
      try{
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);
        hardtokenissuerhome = (HardTokenIssuerDataLocalHome) lookup("java:comp/env/ejb/HardTokenIssuerData", HardTokenIssuerDataLocalHome.class);
        hardtokendatahome = (HardTokenDataLocalHome) lookup("java:comp/env/ejb/HardTokenData", HardTokenDataLocalHome.class);
        hardtokencertificatemaphome = (HardTokenCertificateMapLocalHome) lookup("java:comp/env/ejb/HardTokenCertificateMap", HardTokenCertificateMapLocalHome.class);
		hardtokenprofilehome = (HardTokenProfileDataLocalHome) lookup("java:comp/env/ejb/HardTokenProfileData", HardTokenProfileDataLocalHome.class); 
		hardtokenpropertyhome = (BasePropertyDataLocalHome) lookup("java:comp/env/ejb/HardTokenPropertyData", BasePropertyDataLocalHome.class);
		
		//TODO Tempary add tree tokens
		final String SWESTANDALONESN = "SWESTANDALONESN";

		
		final String ENCMASTERSN   = "ENCMASTERSN";
		final String ENCCOPYSN1     = "ENCCOPYSN1";
		final String ENCCOPYSN2     = "ENCCOPYSN2";
		
		Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
		if(existsHardToken(admin, SWESTANDALONESN)){
			this.removeHardToken(admin, SWESTANDALONESN);		
		}
		this.addHardToken(admin, SWESTANDALONESN, "superadmin", "CN=testca", SecConst.TOKEN_SWEDISHEID, (HardToken) new SwedishEIDHardToken("initialauthencpin","authencpuk", "initialsignaturepin", "signaturepuk", this.getHardTokenProfileId(admin,"test4")), new ArrayList(), null);

		if(existsHardToken(admin, ENCMASTERSN)){
			this.removeHardToken(admin, ENCMASTERSN);	
		}
		this.addHardToken(admin, ENCMASTERSN, "superadmin", "CN=testca", SecConst.TOKEN_ENHANCEDEID,  new EnhancedEIDHardToken( "initialsignaturepin", "signaturepuk" ,"initialauthpin","authpuk","initialencpin","encpuk",true, this.getHardTokenProfileId(admin,"test4")), new ArrayList(), null);

		if(existsHardToken(admin, ENCCOPYSN1)){
			this.removeHardToken(admin, ENCCOPYSN1);			
		}			
	    this.addHardToken(admin, ENCCOPYSN1, "superadmin", "CN=testca", SecConst.TOKEN_ENHANCEDEID,  new EnhancedEIDHardToken( "initialsignaturepin", "signaturepuk" ,"initialauthpin","authpuk","initialencpin","encpuk",true, this.getHardTokenProfileId(admin,"test4")), new ArrayList(), ENCMASTERSN);
	    
		if(existsHardToken(admin, ENCCOPYSN2)){
			this.removeHardToken(admin, ENCCOPYSN2);
		}	
		this.addHardToken(admin, ENCCOPYSN2, "superadmin", "CN=testca", SecConst.TOKEN_ENHANCEDEID,  new EnhancedEIDHardToken( "initialsignaturepin", "signaturepuk" ,"initialauthpin","authpuk","initialencpin","encpuk",true, this.getHardTokenProfileId(admin,"test4")), new ArrayList(), ENCMASTERSN);
						
        debug("<ejbCreate()");
      }catch(Exception e){
         throw new EJBException(e);
      }
    }
    

    /** Gets connection to Datasource used for manual SQL searches
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
        return ds.getConnection();
    } //getConnection


    /** Gets connection to log session bean
     * @return Connection
     */
    private ILogSessionLocal getLogSession() {
        if(logsession == null){
          try{
            ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) lookup("java:comp/env/ejb/LogSessionLocal",ILogSessionLocalHome.class);
            logsession = logsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return logsession;
    } //getLogSession

    /** Gets connection to certificate store session bean
     * @return Connection
     */
    private ICertificateStoreSessionLocal getCertificateStoreSession() {
        if(certificatestoresession == null){
          try{
            ICertificateStoreSessionLocalHome certificatestoresessionhome = (ICertificateStoreSessionLocalHome) lookup("java:comp/env/ejb/CertificateStoreSessionLocal",ICertificateStoreSessionLocalHome.class);
            certificatestoresession = certificatestoresessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return certificatestoresession;
    } //getCertificateStoreSession

    /** Gets connection to authorization session bean
     * @return IAuthorizationSessionLocal
     */
    private IAuthorizationSessionLocal getAuthorizationSession(Admin admin) {
        if(authorizationsession == null){
          try{
            IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) lookup("java:comp/env/ejb/AuthorizationSessionLocal",IAuthorizationSessionLocalHome.class);
            authorizationsession = authorizationsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return authorizationsession;
    } //getAuthorizationSession





	/**
	 * Adds a hard token profile to the database.
	 *
	 * @throws HardTokenExistsException if hard token already exists.
	 * @throws EJBException if a communication or other error occurs.
	 */

	public void addHardTokenProfile(Admin admin, String name, HardTokenProfile profile) throws HardTokenProfileExistsException{
	   debug(">addHardTokenProfile(name: " + name + ")");
	   boolean success=false;	   
	   try{
		  hardtokenprofilehome.findByName(name);
	   }catch(FinderException e){
		 try{
		   hardtokenprofilehome.create(findFreeHardTokenProfileId(), name, profile);
		   success = true;
		 }catch(Exception g){}		 
	   }
     
	   if(success)
		 getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENPROFILEDATA,"Hard token profile " + name + " added.");
	   else
		 getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN,  new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENPROFILEDATA,"Error adding hard token profile "+ name);
       
		if(!success)
		  throw new HardTokenProfileExistsException();
             
	   debug("<addHardTokenProfile()");
	} // addHardTokenProfile


	/**
	 * Adds a hard token profile to the database.
	 * Used for importing and exporting profiles from xml-files.
	 * 
	 * @throws HardTokenExistsException if hard token already exists.
	 * @throws EJBException if a communication or other error occurs.
	 */

	public void addHardTokenProfile(Admin admin, int profileid, String name, HardTokenProfile profile) throws HardTokenProfileExistsException{
	   debug(">addHardTokenProfile(name: " + name + ", id: " + profileid +")");
	   boolean success=false;	   
	   try{
		  hardtokenprofilehome.findByName(name);
	   }catch(FinderException e){
	   	 try{	   	 
			hardtokenprofilehome.findByPrimaryKey(new Integer(profileid));	
		 }catch(FinderException f){	
  	       try{
		     hardtokenprofilehome.create(new Integer(profileid), name, profile);
		     success = true;
		   }catch(Exception g){}		 
	   	 }
	   }
     
	   if(success)
		 getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENPROFILEDATA,"Hard token profile " + name + " added.");
	   else
		 getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN,  new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENPROFILEDATA,"Error adding hard token profile "+ name);
       
       if(!success)
         throw new HardTokenProfileExistsException();
	   debug("<addHardTokenProfile()");	   
	} // addHardTokenProfile

	/**
	 * Updates hard token profile data
	 *	 
	 * @throws EJBException if a communication or other error occurs.
	 */

	public void changeHardTokenProfile(Admin admin, String name, HardTokenProfile profile){
	   debug(">changeHardTokenProfile(name: " + name + ")");
	   boolean success = false;	   
	   try{
		 HardTokenProfileDataLocal htp = hardtokenprofilehome.findByName(name);
		 htp.setHardTokenProfile(profile);		 
		 success = true;
	   }catch(FinderException e){}
      
	   if(success)
		 getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENPROFILEDATA,"Hard token profile " +  name + " edited.");
	   else
		 getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENPROFILEDATA,"Error editing hard token profile " + name + ".");

	   debug("<changeHardTokenProfile()");	   
	} // changeHardTokenProfile

	 /**
	 * Adds a hard token profile with the same content as the original profile,
	 *
	 * @throws HardTokenExistsException if hard token already exists.
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void cloneHardTokenProfile(Admin admin, String oldname, String newname) throws HardTokenProfileExistsException{
	   debug(">cloneHardTokenProfile(name: " + oldname + ")");
	   HardTokenProfile profiledata = null;
	   boolean success = false;	   
	   try{
		 HardTokenProfileDataLocal htp = hardtokenprofilehome.findByName(oldname);
		 profiledata = (HardTokenProfile) htp.getHardTokenProfile().clone();

         try{         
		   addHardTokenProfile(admin, newname, profiledata);
		   getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENPROFILEDATA,"New hard token profile " + newname +  ", used profile " + oldname + " as template.");
         }catch(HardTokenProfileExistsException f){
		   getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN,  new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENPROFILEDATA,"Error adding hard token profile " + newname +  " using profile " + oldname + " as template.");
		   throw f;  
         }
		 		   
	   }catch(Exception e){		  
		  throw new EJBException(e);
	   }

	   debug("<cloneHardTokenProfile()");	   
	} // cloneHardTokenProfile

	 /**
	 * Removes a hard token profile from the database.
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void removeHardTokenProfile(Admin admin, String name){
	  debug(">removeHardTokenProfile(name: " + name + ")");	  
	  try{
		HardTokenProfileDataLocal htp = hardtokenprofilehome.findByName(name);		
		htp.remove();
		getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENPROFILEDATA,"Hard token profile " + name + " removed.");
	  }catch(Exception e){
		 getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENPROFILEDATA,"Error removing hard token profile " + name + ".",e);
	  }
	  debug("<removeHardTokenProfile()");
	} // removeHardTokenProfile

	 /**
	 * Renames a hard token profile
	 *
	 * @throws HardTokenProfileExistsException if hard token already exists.
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void renameHardTokenProfile(Admin admin, String oldname, String newname) throws HardTokenProfileExistsException{										 
	   debug(">renameHardTokenProfile(from " + oldname + " to " + newname + ")");
	   boolean success = false;	   
	   try{
		  hardtokenprofilehome.findByName(newname);
	   }catch(FinderException e){
		  try{
			 HardTokenProfileDataLocal htp = hardtokenprofilehome.findByName(oldname);
			 htp.setName(newname);			 			 
			 success = true;
		  }catch(FinderException g){}		 
	   }
       
	   if(success)
		 getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENPROFILEDATA,"Hard token profile " + oldname + " renamed to " + newname +  "." );
	   else
		 getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENPROFILEDATA," Error renaming hard token profile  " + oldname +  " to " + newname + "." );

       if(!success)
	     throw new HardTokenProfileExistsException();
	   debug("<renameHardTokenProfile()");
	} // renameHardTokenProfile

	/**
	 * Retrives a Collection of id:s (Integer) to authorized profiles.
	 *
	 * @return Collection of id:s (Integer)
	 */
	public Collection getAuthorizedHardTokenProfileIds(Admin admin){
	  ArrayList returnval = new ArrayList();
	  Collection result = null;
      
	  HashSet authorizedcertprofiles = new HashSet(getCertificateStoreSession().getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_HARDTOKEN));
      
	  try{
		result = this.hardtokenprofilehome.findAll();
		Iterator i = result.iterator();
		while(i.hasNext()){
		  HardTokenProfileDataLocal next = (HardTokenProfileDataLocal) i.next();
		  HardTokenProfile profile = next.getHardTokenProfile();
		  
		  if(profile instanceof EIDProfile){		  	
		  	if(authorizedcertprofiles.containsAll(((EIDProfile) profile).getAllCertificateProfileIds())){
		  	  returnval.add(next.getId());	
		  	}		  	
		  }else{
		  	//Implement for other profile types
		  }
		}  
	  }catch(Exception e){}
	  return returnval;
	} // getAuthorizedHardTokenProfileIds    

	/**
	 * Method creating a hashmap mapping profile id (Integer) to profile name (String).
	 */    
	public HashMap getHardTokenProfileIdToNameMap(Admin admin){
	  HashMap returnval = new HashMap();
	  Collection result = null;

	  try{
		result = hardtokenprofilehome.findAll();
		Iterator i = result.iterator();
		while(i.hasNext()){
		  HardTokenProfileDataLocal next = (HardTokenProfileDataLocal) i.next();    
		  returnval.put(next.getId(),next.getName());
		}
	  }catch(FinderException e){}
	  return returnval;
	} // getHardTokenProfileIdToNameMap


	/**
	 * Retrives a named hard token profile.
	 */
	public HardTokenProfile getHardTokenProfile(Admin admin, String name){
	  HardTokenProfile returnval=null;
              
	   try{
		 returnval = (hardtokenprofilehome.findByName(name)).getHardTokenProfile();
	   } catch(FinderException e){
		   // return null if we cant find it
	   }
	   return returnval;
	} //  getCertificateProfile

	 /**
      * Finds a hard token profile by id.
	  *
	  *
	  */
	public HardTokenProfile getHardTokenProfile(Admin admin, int id){
	   HardTokenProfile returnval=null;
       
  	   try{
		   returnval = (hardtokenprofilehome.findByPrimaryKey(new Integer(id))).getHardTokenProfile();
	   } catch(FinderException e){
			 // return null if we cant find it
	   }	     
	   return returnval;
	} // getHardTokenProfile

	/**
	 * Help method used by hard token profile proxys to indicate if it is time to
	 * update it's profile data.
	 *	 
	 */
	
	public int getHardTokenProfileUpdateCount(Admin admin, int hardtokenprofileid){
	  int returnval = 0;
	  
	  try{
	  	returnval = (hardtokenprofilehome.findByPrimaryKey(new Integer(hardtokenprofileid))).getUpdateCounter();  	  	
	  }catch(FinderException e){}		
	  
	  return returnval;
	}


	 /**
	 * Returns a hard token profile id, given it's hard token profile name
	 *	 
	 *
	 * @return the id or 0 if hardtokenprofile cannot be found.
	 */
	public int getHardTokenProfileId(Admin admin, String name){
	  int returnval = 0;
            
	  try{
		Integer id = (hardtokenprofilehome.findByName(name)).getId();
		returnval = id.intValue();
	  }catch(FinderException e){}
           
	  return returnval;
	} // getHardTokenProfileId

     /**
      * Returns a hard token profile name given its id.
 	  *
	  * @return the name or null if id noesnt exists
	  * @throws EJBException if a communication or other error occurs.
	  */
	public String getHardTokenProfileName(Admin admin, int id){
	  debug(">getHardTokenProfileName(id: " + id + ")");
	  String returnval = null;
	  HardTokenProfileDataLocal htp = null;
	  try{
		htp = hardtokenprofilehome.findByPrimaryKey(new Integer(id));
		if(htp != null){
		  returnval = htp.getName();
		}
	  }catch(Exception e){}

	  debug("<getHardTokenProfileName()");
	  return returnval;
	} // getHardTokenProfileName


    /**
     * Adds a hard token issuer to the database.
     *
     * @return false if hard token issuer already exists.
     * @throws EJBException if a communication or other error occurs.
     */

    public boolean addHardTokenIssuer(Admin admin, String alias, int admingroupid, HardTokenIssuer issuerdata){
       debug(">addHardTokenIssuer(alias: " + alias + ")");
       boolean returnval=false;       
       try{
          hardtokenissuerhome.findByAlias(alias);
       }catch(FinderException e){
         try{
           hardtokenissuerhome.create(findFreeHardTokenIssuerId(), alias, admingroupid, issuerdata);
           returnval = true;
         }catch(Exception g){}         
       }
     
       if(returnval)
         getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENISSUERDATA,"Hard token issuer " + alias + " added.");
       else
         getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN,  new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENISSUERDATA,"Error adding hard token issuer "+ alias);
       
       debug("<addHardTokenIssuer()");
       return returnval;
    } // addHardTokenIssuer

    /**
     * Updates hard token issuer data
     *
     * @return false if  alias doesn't exists
     * @throws EJBException if a communication or other error occurs.
     */

    public boolean changeHardTokenIssuer(Admin admin, String alias, HardTokenIssuer issuerdata){
       debug(">changeHardTokenIssuer(alias: " + alias + ")");
       boolean returnvalue = false;
       int caid = ILogSessionLocal.INTERNALCAID;
       try{
         HardTokenIssuerDataLocal htih = hardtokenissuerhome.findByAlias(alias);
         htih.setHardTokenIssuer(issuerdata);         
         returnvalue = true;
       }catch(FinderException e){}
      
       if(returnvalue)
         getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENISSUERDATA,"Hard token issuer " +  alias + " edited.");
       else
         getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENISSUERDATA,"Error editing hard token issuer " + alias + ".");

       debug("<changeHardTokenIssuer()");
       return returnvalue;
    } // changeHardTokenIssuer

     /**
     * Adds a hard token issuer with the same content as the original issuer,
     *
     * @return false if the new alias or certificatesn already exists.
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean cloneHardTokenIssuer(Admin admin, String oldalias, String newalias, int admingroupid){
       debug(">cloneHardTokenIssuer(alias: " + oldalias + ")");
       HardTokenIssuer issuerdata = null;
       boolean returnval = false;	   
       try{
         HardTokenIssuerDataLocal htih = hardtokenissuerhome.findByAlias(oldalias);
         issuerdata = (HardTokenIssuer) htih.getHardTokenIssuer().clone();

         returnval = addHardTokenIssuer(admin, newalias, admingroupid, issuerdata);
         if(returnval)
           getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENISSUERDATA,"New hard token issuer " + newalias +  ", used issuer " + oldalias + " as template.");
         else
           getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN,  new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENISSUERDATA,"Error adding hard token issuer " + newalias +  " using issuer " + oldalias + " as template.");
       }catch(Exception e){
          throw new EJBException(e);
       }

       debug("<cloneHardTokenIssuer()");
       return returnval;
    } // cloneHardTokenIssuer

     /**
     * Removes a hard token issuer from the database.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void removeHardTokenIssuer(Admin admin, String alias){
      debug(">removeHardTokenIssuer(alias: " + alias + ")");
      int caid = ILogSessionLocal.INTERNALCAID;
      try{
        HardTokenIssuerDataLocal htih = hardtokenissuerhome.findByAlias(alias);        
        htih.remove();
        getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENISSUERDATA,"Hard token issuer " + alias + " removed.");
      }catch(Exception e){
         getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENISSUERDATA,"Error removing hard token issuer " + alias + ".",e);
      }
      debug("<removeHardTokenIssuer()");
    } // removeHardTokenIssuer

     /**
     * Renames a hard token issuer
     *
     * @return false if new alias or certificatesn already exists
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean renameHardTokenIssuer(Admin admin, String oldalias, String newalias,
                                         int newadmingroupid){
       debug(">renameHardTokenIssuer(from " + oldalias + " to " + newalias + ")");
       boolean returnvalue = false;	   	  
       try{
          hardtokenissuerhome.findByAlias(newalias);
       }catch(FinderException e){
           try{
             HardTokenIssuerDataLocal htih = hardtokenissuerhome.findByAlias(oldalias);
             htih.setAlias(newalias);
             htih.setAdminGroupId(newadmingroupid);    
             returnvalue = true;
           }catch(FinderException g){}         
       }
       
       if(returnvalue)
         getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENISSUERDATA,"Hard token issuer " + oldalias + " renamed to " + newalias +  "." );
       else
         getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENISSUERDATA," Error renaming hard token issuer  " + oldalias +  " to " + newalias + "." );

       debug("<renameHardTokenIssuer()");
       return returnvalue;
    } // renameHardTokenIssuer
    
    /**
     * Method to check if an administrator is authorized to issue hard tokens for
     * the given alias.
     * 
     * @param admin administrator to check
     * @param alias alias of hardtoken issuer. 
     * @return true if administrator is authorized to issue hardtoken with given alias.
     */
    public boolean getAuthorizedToHardTokenIssuer(Admin admin, String alias){
      boolean returnval = false;
      
      try{
      	int admingroupid = hardtokenissuerhome.findByAlias(alias).getAdminGroupId();
		returnval = authorizationsession.isAuthorizedNoLog(admin, "/hardtoken_functionality/issue_hardtokens");
      	returnval = returnval && authorizationsession.existsAdministratorInGroup(admin, admingroupid);      	 
      	
      }catch(FinderException fe){}
       catch(AuthorizationDeniedException ade){}
      	
      return returnval;	
    }

      /**
       * Returns the available hard token issuers.
       *
       * @return A collection of available HardTokenIssuerData.
       * @throws EJBException if a communication or other error occurs.
       */
    public Collection getHardTokenIssuerDatas(Admin admin){
      debug(">getHardTokenIssuerDatas()");
      ArrayList returnval = new ArrayList();
      Collection result = null;
      HardTokenIssuerDataLocal htih = null;
      try{
        result = hardtokenissuerhome.findAll();
        if(result.size()>0){
          Iterator i = result.iterator();
          while(i.hasNext()){
            htih = (HardTokenIssuerDataLocal) i.next();
            returnval.add(new HardTokenIssuerData(htih.getId().intValue(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer()));
          }
        }
        Collections.sort(returnval);
      }catch(Exception e){}

      debug("<getHardTokenIssuerDatas()");
      return returnval;
    } // getHardTokenIssuers

      /**
       * Returns the available hard token issuer alliases.
       *
       * @return A collection of available hard token issuer aliases.
       * @throws EJBException if a communication or other error occurs.
       */
    public Collection getHardTokenIssuerAliases(Admin admin){
      debug(">getHardTokenIssuerAliases()");
      ArrayList returnval = new ArrayList();
      Collection result = null;
      HardTokenIssuerDataLocal htih = null;
      try{
        result = hardtokenissuerhome.findAll();
        if(result.size()>0){
          Iterator i = result.iterator();
          while(i.hasNext()){
            htih = (HardTokenIssuerDataLocal) i.next();
            returnval.add(htih.getAlias());
          }
        }
        Collections.sort(returnval);
      }catch(Exception e){}

      debug("<getHardTokenIssuerAliases()");
      return returnval;
    }// getHardTokenIssuerAliases

      /**
       * Returns the available hard token issuers.
       *
       * @return A treemap of available hard token issuers.
       * @throws EJBException if a communication or other error occurs.
       */
    public TreeMap getHardTokenIssuers(Admin admin){
      debug(">getHardTokenIssuers()");
      TreeMap returnval = new TreeMap();
      Collection result = null;
      try{
        result = hardtokenissuerhome.findAll();
        if(result.size()>0){
          Iterator i = result.iterator();
          while(i.hasNext()){
            HardTokenIssuerDataLocal htih = (HardTokenIssuerDataLocal) i.next();
            returnval.put(htih.getAlias(), new HardTokenIssuerData(htih.getId().intValue(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer()));
          }
        }
      }catch(FinderException e){}

      debug("<getHardTokenIssuers()");
      return returnval;
    } // getHardTokenIssuers

      /**
       * Returns the specified hard token issuer.
       *
       * @return the hard token issuer data or null if hard token issuer doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */
    public HardTokenIssuerData getHardTokenIssuerData(Admin admin, String alias){
      debug(">getHardTokenIssuerData(alias: " + alias + ")");
      HardTokenIssuerData returnval = null;
      HardTokenIssuerDataLocal htih = null;
      try{
        htih = hardtokenissuerhome.findByAlias(alias);
        if(htih != null){
          returnval = new HardTokenIssuerData(htih.getId().intValue(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer());
        }
      }catch(Exception e){}

      debug("<getHardTokenIssuerData()");
      return returnval;
    } // getHardTokenIssuerData

       /**
       * Returns the specified  hard token issuer.
       *
       * @return the  hard token issuer data or null if  hard token issuer doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */
    public HardTokenIssuerData getHardTokenIssuerData(Admin admin, int id){
      debug(">getHardTokenIssuerData(id: " + id +")" );
      HardTokenIssuerData returnval = null;
      HardTokenIssuerDataLocal htih = null;
      try{
        htih = hardtokenissuerhome.findByPrimaryKey(new Integer(id));
        if(htih != null){
          returnval = new HardTokenIssuerData(htih.getId().intValue(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer());
        }
      }catch(Exception e){}

      debug("<getHardTokenIssuerData()");
      return returnval;
    } // getHardTokenIssuerData    


      /**
       * Returns the number of available hard token issuer.
       *
       * @return the number of available hard token issuer.
       * @throws EJBException if a communication or other error occurs.
       */
    public int getNumberOfHardTokenIssuers(Admin admin){
      debug(">getNumberOfHardTokenIssuers()");
      int returnval =0;
      try{
        returnval = (hardtokenissuerhome.findAll()).size();
      }catch(FinderException e){}

      debug("<getNumberOfHardTokenIssuers()");
      return returnval;
    } // getNumberOfHardTokenIssuers

      /**
       * Returns a hard token issuer id given its alias.
       *
       * @return id number of hard token issuer.
       * @throws EJBException if a communication or other error occurs.
       */
    public int getHardTokenIssuerId(Admin admin, String alias){
      debug(">getHardTokenIssuerId(alias: " + alias + ")");
      int returnval = IHardTokenSessionRemote.NO_ISSUER;
      HardTokenIssuerDataLocal htih = null;
      try{
        htih = hardtokenissuerhome.findByAlias(alias);
        if(htih != null){
          returnval = htih.getId().intValue();
        }
      }catch(Exception e){}

      debug("<getHardTokenIssuerId()");
      return returnval;
    } // getNumberOfHardTokenIssuersId

       /**
       * Returns a hard token issuer alias given its id.
       *
       * @return the alias or null if id noesnt exists
       * @throws EJBException if a communication or other error occurs.
       */
    public String getHardTokenIssuerAlias(Admin admin, int id){
      debug(">getHardTokenIssuerAlias(id: " + id + ")");
      String returnval = null;
      HardTokenIssuerDataLocal htih = null;
      try{
        htih = hardtokenissuerhome.findByPrimaryKey(new Integer(id));
        if(htih != null){
          returnval = htih.getAlias();
        }
      }catch(Exception e){}

      debug("<getHardTokenIssuerAlias()");
      return returnval;
    } // getHardTokenIssuerAlias

        /**
       * Checks if a hard token profile is among a hard tokens issuers available token types.
       *
       * @param admin, the administrator calling the function
       * @param isserid, the id of the issuer to check.
       * @param userdata, the data of user about to be generated
       *
       * @throws UnavalableTokenException if users tokentype isn't among hard token issuers available tokentypes.
       * @throws EJBException if a communication or other error occurs.
       */

    public void getIsHardTokenProfileAvailableToIssuer(Admin admin, int issuerid, UserAdminData userdata) throws UnavailableTokenException{
        debug(">getIsTokenTypeAvailableToIssuer(issuerid: " + issuerid + ", tokentype: " + userdata.getTokenType()+ ")");
        boolean returnval = false;
        ArrayList availabletokentypes = getHardTokenIssuerData(admin, issuerid).getHardTokenIssuer().getAvailableHardTokenProfiles();

        for(int i=0; i < availabletokentypes.size(); i++){
          if(((Integer) availabletokentypes.get(i)).intValue() == userdata.getTokenType())
            returnval = true;
        }

        if(!returnval)
          throw new UnavailableTokenException("Error hard token issuer cannot issue specified tokentype for user " + userdata.getUsername() + ". Change tokentype or issuer for user");
        debug("<getIsTokenTypeAvailableToIssuer()");
    } // getIsTokenTypeAvailableToIssuer

       /**
       * Adds a hard token to the database
       *
       * @param admin, the administrator calling the function
       * @param tokensn, The serialnumber of token.
       * @param username, the user owning the token.
       * @param significantissuerdn, indicates which CA the hard token should belong to.
       * @param hardtoken, the hard token data
       * @param certificates,  a collection of certificates places in the hard token
       * @param copyof indicates if the newly created token is a copy of an existing token. Use null if token is an original
       *
       * @throws EJBException if a communication or other error occurs.
       * @throws HardTokenExistsException if tokensn already exists in databas.
       */
    public void addHardToken(Admin admin, String tokensn, String username, String significantissuerdn, int tokentype,  HardToken hardtokendata, Collection certificates, String copyof) throws HardTokenExistsException{
        debug(">addHardToken(tokensn : " + tokensn + ")");
		String bcdn = CertTools.stringToBCDNString(significantissuerdn);
        try {
            hardtokendatahome.create(tokensn, username,new java.util.Date(), new java.util.Date(), tokentype, bcdn, hardtokendata);
            if(certificates != null){
              Iterator i = certificates.iterator();
              while(i.hasNext()){
                addHardTokenCertificateMapping(admin, tokensn, (X509Certificate) i.next());
              }
            }
            if(copyof != null){
            	hardtokenpropertyhome.create(tokensn, HardTokenPropertyEntityBean.PROPERTY_COPYOF,copyof);
            }
            getLogSession().log(admin, bcdn.hashCode(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),username, null, LogEntry.EVENT_INFO_HARDTOKENDATA,"Hard token with serial number : " + tokensn + " added.");
        }
        catch (Exception e) {
          getLogSession().log(admin, bcdn.hashCode(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_HARDTOKENDATA,"Trying to add hard tokensn that already exists.");
          throw new HardTokenExistsException("Tokensn : " + tokensn);
        }
        debug("<addHardToken()");
    } // addHardToken

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
    public void changeHardToken(Admin admin, String tokensn, int tokentype, HardToken hardtokendata) throws HardTokenDoesntExistsException{
        debug(">changeHardToken(tokensn : " + tokensn + ")");
        int caid = ILogSessionLocal.INTERNALCAID;
        try {
            HardTokenDataLocal htd = hardtokendatahome.findByPrimaryKey(tokensn);
            htd.setTokenType(tokentype);
            htd.setHardToken(hardtokendata);
            htd.setModifyTime(new java.util.Date());
            caid = htd.getSignificantIssuerDN().hashCode();
            getLogSession().log(admin, caid, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),htd.getUsername(), null, LogEntry.EVENT_INFO_HARDTOKENDATA,"Hard token with serial number : " + tokensn + " changed.");
        }
        catch (Exception e) {
            getLogSession().log(admin, caid, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENDATA,"Error when trying to update token with sn : " + tokensn + ".");
          throw new HardTokenDoesntExistsException("Tokensn : " + tokensn);
        }
        debug("<changeHardToken()");
    } // changeHardToken

       /**
       * removes a hard token data from the database
       *
       * @param admin, the administrator calling the function
       * @param tokensn, The serialnumber of token.
       *
       * @throws EJBException if a communication or other error occurs.
       * @throws HardTokenDoesntExistsException if tokensn doesn't exists in databas.
       */
    public void removeHardToken(Admin admin, String tokensn) throws HardTokenDoesntExistsException{
      debug(">removeHardToken(tokensn : " + tokensn + ")");
      int caid = ILogSessionLocal.INTERNALCAID;      
      try{
        HardTokenDataLocal htd = hardtokendatahome.findByPrimaryKey(tokensn);
        caid = htd.getSignificantIssuerDN().hashCode();
        htd.remove();
        
        // Remove all copyof references id property database.
       try{
        	hardtokenpropertyhome.findByProperty(tokensn, HardTokenPropertyEntityBean.PROPERTY_COPYOF).remove();         
        }catch(FinderException fe){}                                         	
        try{
          Collection copieslocal = hardtokenpropertyhome.findIdsByPropertyAndValue(HardTokenPropertyEntityBean.PROPERTY_COPYOF , tokensn);                          
          Iterator iter = copieslocal.iterator();
          while(iter.hasNext()){
        	 ((BasePropertyDataLocal) iter.next()).remove();         	
           }        
        }catch(FinderException fe){}                               
        getLogSession().log(admin, caid, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENDATA,"Hard token with sn " + tokensn + " removed.");
      }catch(Exception e){
         getLogSession().log(admin, caid, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENDATA,"Error removing hard token with sn " + tokensn + ".");
         throw new HardTokenDoesntExistsException("Tokensn : " + tokensn);
      }
      debug("<removeHardToken()");
    } // removeHardToken

       /**
       * Checks if a hard token serialnumber exists in the database
       *
       * @param admin, the administrator calling the function
       * @param tokensn, The serialnumber of token.
       *
       * @return true if it exists or false otherwise.
       * @throws EJBException if a communication or other error occurs.
       */
    public boolean existsHardToken(Admin admin, String tokensn){
       debug(">existsHardToken(tokensn : " + tokensn + ")");
       boolean ret = false;
        try {
            hardtokendatahome.findByPrimaryKey(tokensn);
            ret = true;
        } catch (javax.ejb.FinderException fe) {
             ret=false;
        } catch(Exception e){
          throw new EJBException(e);
        }
       debug("<existsHardToken()");
       return ret;
    } // existsHardToken

      /**
       * returns hard token data for the specified tokensn
       *
       * @param admin, the administrator calling the function
       * @param tokensn, The serialnumber of token.
       *
       * @return the hard token data or NULL if tokensn doesnt exists in database.
       * @throws EJBException if a communication or other error occurs.
       */
    public HardTokenData getHardToken(Admin admin, String tokensn){
       debug("<getHardToken(tokensn :" + tokensn +")");
       HardTokenData returnval = null;
       HardTokenDataLocal htd = null;
       try{
         htd = hardtokendatahome.findByPrimaryKey(tokensn);
         
         // Find Copyof
         String copyof = null;
         try{
         	copyof = hardtokenpropertyhome.findByProperty(tokensn, HardTokenPropertyEntityBean.PROPERTY_COPYOF).getValue();         	
         }catch(FinderException fe){}                          
         
         ArrayList copies = null;
         if(copyof == null){
           //  Find Copies           
	  	   try{
             Collection copieslocal = hardtokenpropertyhome.findIdsByPropertyAndValue(HardTokenPropertyEntityBean.PROPERTY_COPYOF , tokensn);         
             if(copieslocal.size() >0 ){
               copies = new ArrayList();
		       Iterator iter = copieslocal.iterator();
               while(iter.hasNext()){
           	      copies.add(((BasePropertyDataLocal) iter.next()).getId());         	
               }
             }
		   }catch(FinderException fe){}
         }         
         
         if(htd != null){
           returnval = new HardTokenData(htd.getTokenSN(),htd.getUsername(), htd.getCreateTime(),htd.getModifyTime(),htd.getTokenType(),htd.getHardToken(), copyof, copies);
           getLogSession().log(admin, htd.getSignificantIssuerDN().hashCode(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),htd.getUsername(), null, LogEntry.EVENT_INFO_HARDTOKENVIEWED,"Hard token with sn " + tokensn + " viewed.");
         }
       }catch(Exception e){}

       debug("<getHardToken()");
       return returnval;
    } // getHardToken

      /**
       * returns hard token data for the specified user
       *
       * @param admin, the administrator calling the function
       * @param username, The username owning the tokens.
       *
       * @return a Collection of all hard token user data.
       * @throws EJBException if a communication or other error occurs.
       */
    public Collection getHardTokens(Admin admin, String username){
       debug("<getHardToken(username :" + username +")");
       ArrayList returnval = new ArrayList();
       HardTokenDataLocal htd = null;
       try{
         Collection result = hardtokendatahome.findByUsername(username);
         Iterator i = result.iterator();
         while(i.hasNext()){
           htd = (HardTokenDataLocal) i.next();
           // Find Copyof
           String copyof = null;
           try{
           	copyof = hardtokenpropertyhome.findByProperty(htd.getTokenSN(), HardTokenPropertyEntityBean.PROPERTY_COPYOF).getValue();         
           }catch(FinderException fe){}         
         
           System.out.println("Token SN " + htd.getTokenSN() + "copyof" + copyof);  
           
           ArrayList copies = null;
           if(copyof == null){
           	//  Find Copies           	
           	 try{
           		Collection copieslocal = hardtokenpropertyhome.findIdsByPropertyAndValue(HardTokenPropertyEntityBean.PROPERTY_COPYOF , htd.getTokenSN());         
           		if(copieslocal.size() >0 ){
           			copies = new ArrayList();
           			Iterator iter = copieslocal.iterator();
           			while(iter.hasNext()){
           				copies.add(((BasePropertyDataLocal) iter.next()).getId());         	
           			}
           		}
           	 }catch(FinderException fe){}
           }                   
           
           returnval.add(new HardTokenData(htd.getTokenSN(),htd.getUsername(), htd.getCreateTime(),htd.getModifyTime(),htd.getTokenType(),htd.getHardToken(),copyof, copies));
           getLogSession().log(admin, htd.getSignificantIssuerDN().hashCode(), LogEntry.MODULE_HARDTOKEN, new java.util.Date(),htd.getUsername(), null, LogEntry.EVENT_INFO_HARDTOKENVIEWED,"Hard token with sn " + htd.getTokenSN() + " viewed.");
         }
       }catch(Exception e){}

       debug("<getHardToken()");
       return returnval;
    } // getHardTokens
    
    /**
     *  Method that searches the database for a tokensn. It returns all hardtokens
     * with a serialnumber that begins with the given searchpattern.
     * 
     *  @param admin the administrator calling the function
     *  @param searchpattern of begining of hard token sn
     *  @return a Collection of username(String) matching the search string
     * 
     */
    
    public Collection findHardTokenByTokenSerialNumber(Admin admin, String searchpattern){
    	debug(">findHardTokenByTokenSerialNumber()");
    	ArrayList returnval = new ArrayList();
    	Connection con = null;
    	PreparedStatement ps = null;
    	ResultSet rs = null;
    	int count = 1; // return true as default.


    	try{
    		// Construct SQL query.
    		con = getConnection();
    		ps = con.prepareStatement("select distinct username from HardTokenData where  tokenSN LIKE '" + searchpattern + "%'");
    		// Execute query.
    		rs = ps.executeQuery();
    		// Assemble result.
    		while(rs.next() && returnval.size() <= IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT){
    			returnval.add(rs.getString(1));
    		}
    		debug("<findHardTokenByTokenSerialNumber()");
    		return returnval;

    	}catch(Exception e){
    		throw new EJBException(e);
    	}finally{
    		try{
    			if(rs != null) rs.close();
    			if(ps != null) ps.close();
    			if(con!= null) con.close();
    		}catch(SQLException se){
    			error("Error at cleanup: ", se);
    		}
    	}
    	    	
    }

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
    public void addHardTokenCertificateMapping(Admin admin, String tokensn, X509Certificate certificate){
        String certificatesn = certificate.getSerialNumber().toString(16);
        debug(">addHardTokenCertificateMapping(certificatesn : "+ certificatesn  +", tokensn : " + tokensn + ")");
        int caid = CertTools.getIssuerDN(certificate).hashCode(); 
        try {
            hardtokencertificatemaphome.create(CertTools.getFingerprintAsString(certificate),tokensn);
            getLogSession().log(admin, caid, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENCERTIFICATEMAP,"Certificate mapping added, certificatesn: "  + certificatesn +", tokensn: " + tokensn + " added.");
        }
        catch (Exception e) {
          getLogSession().log(admin, caid, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENCERTIFICATEMAP,"Error adding certificate mapping, certificatesn: "  + certificatesn +", tokensn: " + tokensn);
        }
        debug("<addHardTokenCertificateMapping()");
    } // addHardTokenCertificateMapping

      /**
       * Removes a mapping between a hard token and a certificate
       *
       * @param admin, the administrator calling the function
       * @param certificate, the certificate to map to.
       *
       * @return true if removal went successful.
       * @throws EJBException if a communication or other error occurs.
       */
    public void removeHardTokenCertificateMapping(Admin admin, X509Certificate certificate){
       String certificatesn = certificate.getSerialNumber().toString(16);
       debug(">removeHardTokenCertificateMapping(Certificatesn: " + certificatesn + ")");
	   int caid = CertTools.getIssuerDN(certificate).hashCode();
      try{
        HardTokenCertificateMapLocal htcm =hardtokencertificatemaphome.findByPrimaryKey(CertTools.getFingerprintAsString(certificate));
        htcm.remove();
        getLogSession().log(admin, caid, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_INFO_HARDTOKENCERTIFICATEMAP, "Certificate mapping with certificatesn: "  + certificatesn +" removed.");
      }catch(Exception e){
         try{
           getLogSession().log(admin, caid, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKENCERTIFICATEMAP, "Error removing certificate mapping with certificatesn " + certificatesn + ".");
         }catch(Exception re){
            throw new EJBException(e);
         }
      }
      debug("<removeHardTokenCertificateMapping()");
    } // removeHardTokenCertificateMapping

       /**
       * Returns all the X509Certificates places in a hard token.
       *
       * @param admin, the administrator calling the function
       * @param tokensn, The serialnumber of token.
       *
       * @return a collection of X509Certificates
       * @throws EJBException if a communication or other error occurs.
       */
    public Collection findCertificatesInHardToken(Admin admin, String tokensn){
       debug("<findCertificatesInHardToken(username :" + tokensn +")");
       ArrayList returnval = new ArrayList();
       HardTokenCertificateMapLocal htcm = null;
       try{
         Collection result = hardtokencertificatemaphome.findByTokenSN(tokensn);
         Iterator i = result.iterator();
         while(i.hasNext()){
           htcm = (HardTokenCertificateMapLocal) i.next();
           Certificate cert = getCertificateStoreSession().findCertificateByFingerprint(admin, htcm.getCertificateFingerprint()); 
           if (cert != null) {
               returnval.add(cert);
           }
         }
       }catch(Exception e){
          throw new EJBException(e);
       }

       debug("<findCertificatesInHardToken()");
       return returnval;
    } // findCertificatesInHardToken


    /**
     * Method used to signal to the log that token was generated successfully.
     *
     * @param admin, administrator performing action
     * @param tokensn, tokensn of token generated
     * @param username, username of user token was generated for.
     * @param significantissuerdn, indicates which CA the hard token should belong to.
     *
     */
    public void tokenGenerated(Admin admin, String tokensn, String username, String significantissuerdn){
	  int caid = CertTools.stringToBCDNString(significantissuerdn).hashCode(); 	
      try{
        getLogSession().log(admin, caid, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),username, null, LogEntry.EVENT_INFO_HARDTOKENGENERATED, "Token with serialnumber : " + tokensn + " generated successfully.");
      }catch(Exception e){
        throw new EJBException(e);
      }
    } // tokenGenerated

    /**
     * Method used to signal to the log that error occured when generating token.
     *
     * @param admin, administrator performing action
     * @param tokensn, tokensn of token.
     * @param username, username of user token was generated for.
     * @param significantissuerdn, indicates which CA the hard token should belong to.
     *
     */
    public void errorWhenGeneratingToken(Admin admin, String tokensn, String username, String significantissuerdn){
      int caid = CertTools.stringToBCDNString(significantissuerdn).hashCode();	
      try{
        getLogSession().log(admin, caid, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_HARDTOKENGENERATED, "Error when generating token with serialnumber : " + tokensn + ".");
      }catch(Exception e){
        throw new EJBException(e);
      }
    } // errorWhenGeneratingToken
    
    
	/**
	* Method to check if a certificate profile exists in any of the hard token profiles. 
	* Used to avoid desyncronization of certificate profile data.
	*
	* @param certificateprofileid the certificateprofileid to search for.
	* @return true if certificateprofileid exists in any of the hard token profiles.
	*/
   public boolean existsCertificateProfileInHardTokenProfiles(Admin admin, int id){
   	 HardTokenProfile profile = null;
	 Collection certprofiles=null;
	 boolean exists = false;
	 try{
	   Collection result = hardtokenprofilehome.findAll();
	   Iterator i = result.iterator();
	   while(i.hasNext() && !exists){
		 profile = ((HardTokenProfileDataLocal) i.next()).getHardTokenProfile();
		 if(profile instanceof EIDProfile){
		   certprofiles = ((EIDProfile) profile).getAllCertificateProfileIds();
		   if(certprofiles.contains(new Integer(id)))
		     exists = true;	
		 }
	   }
	 }catch(Exception e){}

	 return exists;
   } // existsCertificateProfileInHardTokenProfiles
    
	private Integer findFreeHardTokenProfileId(){
	  int id = (new Random((new Date()).getTime())).nextInt();
	  boolean foundfree = false;

	  while(!foundfree){
		try{
		  if(id < 0 || id > SecConst.TOKEN_SOFT)
			hardtokenprofilehome.findByPrimaryKey(new Integer(id));
		    id++;
		}catch(FinderException e){
		   foundfree = true;
		}
	  }
	  return new Integer(id);
	} // findFreeHardTokenProfileId

    private Integer findFreeHardTokenIssuerId(){
      int id = (new Random((new Date()).getTime())).nextInt();
      boolean foundfree = false;

      while(!foundfree){
        try{
          if(id > 1)
            hardtokenissuerhome.findByPrimaryKey(new Integer(id));
          id++;
        }catch(FinderException e){
           foundfree = true;
        }
      }
      return new Integer(id);
    } // findFreeHardTokenIssuerId


} // LocalHardTokenSessionBean
