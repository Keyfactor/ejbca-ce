package se.anatom.ejbca.hardtoken;

import java.rmi.*;
import java.util.ArrayList;
import java.util.Collection;
import java.sql.*;
import javax.sql.DataSource;
import javax.naming.*;
import javax.ejb.*;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.ra.UserDataLocalHome;
import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.SecConst;

/**
 * Remote interface for bean used by hardtoken batchprograms to retrieve users to generate from EJBCA RA. 
 *
 * @version $Id: LocalEjbcaHardTokenBatchJobSessionBean.java,v 1.4 2003-02-28 09:25:16 koen_serry Exp $
 */
public class LocalEjbcaHardTokenBatchJobSessionBean extends BaseSessionBean  {

    private static Logger log = Logger.getLogger(LocalEjbcaHardTokenBatchJobSessionBean.class);
    
    /** Columns in the database used in select */
    private final String USERDATA_COL = "username, subjectDN, subjectAltName, subjectEmail, status, type, clearpassword, timeCreated, timeModified, endEntityprofileId, certificateProfileId, tokenType, hardTokenIssuerId";    
    
    /** Var holding JNDI name of datasource */
    private String dataSource = "";

    /** The home interface of  User Admin entity bean */
    private UserDataLocalHome useradminsession = null;

    /** The local interface of  hard token session bean */
    private IHardTokenSessionLocal hardtokensession = null;
    
    /** The remote interface of  log session bean */    
    private ILogSessionRemote logsession = null;
         
    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
        
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
      try{  
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);
        
        useradminsession = (UserDataLocalHome) lookup("java:comp/env/ejb/UserDataLocal", UserDataLocalHome.class);
              
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
    
    /** Gets connection to hard token session bean
     * @return IHardTokenSessionLocal
     */
    private IHardTokenSessionLocal getHardTokenSession() {
        if(hardtokensession == null){
          try{  
            IHardTokenSessionLocalHome hardtokensessionhome = (IHardTokenSessionLocalHome) lookup("java:comp/env/ejb/HardTokenSession",IHardTokenSessionLocalHome.class);       
            hardtokensession = hardtokensessionhome.create();  
          }catch(Exception e){
             throw new EJBException(e);   
          }
        }  
        return hardtokensession;
    } //getHardTokenSession
    
    /** Gets connection to log session bean
     * @return Connection
     */
    private ILogSessionRemote getLogSession() {  
        if(logsession == null){
          try{  
            ILogSessionHome logsessionhome = (ILogSessionHome) lookup("java:comp/env/ejb/LogSession",ILogSessionHome.class);       
            logsession = logsessionhome.create(); 
          }catch(Exception e){
             throw new EJBException(e);   
          }
        }  
        return logsession;
    } //getLogSession    
    
    

    /**
     * Returns the next user scheduled for batch generation for the given issuer.
     *
     * @param admin the administrator performing the actions
     * @param issuercert the certificate of the hard token issuer.
     *
     * @return The next user to generate or NULL if there are no users i queue.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
       
    public UserAdminData getNextHardTokenToGenerate(Admin admin, X509Certificate issuercert) throws UnavailableTokenException{
      debug(">getNextHardTokenToGenerate()");
      UserAdminData returnval=null; 
      int issuerid = getHardTokenSession().getHardTokenIssuerId(admin, issuercert);

      if(issuerid != IHardTokenSessionLocal.NO_ISSUER){
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try{
           // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select " + USERDATA_COL + " from UserData where hardTokenIssuerId = " + issuerid + " and tokenType > " + SecConst.TOKEN_SOFT);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
           if(rs.next()){
              returnval = new UserAdminData(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getInt(5), rs.getInt(6)
                                               , rs.getInt(10), rs.getInt(11)
                                               , new java.util.Date(rs.getLong(8)), new java.util.Date(rs.getLong(9))
                                               ,  rs.getInt(12), rs.getInt(13));            
              returnval.setPassword(rs.getString(7));
            }
            if(returnval !=null){
              getHardTokenSession().getIsTokenTypeAvailableToIssuer(admin, issuerid, returnval);
              getLogSession().log(admin, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),returnval.getUsername(), null, LogEntry.EVENT_ERROR_HARDTOKEN_USERDATASENT,"Userdata sent for token generation to issuer with dn: " + issuercert.getSubjectDN().toString());             
            }
        }catch(Exception e){
          try{
            getLogSession().log(admin, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKEN_USERDATASENT,"Error when retrieving next token for issuer with dn: " + issuercert.getSubjectDN().toString());  
          }catch(RemoteException re){}              
          throw new EJBException(e);
        }finally{
           try{
             if(rs != null) rs.close();
             if(ps != null) ps.close();
             if(con!= null) con.close();
           }catch(SQLException se){
              se.printStackTrace();
           }
        }  
      }    
      debug("<getNextHardTokenToGenerate()");
      return returnval;
    }// getNextHardTokenToGenerate

    /**
     * Returns a Collection of users scheduled for batch generation for the given issuer. 
     * A maximum of MAX_RETURNED_QUEUE_SIZE users will be returned by call.
     *
     * @param admin the administrator performing the actions
     * @param issuercert the certificate of the hard token issuer.
     *
     * @return A Collection of users to generate or NULL if there are no users i queue.
     * @throws EJBException if a communication or other error occurs.
     */ 
       
    public Collection getNextHardTokensToGenerate(Admin admin, X509Certificate issuercert) throws UnavailableTokenException{
      debug(">getNextHardTokensToGenerate()");
      ArrayList returnval = new ArrayList(); 
      int issuerid = getHardTokenSession().getHardTokenIssuerId(admin, issuercert);
 
      if(issuerid != IHardTokenSessionLocal.NO_ISSUER){
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try{
           // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select " + USERDATA_COL + " from UserData where hardTokenIssuerId = " + issuerid + " and tokenType > " + SecConst.TOKEN_SOFT);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
           while(rs.next() && returnval.size() <= IHardTokenBatchJobSessionLocal.MAX_RETURNED_QUEUE_SIZE){
              UserAdminData data = new UserAdminData(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getInt(5), rs.getInt(6)
                                               , rs.getInt(10), rs.getInt(11)
                                               , new java.util.Date(rs.getLong(8)), new java.util.Date(rs.getLong(9))
                                               ,  rs.getInt(12), rs.getInt(13));            
              data.setPassword(rs.getString(7));
              getHardTokenSession().getIsTokenTypeAvailableToIssuer(admin, issuerid, data);
              returnval.add(data);
              getLogSession().log(admin, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),data.getUsername(), null, LogEntry.EVENT_ERROR_HARDTOKEN_USERDATASENT,"Userdata sent for token generation to issuer with dn: " + issuercert.getSubjectDN().toString());                
            }           
        }catch(Exception e){
          try{
            getLogSession().log(admin, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKEN_USERDATASENT,"Error when retrieving next tokens for issuer with dn: " + issuercert.getSubjectDN().toString());  
          }catch(RemoteException re){}            
          throw new EJBException(e);
        }finally{
           try{
             if(rs != null) rs.close();
             if(ps != null) ps.close();
             if(con!= null) con.close();
           }catch(SQLException se){
              se.printStackTrace();
           }
        }  
      }    

      if(returnval.size()==0)
        returnval=null;  
      
      debug("<getNextHardTokensToGenerate()");      
      return returnval;          
    }// getNextHardTokensToGenerate
    
    
    /**
     * Returns the indexed user in queue scheduled for batch generation for the given issuer.
     *
     * @param admin the administrator performing the actions
     * @param issuercert the certificate of the hard token issuer.
     * @param index index in queue of user to retrieve.
     *
     * @return The next token to generate or NULL if the given user doesn't exist in queue.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
       
    public UserAdminData getNextHardTokenToGenerateInQueue(Admin admin, X509Certificate issuercert, int index) throws UnavailableTokenException{
      debug(">getNextHardTokenToGenerateInQueue()");
      UserAdminData returnval=null; 
      int issuerid = getHardTokenSession().getHardTokenIssuerId(admin, issuercert);
 
      if(issuerid != IHardTokenSessionLocal.NO_ISSUER){
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try{
           // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select " + USERDATA_COL + " from UserData where hardTokenIssuerId = " + issuerid + " and tokenType > " + SecConst.TOKEN_SOFT);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
           if(rs.relative(index)){
              returnval = new UserAdminData(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getInt(5), rs.getInt(6)
                                               , rs.getInt(10), rs.getInt(11)
                                               , new java.util.Date(rs.getLong(8)), new java.util.Date(rs.getLong(9))
                                               ,  rs.getInt(12), rs.getInt(13));            
              returnval.setPassword(rs.getString(7));
            }
            if(returnval !=null){
              getHardTokenSession().getIsTokenTypeAvailableToIssuer(admin, issuerid, returnval);
              getLogSession().log(admin, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),returnval.getUsername(), null, LogEntry.EVENT_ERROR_HARDTOKEN_USERDATASENT,"Userdata sent for token generation to issuer with dn: " + issuercert.getSubjectDN().toString());  
            }
        }catch(Exception e){
          try{
            getLogSession().log(admin, LogEntry.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_HARDTOKEN_USERDATASENT,"Error when retrieving next token for issuer with dn: " + issuercert.getSubjectDN().toString());  
          }catch(RemoteException re){}                  
          throw new EJBException(e);
        }finally{
           try{
             if(rs != null) rs.close();
             if(ps != null) ps.close();
             if(con!= null) con.close();
           }catch(SQLException se){
              se.printStackTrace();
           }
        }  
      }    
      debug("<getNextHardTokenToGenerateInQueue()");        
      return returnval;  
    }// getNextHardTokenToGenerateInQueue
    
    
    /**
     * Returns the number of users scheduled for batch generation for the given issuer.
     *
     * @param admin the administrator performing the actions
     * @param issuercert the certificate of the hard token issuer.
     *
     * @return the number of users to generate.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
       
    public int getNumberOfHardTokensToGenerate(Admin admin, X509Certificate issuercert){
      debug(">getNumberOfHardTokensToGenerate()");
      int count = 0; 
      int issuerid = getHardTokenSession().getHardTokenIssuerId(admin, issuercert);
 
      if(issuerid != IHardTokenSessionLocal.NO_ISSUER){          
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try{
           // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select COUNT(*) from UserData where hardTokenIssuerId = " + issuerid + " and tokenType > " + SecConst.TOKEN_SOFT);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            while(rs.next()){
              count = rs.getInt(1);
            }
        }catch(Exception e){
          throw new EJBException(e);
        }finally{
           try{
             if(rs != null) rs.close();
             if(ps != null) ps.close();
             if(con!= null) con.close();
           }catch(SQLException se){
              se.printStackTrace();
           }
        }
      }
      debug("<getNumberOfHardTokensToGenerate()");        
      return count;  
    }// getNumberOfHardTokensToGenerate
    
    /**
     * Methods that checks if a user exists in the database having the given hard token issuer id. This function is mainly for avoiding
     * desyncronisation when a hard token issuer is deleted.
     *
     * @param hardtokenissuerid the id of hard token issuer to look for.
     * @return true if hardtokenissuerid exists in userdatabase.
     */
    public boolean checkForHardTokenIssuerId(Admin admin, int hardtokenissuerid){
        debug(">checkForHardTokenIssuerId(id: " + hardtokenissuerid + ")");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int count = 1; // return true as default.

        try{
           // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select COUNT(*) from UserData where hardTokenIssuerId = " + hardtokenissuerid );
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            if(rs.next()){
              count = rs.getInt(1);
            }
            debug("<checkForHardTokenIssuerId()");
            return count > 0;

        }catch(Exception e){
          throw new EJBException(e);
        }finally{
           try{
             if(rs != null) rs.close();
             if(ps != null) ps.close();
             if(con!= null) con.close();
           }catch(SQLException se){
              se.printStackTrace();
           }
        }
    } // checkForHardTokenIssuerId    
    
} // LocalRaAdminSessionBean

