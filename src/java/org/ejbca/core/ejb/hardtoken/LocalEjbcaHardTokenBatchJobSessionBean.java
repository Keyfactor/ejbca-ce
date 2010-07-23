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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.hardtoken.UnavailableTokenException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.JDBCUtil;



/**
 * Remote interface for bean used by hardtoken batchprograms to retrieve users to generate from EJBCA RA.
 *
 * @ejb.bean
 *   description="Session bean handling userdata queue for hard token issuers"
 *   display-name="HardTokenBatchJobSessionSB"
 *   name="HardTokenBatchJobSession"
 *   jndi-name="HardTokenBatchJobSession"
 *   local-jndi-name="HardTokenBatchJobSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry
 *  description="The JDBC datasource to be used"
 *  name="DataSource"
 *  type="java.lang.String"
 *  value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.hardtoken.IHardTokenBatchJobSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.hardtoken.IHardTokenBatchJobSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.hardtoken.IHardTokenBatchJobSessionLocal"
 *   remote-class="org.ejbca.core.ejb.hardtoken.IHardTokenBatchJobSessionRemote"
 *
 * @ejb.ejb-external-ref
 *   description="The User entity bean"
 *   view-type="local"
 *   ref-name="ejb/UserDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ra.UserDataLocalHome"
 *   business="org.ejbca.core.ejb.ra.UserDataLocal"
 *   link="UserData"
 *
 * @ejb.ejb-external-ref
 *   description="The Certificate Store session bean"
 *   view-type="local"
 *   ref-name="ejb/HardTokenSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome"
 *   business="org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal"
 *   link="HardTokenSession"
 *
 * @ejb.ejb-external-ref
 *   description="The log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @jonas.bean
 *   ejb-name="HardTokenSession"
 *
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "HardTokenBatchJobSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class LocalEjbcaHardTokenBatchJobSessionBean implements HardTokenBatchJobSessionRemote, HardTokenBatchJobSessionLocal  {

    public static final int MAX_RETURNED_QUEUE_SIZE = 300;

    private static final Logger log = Logger.getLogger(LocalEjbcaHardTokenBatchJobSessionBean.class);
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /** Columns in the database used in select */
    private static final String USERDATA_COL = "username, subjectDN, subjectAltName, subjectEmail, status, type, clearPassword, timeCreated, timeModified, endEntityProfileId, certificateProfileId, tokenType, hardTokenIssuerId, cAId";

    /** The local interface of  hard token session bean */
    @EJB
    private HardTokenSessionLocal hardtokensession;

    /** The remote interface of  log session bean */
    @EJB
    private LogSessionLocal logsession;



    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */

    public void ejbCreate() throws CreateException {
    }



    /**
     * Returns the next user scheduled for batch generation for the given issuer.
     *
     * @param admin the administrator performing the actions
     *
     * @return The next user to generate or NULL if there are no users i queue.
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public UserDataVO getNextHardTokenToGenerate(Admin admin, String alias) throws UnavailableTokenException{
      log.trace(">getNextHardTokenToGenerate()");
      log.debug("alias " + alias);
      UserDataVO returnval=null;
      int issuerid = hardtokensession.getHardTokenIssuerId(admin, alias);

      log.debug("issuerid " + issuerid);

      if(issuerid != LocalHardTokenSessionBean.NO_ISSUER){
        Connection con = null;
        ResultSet rs = null;
        PreparedStatement ps = null;

        try{
           // Construct SQL query.
        	log.debug("HERE");
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select " + USERDATA_COL + " from UserData where hardTokenIssuerId=? and tokenType>? and (status=? or status=?)" );
            ps.setInt(1,issuerid);
            ps.setInt(2,SecConst.TOKEN_SOFT);
            ps.setInt(3,UserDataConstants.STATUS_NEW);
            ps.setInt(4,UserDataConstants.STATUS_KEYRECOVERY);

            // Execute query.
            rs = ps.executeQuery();

            // Assemble result.

           if(rs.next()){
           	  // TODO add support for Extended Information
              returnval = new UserDataVO(rs.getString(1), rs.getString(2), rs.getInt(14), rs.getString(3), rs.getString(4), rs.getInt(5), rs.getInt(6)
                                               , rs.getInt(10), rs.getInt(11)
                                               , new java.util.Date(rs.getLong(8)), new java.util.Date(rs.getLong(9))
                                               ,  rs.getInt(12), rs.getInt(13),null);
              returnval.setPassword(rs.getString(7));
              log.debug("found user" + returnval.getUsername());
            }
            if(returnval !=null){
              hardtokensession.getIsHardTokenProfileAvailableToIssuer(admin, issuerid, returnval);
              String msg = intres.getLocalizedMessage("hardtoken.userdatasent", alias);            	
              logsession.log(admin, returnval.getCAId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),returnval.getUsername(), null, LogConstants.EVENT_INFO_HARDTOKEN_USERDATASENT, msg);
            }
        }catch(Exception e){
        	String msg = intres.getLocalizedMessage("hardtoken.errorsenduserdata", alias);            	
        	logsession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKEN_USERDATASENT, msg);
        	throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
      }

      log.trace("<getNextHardTokenToGenerate()");
      return returnval;
    }// getNextHardTokenToGenerate

    /**
     * Returns a Collection of users scheduled for batch generation for the given issuer.
     * A maximum of MAX_RETURNED_QUEUE_SIZE users will be returned by call.
     *
     * @param admin the administrator performing the actions
     *
     * @return A Collection of users to generate or NULL if there are no users i queue.
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public Collection getNextHardTokensToGenerate(Admin admin, String alias) throws UnavailableTokenException{
      log.trace(">getNextHardTokensToGenerate()");
      ArrayList returnval = new ArrayList();
      int issuerid = hardtokensession.getHardTokenIssuerId(admin, alias);

      if(issuerid != LocalHardTokenSessionBean.NO_ISSUER){
        ResultSet rs = null;
        Connection con = null;
        PreparedStatement ps = null;
        try{
           // Construct SQL query.
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select " + USERDATA_COL + " from UserData where hardTokenIssuerId=? and tokenType>? and (status=? or status=?)" );
            ps.setInt(1,issuerid);
            ps.setInt(2,SecConst.TOKEN_SOFT);
            ps.setInt(3,UserDataConstants.STATUS_NEW);
            ps.setInt(4,UserDataConstants.STATUS_KEYRECOVERY);
            // Assemble result.
           while(rs.next() && returnval.size() <= MAX_RETURNED_QUEUE_SIZE){
              // TODO add support for Extended Information
              UserDataVO data = new UserDataVO(rs.getString(1), rs.getString(2), rs.getInt(14), rs.getString(3), rs.getString(4), rs.getInt(5), rs.getInt(6)
                                               , rs.getInt(10), rs.getInt(11)
                                               , new java.util.Date(rs.getLong(8)), new java.util.Date(rs.getLong(9))
                                               ,  rs.getInt(12), rs.getInt(13), null);
              data.setPassword(rs.getString(7));
              hardtokensession.getIsHardTokenProfileAvailableToIssuer(admin, issuerid, data);
              returnval.add(data);
              String msg = intres.getLocalizedMessage("hardtoken.userdatasent", alias);            	
              logsession.log(admin, data.getCAId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),data.getUsername(), null, LogConstants.EVENT_INFO_HARDTOKEN_USERDATASENT, msg);
            }
        }catch(Exception e){
        	String msg = intres.getLocalizedMessage("hardtoken.errorsenduserdata", alias);            	
        	logsession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKEN_USERDATASENT, msg);
        	throw new EJBException(e);
        }finally{
           JDBCUtil.close(con, ps, rs);
        }
      }

      if(returnval.size()==0) {
        returnval=null;
      }
      log.trace("<getNextHardTokensToGenerate()");
      return returnval;
    }// getNextHardTokensToGenerate


    /**
     * Returns the indexed user in queue scheduled for batch generation for the given issuer.
     *
     * @param admin the administrator performing the actions
     * @param index index in queue of user to retrieve.
     *
     * @return The next token to generate or NULL if the given user doesn't exist in queue.
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public UserDataVO getNextHardTokenToGenerateInQueue(Admin admin, String alias, int index) throws UnavailableTokenException{
      log.trace(">getNextHardTokenToGenerateInQueue()");
      UserDataVO returnval=null;
      int issuerid = hardtokensession.getHardTokenIssuerId(admin, alias);

      if(issuerid != LocalHardTokenSessionBean.NO_ISSUER){
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try{
           // Construct SQL query.
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select " + USERDATA_COL + " from UserData where hardTokenIssuerId=? and tokenType>? and (status=? or status=?)" );
            ps.setInt(1,issuerid);
            ps.setInt(2,SecConst.TOKEN_SOFT);
            ps.setInt(3,UserDataConstants.STATUS_NEW);
            ps.setInt(4,UserDataConstants.STATUS_KEYRECOVERY);

            // Assemble result.
           if(rs.relative(index)){
              // TODO add support for Extended Information
              returnval = new UserDataVO(rs.getString(1), rs.getString(2), rs.getInt(14), rs.getString(3), rs.getString(4), rs.getInt(5), rs.getInt(6)
                                               , rs.getInt(10), rs.getInt(11)
                                               , new java.util.Date(rs.getLong(8)), new java.util.Date(rs.getLong(9))
                                               ,  rs.getInt(12), rs.getInt(13), null);
              returnval.setPassword(rs.getString(7));
            }
            if(returnval !=null){
              hardtokensession.getIsHardTokenProfileAvailableToIssuer(admin, issuerid, returnval);
              String msg = intres.getLocalizedMessage("hardtoken.userdatasent", alias);            	
              logsession.log(admin, returnval.getCAId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),returnval.getUsername(), null, LogConstants.EVENT_INFO_HARDTOKEN_USERDATASENT, msg);
            }
        }catch(Exception e){
        	String msg = intres.getLocalizedMessage("hardtoken.errorsenduserdata", alias);            	
        	logsession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKEN_USERDATASENT, msg);
        	throw new EJBException(e);
        }finally{
           JDBCUtil.close(con, ps, rs);
        }
      }
      log.trace("<getNextHardTokenToGenerateInQueue()");
      return returnval;
    }// getNextHardTokenToGenerateInQueue


    /**
     * Returns the number of users scheduled for batch generation for the given issuer.
     *
     * @param admin the administrator performing the actions
     *
     * @return the number of users to generate.
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public int getNumberOfHardTokensToGenerate(Admin admin, String alias){
      log.trace(">getNumberOfHardTokensToGenerate()");
      int count = 0;
      int issuerid = hardtokensession.getHardTokenIssuerId(admin, alias);

      if(issuerid != LocalHardTokenSessionBean.NO_ISSUER){
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try{
           // Construct SQL query.
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select COUNT(*) from UserData where hardTokenIssuerId=? and tokenType>? and (status=? or status=?)");
            ps.setInt(1,issuerid);
            ps.setInt(2,SecConst.TOKEN_SOFT);
			ps.setInt(3,UserDataConstants.STATUS_NEW);
			ps.setInt(4,UserDataConstants.STATUS_KEYRECOVERY);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            while(rs.next()){
              count = rs.getInt(1);
            }
        }catch(Exception e){
          throw new EJBException(e);
        }finally{
           JDBCUtil.close(con, ps, rs);
        }
      }
      log.trace("<getNumberOfHardTokensToGenerate()");
      return count;
    }// getNumberOfHardTokensToGenerate

    /**
     * Methods that checks if a user exists in the database having the given hard token issuer id. This function is mainly for avoiding
     * desyncronisation when a hard token issuer is deleted.
     *
     * @param hardtokenissuerid the id of hard token issuer to look for.
     * @return true if hardtokenissuerid exists in userdatabase.
     * @ejb.interface-method view-type="both"
     */
    public boolean checkForHardTokenIssuerId(Admin admin, int hardtokenissuerid){
    	if (log.isTraceEnabled()) {
            log.trace(">checkForHardTokenIssuerId(id: " + hardtokenissuerid + ")");
    	}
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int count = 1; // return true as default.

        try{
           // Construct SQL query.
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select COUNT(*) from UserData where hardTokenIssuerId=?");
            ps.setInt(1,hardtokenissuerid);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            if(rs.next()){
              count = rs.getInt(1);
            }
            log.trace("<checkForHardTokenIssuerId()");
            return count > 0;

        }catch(Exception e){
          throw new EJBException(e);
        }finally{
           JDBCUtil.close(con, ps, rs);
        }
    } // checkForHardTokenIssuerId



} // LocalRaAdminSessionBean

