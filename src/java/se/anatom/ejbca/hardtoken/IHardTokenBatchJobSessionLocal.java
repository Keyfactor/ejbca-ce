package se.anatom.ejbca.hardtoken;

import java.util.Collection;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.UserAdminData;


/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see IHardTokenBatchJobSessionRemote for docs.
 *
 * @version $Id: IHardTokenBatchJobSessionLocal.java,v 1.5 2004-01-08 14:31:26 herrvendil Exp $
 * @see se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionLocal
 */

public interface IHardTokenBatchJobSessionLocal extends javax.ejb.EJBLocalObject

{
    public static final int MAX_RETURNED_QUEUE_SIZE = IHardTokenBatchJobSessionRemote.MAX_RETURNED_QUEUE_SIZE;
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionRemote
     */ 
       
    public UserAdminData getNextHardTokenToGenerate(Admin admin, String alias)  throws UnavailableTokenException;

    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionRemote
     */ 
       
    public Collection getNextHardTokensToGenerate(Admin admin, String alias)  throws UnavailableTokenException;
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionRemote
     */ 
       
    public UserAdminData getNextHardTokenToGenerateInQueue(Admin admin, String alias, int index)  throws UnavailableTokenException;
    
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionRemote
     */  
       
    public int getNumberOfHardTokensToGenerate(Admin admin, String alias);   
 
    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionRemote
     */ 
    
    public boolean checkForHardTokenIssuerId(Admin admin, int hardtokenissuerid);    

}

