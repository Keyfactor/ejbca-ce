package se.anatom.ejbca.hardtoken;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.UserAdminData;

import java.security.cert.X509Certificate;

import java.util.Collection;


/**
 * Local interface for EJB, unforturnately this must be a copy of the remote interface except that
 * RemoteException is not thrown, see IHardTokenBatchJobSessionRemote for docs.
 *
 * @version $Id: IHardTokenBatchJobSessionLocal.java,v 1.3 2003-06-26 11:43:24 anatom Exp $
 *
 * @see se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionLocal
 */
public interface IHardTokenBatchJobSessionLocal extends javax.ejb.EJBLocalObject {
    public static final int MAX_RETURNED_QUEUE_SIZE = IHardTokenBatchJobSessionRemote.MAX_RETURNED_QUEUE_SIZE;

    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionRemote
     */
    public UserAdminData getNextHardTokenToGenerate(Admin admin, X509Certificate issuercert)
        throws UnavailableTokenException;

    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionRemote
     */
    public Collection getNextHardTokensToGenerate(Admin admin, X509Certificate issuercert)
        throws UnavailableTokenException;

    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionRemote
     */
    public UserAdminData getNextHardTokenToGenerateInQueue(Admin admin, X509Certificate issuercert,
        int index) throws UnavailableTokenException;

    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionRemote
     */
    public int getNumberOfHardTokensToGenerate(Admin admin, X509Certificate issuercert);

    /**
     * @see se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionRemote
     */
    public boolean checkForHardTokenIssuerId(Admin admin, int hardtokenissuerid);
}
