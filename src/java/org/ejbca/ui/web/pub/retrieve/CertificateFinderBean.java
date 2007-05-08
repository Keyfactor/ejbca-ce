package org.ejbca.ui.web.pub.retrieve;

import java.rmi.RemoteException;
import java.util.Collection;

import javax.ejb.CreateException;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.rmi.PortableRemoteObject;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.ISignSessionHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;

/**
 * This bean performs a number of certificate searches for the public web.
 * 
 * @author Rolf Staflin
 * @version $Id: CertificateFinderBean.java,v 1.2 2007-05-08 07:40:50 rolf_s Exp $
 */
public class CertificateFinderBean {
	
	private static final Logger log = Logger.getLogger(CertificateFinderBean.class);

	private ISignSessionRemote mSignSession;
	private ICAAdminSessionRemote mCaAdminSession;
	private boolean mInitialized = false;
	private Admin mAdmin;
	
	/** This member is used by the JSP pages to indicate which CA they are interested in. 
	 * It is used by getCAInfo().
	 */
	private int mCurrentCA;

	public CertificateFinderBean() {
	}
	
	public void initialize(String remoteAddress) throws NamingException, RemoteException, CreateException {
		log.info(">initialize()");
	    mAdmin = new Admin(Admin.TYPE_PUBLIC_WEB_USER, remoteAddress);
		InitialContext ctx = new InitialContext();
	    final ISignSessionHome home = (ISignSessionHome) PortableRemoteObject.narrow(ctx.lookup("RSASignSession"), ISignSessionHome.class );
	    mSignSession = home.create();
		ICAAdminSessionHome cahome = (ICAAdminSessionHome) PortableRemoteObject.narrow(ctx.lookup("CAAdminSession"), ICAAdminSessionHome.class );            
	    mCaAdminSession = cahome.create();
	    mInitialized = true;
	}

	public Collection getAvailableCAs() throws RemoteException {
		log.info(">getAvailableCAs()");
		return mInitialized ? mCaAdminSession.getAvailableCAs(mAdmin) : null;
	}

	public CAInfo getCAInfo() throws RemoteException {
		log.info(">getCAInfo() currentCA = " + mCurrentCA + ", initialized == " + mInitialized);
		return mInitialized ? mCaAdminSession.getCAInfo(mAdmin, mCurrentCA) : null;
	}

	public Collection getCACertificateChain() throws RemoteException {
		log.info(">getCACertificateChain() currentCA = " + mCurrentCA + ", initialized == " + mInitialized);
		return mInitialized ? mSignSession.getCertificateChain(mAdmin, mCurrentCA) : null;
	}
	
	public int getCurrentCA() {
		return mCurrentCA;
	}

	public void setCurrentCA(Integer currentCA) {
		mCurrentCA = currentCA;
	}
}
