package se.anatom.ejbca.hardtoken;

import se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile;



/**
 * For docs, see HardTokenProfileDataBean
 *
 * @version $Id: HardTokenProfileDataLocal.java,v 1.1 2003-12-05 14:50:27 herrvendil Exp $
 **/

public interface HardTokenProfileDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getId();

    public int getUpdateCounter();

    public void setName(String name);
    
	public String getName();
     
    public HardTokenProfile getHardTokenProfile();

    public void setHardTokenProfile(HardTokenProfile profile);
}

