package se.anatom.ejbca.hardtoken;


/**
 * For docs, see HardTokenIssuerDataBean
 *
 * @version $Id: HardTokenIssuerDataLocal.java,v 1.5 2004-01-08 14:31:26 herrvendil Exp $
 **/

public interface HardTokenIssuerDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getId();

    public String getAlias();

    public void setAlias(String alias);
    
    public int getAdminGroupId();
    
    public void setAdminGroupId(int admingroupid);
   
    public HardTokenIssuer getHardTokenIssuer();

    public void setHardTokenIssuer(HardTokenIssuer issuerdata);
}

