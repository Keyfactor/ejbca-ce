package se.anatom.ejbca.hardtoken;

import java.util.Date;

import se.anatom.ejbca.hardtoken.hardtokentypes.HardToken;

/**
 * For docs, see HardTokenDataBean
 *
 * @version $Id: HardTokenDataLocal.java,v 1.5 2003-09-03 12:47:24 herrvendil Exp $
 **/

public interface HardTokenDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public String getTokenSN();

    public String getUsername();
    /** username must be called 'striped' using StringTools.strip()
    * @see se.anatom.ejbca.util.StringTools
    */
    public void setUsername(String username);

    public Date getCreateTime();

    public void setCreateTime(Date createtime);

    public Date getModifyTime();

    public void setModifyTime(Date modifytime);

    public int getTokenType();

    public void setTokenType(int tokentype);
    
    public String getSignificantIssuerDN();
    
    public void setSignificantIssuerDN(String significantissuerdn);    

    public HardToken getHardToken();

    public void setHardToken(HardToken tokendata);
}

