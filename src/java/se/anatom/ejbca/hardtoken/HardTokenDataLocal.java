package se.anatom.ejbca.hardtoken;

import se.anatom.ejbca.hardtoken.hardtokentypes.HardToken;

import java.util.Date;


/**
 * For docs, see HardTokenDataBean
 *
 * @version $Id: HardTokenDataLocal.java,v 1.3 2003-06-26 11:43:24 anatom Exp $
 */
public interface HardTokenDataLocal extends javax.ejb.EJBLocalObject {
    // Public methods
    public String getTokenSN();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @see se.anatom.ejbca.util.StringTools
     */
    public void setUsername(String username);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getCreateTime();

    /**
     * DOCUMENT ME!
     *
     * @param createtime DOCUMENT ME!
     */
    public void setCreateTime(Date createtime);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getModifyTime();

    /**
     * DOCUMENT ME!
     *
     * @param modifytime DOCUMENT ME!
     */
    public void setModifyTime(Date modifytime);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getTokenType();

    /**
     * DOCUMENT ME!
     *
     * @param tokentype DOCUMENT ME!
     */
    public void setTokenType(int tokentype);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public HardToken getHardToken();

    /**
     * DOCUMENT ME!
     *
     * @param tokendata DOCUMENT ME!
     */
    public void setHardToken(HardToken tokendata);
}
