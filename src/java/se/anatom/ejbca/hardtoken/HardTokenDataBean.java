package se.anatom.ejbca.hardtoken;

import java.util.Date;
import java.util.HashMap;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.hardtoken.hardtokentypes.*;
import se.anatom.ejbca.util.StringTools;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing a
 * hard token in the ra. Information stored:
 * <pre>
 *  tokenSN (Primary key)
 *  cTime (createtime)
 *  username (username)
 *  mTime (modifytime)
 *  tokenType  (tokentype)
 *  data (Data saved concerning the hard token)
 * </pre>
 *
 * @version $Id: HardTokenDataBean.java,v 1.7 2003-07-24 08:43:30 anatom Exp $
 */
public abstract class HardTokenDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(HardTokenIssuerDataBean.class);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getTokenSN();

    /**
     * DOCUMENT ME!
     *
     * @param tokensn DOCUMENT ME!
     */
    public abstract void setTokenSN(String tokensn);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @see se.anatom.ejbca.util.StringTools
     */
    public abstract void setUsername(String username);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract long getCTime();

    /**
     * DOCUMENT ME!
     *
     * @param createtime DOCUMENT ME!
     */
    public abstract void setCTime(long createtime);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract long getMTime();

    /**
     * DOCUMENT ME!
     *
     * @param modifytime DOCUMENT ME!
     */
    public abstract void setMTime(long modifytime);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract int getTokenType();

    /**
     * DOCUMENT ME!
     *
     * @param tokentype DOCUMENT ME!
     */
    public abstract void setTokenType(int tokentype);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract HashMap getData();

    /**
     * DOCUMENT ME!
     *
     * @param data DOCUMENT ME!
     */
    public abstract void setData(HashMap data);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getCreateTime() {
        return new Date(getCTime());
    }

    /**
     * DOCUMENT ME!
     *
     * @param createtime DOCUMENT ME!
     */
    public void setCreateTime(Date createtime) {
        setCTime(createtime.getTime());
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getModifyTime() {
        return new Date(getMTime());
    }

    /**
     * DOCUMENT ME!
     *
     * @param modifytime DOCUMENT ME!
     */
    public void setModifyTime(Date modifytime) {
        setMTime(modifytime.getTime());
    }

    /**
     * Method that returns the hard token issuer data and updates it if nessesary.
     *
     * @return DOCUMENT ME!
     */
    public HardToken getHardToken() {
        HardToken returnval = null;
        HashMap data = getData();
        int tokentype = ((Integer) data.get(HardToken.TOKENTYPE)).intValue();

        switch (tokentype) {
        case SecConst.TOKEN_EID:
            returnval = new EIDHardToken();

            break;

        default:
            returnval = new EIDHardToken();

            break;
        }

        returnval.loadData((Object) data);

        return returnval;
    }

    /**
     * Method that saves the hard token issuer data to database.
     *
     * @param tokendata DOCUMENT ME!
     */
    public void setHardToken(HardToken tokendata) {
        setData((HashMap) tokendata.saveData());
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of a ahrd token issuer.
     *
     * @param tokensn DOCUMENT ME!
     * @param username DOCUMENT ME!
     * @param createtime DOCUMENT ME!
     * @param modifytime DOCUMENT ME!
     * @param tokentype DOCUMENT ME!
     * @param tokendata DOCUMENT ME!
     *
     * @return null
     */
    public String ejbCreate(String tokensn, String username, Date createtime, Date modifytime,
        int tokentype, HardToken tokendata) throws CreateException {
        setTokenSN(tokensn);
        setUsername(StringTools.strip(username));
        setCTime(createtime.getTime());
        setMTime(modifytime.getTime());
        setTokenType(tokentype);
        setHardToken(tokendata);

        log.debug("Created Hard Token " + tokensn);

        return tokensn;
    }

    /**
     * DOCUMENT ME!
     *
     * @param tokensn DOCUMENT ME!
     * @param username DOCUMENT ME!
     * @param createtime DOCUMENT ME!
     * @param modifytime DOCUMENT ME!
     * @param tokentype DOCUMENT ME!
     * @param tokendata DOCUMENT ME!
     */
    public void ejbPostCreate(String tokensn, String username, Date createtime, Date modifytime,
        int tokentype, HardToken tokendata) {
        // Do nothing. Required.
    }
}
