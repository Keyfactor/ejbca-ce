package se.anatom.ejbca.hardtoken;

import se.anatom.ejbca.hardtoken.hardtokentypes.HardToken;
import se.anatom.ejbca.util.StringTools;

import java.util.Date;


/**
 * This is a value class containing the data relating to a hard token sent between server and
 * clients.
 *
 * @author TomSelleck
 * @version $Id: HardTokenData.java,v 1.3 2003-06-26 11:43:24 anatom Exp $
 */
public class HardTokenData implements java.io.Serializable {
    // Public Constructors
    public HardTokenData(String tokensn, String username, Date createtime, Date modifytime,
        int tokentype, HardToken hardtoken) {
        this.tokensn = tokensn;
        this.username = StringTools.strip(username);
        this.createtime = createtime;
        this.modifytime = modifytime;
        this.tokentype = tokentype;
        this.hardtoken = hardtoken;
    }

    /**
     * Creates a new HardTokenData object.
     */
    public HardTokenData() {
    }

    // Public Methods
    public String getTokenSN() {
        return this.tokensn;
    }

    /**
     * DOCUMENT ME!
     *
     * @param tokensn DOCUMENT ME!
     */
    public void setTokenSN(String tokensn) {
        this.tokensn = tokensn;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getUsername() {
        return this.username;
    }

    /**
     * DOCUMENT ME!
     *
     * @param username DOCUMENT ME!
     */
    public void setUsername(String username) {
        this.username = StringTools.strip(username);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getCreateTime() {
        return this.createtime;
    }

    /**
     * DOCUMENT ME!
     *
     * @param createtime DOCUMENT ME!
     */
    public void setCreateTime(Date createtime) {
        this.createtime = createtime;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getModifyTime() {
        return this.modifytime;
    }

    /**
     * DOCUMENT ME!
     *
     * @param modifytime DOCUMENT ME!
     */
    public void setModifyTime(Date modifytime) {
        this.modifytime = modifytime;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getTokenType() {
        return this.tokentype;
    }

    /**
     * DOCUMENT ME!
     *
     * @param tokentype DOCUMENT ME!
     */
    public void setTokenType(int tokentype) {
        this.tokentype = tokentype;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public HardToken getHardToken() {
        return this.hardtoken;
    }

    /**
     * DOCUMENT ME!
     *
     * @param hardtoken DOCUMENT ME!
     */
    public void setHardToken(HardToken hardtoken) {
        this.hardtoken = hardtoken;
    }

    // Private fields
    private String tokensn;
    private String username;
    private Date createtime;
    private Date modifytime;
    private int tokentype;
    private HardToken hardtoken;
}
