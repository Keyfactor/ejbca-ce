package se.anatom.ejbca.webdist.hardtokeninterface;

import java.util.Date;

import se.anatom.ejbca.hardtoken.*;
import se.anatom.ejbca.hardtoken.hardtokentypes.*;
import se.anatom.ejbca.util.StringTools;


/**
 * A class representing a web interface view of a hard token in the ra database.
 *
 * @version $Id: UserView.java,v 1.0 2003/01/26 20:00:01 herrvendil Exp $
 */
public class HardTokenView implements java.io.Serializable, Cloneable {
    // Public constants.
    public HardTokenView(AvailableHardToken[] availablehardtokens) {
        this.tokendata = new HardTokenData();
        this.availablehardtokens = availablehardtokens;
    }

    /**
     * Creates a new HardTokenView object.
     *
     * @param availablehardtokens DOCUMENT ME!
     * @param newtokendata DOCUMENT ME!
     */
    public HardTokenView(AvailableHardToken[] availablehardtokens, HardTokenData newtokendata) {
        tokendata = newtokendata;
        this.availablehardtokens = availablehardtokens;
    }

    /**
     * DOCUMENT ME!
     *
     * @param user DOCUMENT ME!
     */
    public void setUsername(String user) {
        tokendata.setUsername(StringTools.strip(user));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getUsername() {
        return tokendata.getUsername();
    }

    /**
     * DOCUMENT ME!
     *
     * @param tokentype DOCUMENT ME!
     */
    public void setHardTokenType(String tokentype) {
        for (int i = 0; i < availablehardtokens.length; i++) {
            if (tokentype.equals(availablehardtokens[i].getName())) {
                tokendata.setTokenType(Integer.parseInt(availablehardtokens[i].getId()));
            }
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getHardTokenType() {
        String returnval = "";

        for (int i = 0; i < availablehardtokens.length; i++) {
            if (tokendata.getTokenType() == Integer.parseInt(availablehardtokens[i].getId())) {
                returnval = availablehardtokens[i].getName();
            }
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @param tokensn DOCUMENT ME!
     */
    public void setTokenSN(String tokensn) {
        tokendata.setTokenSN(tokensn);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getTokenSN() {
        return tokendata.getTokenSN();
    }

    /**
     * DOCUMENT ME!
     *
     * @param createtime DOCUMENT ME!
     */
    public void setCreateTime(Date createtime) {
        tokendata.setCreateTime(createtime);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getCreateTime() {
        return tokendata.getCreateTime();
    }

    /**
     * DOCUMENT ME!
     *
     * @param modifytime DOCUMENT ME!
     */
    public void setModifyTime(Date modifytime) {
        tokendata.setModifyTime(modifytime);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getModifyTime() {
        return tokendata.getModifyTime();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getNumberOfFields() {
        return tokendata.getHardToken().getNumberOfFields();
    }

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getTextOfField(int index) {
        if (tokendata.getHardToken().getFieldText(index).equals(HardToken.EMPTYROW_FIELD)) {
            return "";
        } else {
            return tokendata.getHardToken().getFieldText(index);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Object getField(int index) {
        HardToken token = tokendata.getHardToken();

        if (token.getFieldPointer(index).equals(HardToken.EMPTYROW_FIELD)) {
            return (Object) "";
        } else {
            return (Object) token.getField(token.getFieldPointer(index));
        }
    }

    // Private constants.
    // Private methods.
    private HardTokenData tokendata;
    private AvailableHardToken[] availablehardtokens;
}
