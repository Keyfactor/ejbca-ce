/*
 * HardTokenIssuer.java
 *
 * Created on den 19 januari 2003, 12:53
 */
package se.anatom.ejbca.hardtoken;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import se.anatom.ejbca.util.UpgradeableDataHashMap;


/**
 * HardTokenIssuer is a class representing the data saved for each HardTokenIssuer.
 *
 * @author TomSelleck
 * @version $Id: HardTokenIssuer.java,v 1.4 2003-07-24 08:43:30 anatom Exp $
 */
public class HardTokenIssuer extends UpgradeableDataHashMap implements Serializable, Cloneable {
    // Default Values
    public static final float LATEST_VERSION = 0;

    // Protexted Constants, must be overloaded by all deriving classes.
    protected static final String AVAILABLEHARDTOKENS = "availablehardtokens";

    // Public Constructors.
    public HardTokenIssuer() {
        data.put(AVAILABLEHARDTOKENS, new ArrayList());
    }

    // Public Methods
    // Availablehardtokens defines which hard tokens the issuer is able to issue.
    public ArrayList getAvailableHardTokens() {
        return (ArrayList) data.get(AVAILABLEHARDTOKENS);
    }

    /**
     * DOCUMENT ME!
     *
     * @param availablehardtokens DOCUMENT ME!
     */
    public void setAvailableHardTokens(ArrayList availablehardtokens) {
        data.put(AVAILABLEHARDTOKENS, availablehardtokens);
    }

    /**
     * DOCUMENT ME!
     *
     * @param field DOCUMENT ME!
     * @param value DOCUMENT ME!
     */
    public void setField(String field, Object value) {
        data.put(field, value);
    }

    /**
     * Implemtation of UpgradableDataHashMap function getLatestVersion
     *
     * @return DOCUMENT ME!
     */
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    /**
     * Implemtation of UpgradableDataHashMap function upgrade.
     */
    public void upgrade() {
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CloneNotSupportedException DOCUMENT ME!
     */
    public Object clone() throws CloneNotSupportedException {
        HardTokenIssuer clone = new HardTokenIssuer();
        HashMap clonedata = (HashMap) clone.saveData();

        Iterator i = (data.keySet()).iterator();

        while (i.hasNext()) {
            Object key = i.next();
            clonedata.put(key, data.get(key));
        }

        clone.loadData(clonedata);

        return clone;
    }
}
