package se.anatom.ejbca.hardtoken.hardtokentypes;

import se.anatom.ejbca.util.UpgradeableDataHashMap;

import java.io.Serializable;


/**
 * HardToken is a base class that all HardToken classes is supposed to inherit.  It function is to
 * define the data the token is supposed contain.
 *
 * @author TomSelleck
 * @version $Id$
 */
public abstract class HardToken extends UpgradeableDataHashMap implements Serializable, Cloneable {
    // Default Values
    public static final float LATEST_VERSION = 0;
    public static final String TOKENTYPE = "TOKENTYPE";

    // Protexted Constants, must be overloaded by all deriving classes.
    public String[] FIELDS;
    public int[] DATATYPES;
    public String[] FIELDTEXTS;

    // Public Constants.

    /* Constants used to define how the stored data should be represented in the web-gui.*/
    public static final int INTEGER = 0;
    public static final int LONG = 1;
    public static final int STRING = 2;
    public static final int BOOLEAN = 3;
    public static final int DATE = 4;
    public static final int EMPTYROW = 5;
    public static final String EMPTYROW_FIELD = "EMTPYROW";

    // Abstarct Methods.
    public abstract int getNumberOfFields();

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getFieldText(int index);

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getFieldPointer(int index);

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract int getFieldDataType(int index);

    // Public Methods
    public Object getField(String field) {
        return (Object) data.get(field);
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
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getTokenType() {
        return ((Integer) data.get(HardToken.TOKENTYPE)).intValue();
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
}
