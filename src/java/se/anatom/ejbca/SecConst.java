
package se.anatom.ejbca;


/** Constants for users and certificates.
 *
 * Constants for Type of user:
 * Type is constructed as a mask since one user can be of several types.
 * To test a user type:
 * <pre>
 * if (((type & USER_ENDUSER) == USER_ENDUSER) && ((type & USER_CAADMIN) == USER_CAADMIN) || ...
 *    ...
 * </pre>
 *
 *
 * Bit usage:
 * bits 0-7   (1:st byte):  user types
 * bits 8-15  (2:nd byte):  unused
 * bits 16-23 (3:rd byte):  unused
 * bits 24-30 (4:th byte):  unused
 *
 * Constants for certificates are simple integer types.
 *
 * @version $Id: SecConst.java,v 1.4 2002-05-15 07:10:17 anatom Exp $
 */
public class SecConst extends Object {

    // User types

    /** Dummy type. */
    public static final int USER_INVALID =        0x0;
    /** This is an end user certificate (default). */
    public static final int USER_ENDUSER =        0x1;
    /** This is a CA. */
    public static final int USER_CA =             0x2;
    /** This is a RA. */
    public static final int USER_RA =             0x4;
    /** This is a Root CA. */
    public static final int USER_ROOTCA =         0x8;
    /** This is a CA Administrator. */
    public static final int USER_CAADMIN =        0x10;
    /** This is a RA Administrator. */
    public static final int USER_RAADMIN =        0x20;
    /** All bits used by Type. */
    public static final int USER_MASK =           0xff;

    /** Prevents creation of new SecConst **/
    private SecConst() {
    }

} // SecConst
