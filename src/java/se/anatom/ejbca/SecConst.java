
package se.anatom.ejbca;


/**
 * Constants for Type of user.
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
 * @version $Id: SecConst.java,v 1.2 2002-01-06 17:40:21 anatom Exp $
 */
public class SecConst extends Object {

    // User types
    public static int USER_INVALID =        0x00;   // Dummy type
    public static int USER_ENDUSER =        0x1;    // This is an end user certificate (default)
    public static int USER_CA =             0x2;    // This is a CA
    public static int USER_RA =             0x4;    // This is a RA
    public static int USER_ROOTCA =         0x8;    // This is a Root CA
    public static int USER_CAADMIN =        0x10;   // This is a CA Administrator
    public static int USER_RAADMIN =        0x20;   // This is a RA Administrator
    public static int USER_MASK =           0xff;   // All bits used by Type

    /** Prevents creation of new SecConst **/
    private SecConst() {
    }

} // SecConst
