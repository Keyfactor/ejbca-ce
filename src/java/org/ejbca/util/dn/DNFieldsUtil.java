/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.util.dn;

import org.apache.log4j.Logger;

/**
 * DN string utilities.
 * 
 * @author primelars
 * @version $Id$
 *
 */
public class DNFieldsUtil {
    private static Logger log = Logger.getLogger(DNFieldsUtil.class);
    /**
     * Removes fields with empty values that is not followed by any other fields with value and same key.
     * @param sDN
     * @return DN with some fields removed
     */
    public static String removeTrailingEmpties( String sDN ) {
        try {
            return DNFields.removeTrailingEmpties(sDN).toString();
        } catch (Exception e) {
            log.warn(e.getMessage(), e);
            return null;
        }
    }
    /**
     * Removes all fields with empty values.
     * @param sDN
     * @return DN representation without all empties. To be used for the target (not user data). The target could be a certificate.
     * @throws Exception
     */
    public static String removeAllEmpties( String sDN ) throws Exception {
        return DNFields.removeAllEmpties( sDN ).toString();
    }
}
