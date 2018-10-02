/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.dnssec;

/**
 * Defaults for DNSSEC.
 * @version $Id$
 */
public final class DnsSecDefaults {

    private DnsSecDefaults() { }

    /**
     * Default root anchors for DNSSEC from IANA. Defined in https://data.iana.org/root-anchors/root-anchors.xml
     * <p>
     * In the long run we should consider:
     * <ol>
     * <li>Making DNSSEC configurable in a central place
     * <li>Automatic update of the DNSSEC key using
     * </ol>
     */
    public static final String IANA_ROOT_ANCHORS_DEFAULT =
            ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5\n" + // old key, going to be phased out
            ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"; // new key, valid from 2018-10-11

}
