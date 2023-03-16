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

package org.ejbca.core.ejb;

import javax.ejb.DependsOn;
import javax.ejb.Singleton;

import org.ejbca.core.protocol.msae.ADConnectionSingletonLocal;

@Singleton
@DependsOn({"StartupSingletonBean"})
public class ADConnectionSingletonBean implements ADConnectionSingletonLocal {
    // Only available in enterprise EJBCA!
}
