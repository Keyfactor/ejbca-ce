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
package org.ejbca.core.protocol.msae;

import jakarta.ejb.ConcurrencyManagement;
import jakarta.ejb.ConcurrencyManagementType;
import jakarta.ejb.DependsOn;
import jakarta.ejb.Singleton;

/**
 * Stub implementation of Certificate Template Cache for Community Edition.
 * The actual implementation is only available in EJBCA Enterprise.
 */
@Singleton
@ConcurrencyManagement(ConcurrencyManagementType.CONTAINER)
@DependsOn({ "StartupSingletonBean" })
public class CertificateTemplateCacheBean implements CertificateTemplateCacheLocal {
    // Only available in enterprise EJBCA!
}
