/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.certificate.certextensions.standard;

import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificateprofile.CertificateProfile;

/**
 * Base class for a standard certificate extension.
 * All standard extensions should inherit this class.
 * 
 * The methods that need implementation is init frmm here and getValue from the super class.
 * init should call setOID and setCriticalFlag from the super class.
 * Implementing class must have a default constructor, calling super constructor.
 * 
 * @version $Id$
 */
public abstract class StandardCertificateExtension extends CertificateExtension {
	
	private static final long serialVersionUID = 1L;

    /**
	 * Method that initializes the CertificateExtension
	 * 
	 * @param certProf certificateprofile that defines if this extension is used and critical
	 */
	public abstract void init(CertificateProfile certProf);
	
}
