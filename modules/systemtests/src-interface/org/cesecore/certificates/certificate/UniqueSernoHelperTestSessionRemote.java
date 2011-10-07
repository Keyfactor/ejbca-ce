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
package org.cesecore.certificates.certificate;

import javax.ejb.Remote;

/**
 * This session bean should under no circumstances be included in the production version of EJBCA.
 * 
 * @version $Id$
 */
@Remote
public interface UniqueSernoHelperTestSessionRemote {
    
    public void setUniqueSernoOkIndex();

    public boolean existsUniqueSernoIndex();

    public void resetUniqueSernoCheck();

}
