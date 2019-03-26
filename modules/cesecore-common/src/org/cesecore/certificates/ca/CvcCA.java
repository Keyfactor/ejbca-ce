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
package org.cesecore.certificates.ca;

import java.util.Date;
import java.util.HashMap;

/**
 * 
 * @version $Id$
 *
 */
public interface CvcCA extends CA {

    /** Creates a new instance of CA, this constructor should be used when a new CA is created */
    void init(CVCCAInfo cainfo);

    /** Constructor used when retrieving existing CVCCA from database. */
    void init(HashMap<Object, Object> data, int caId, String subjectDN, String name, int status, Date updateTime, Date expireTime);

    String getCvcType();

}