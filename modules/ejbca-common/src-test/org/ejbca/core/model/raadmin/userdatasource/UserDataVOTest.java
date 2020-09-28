/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Crap Authority                       *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.raadmin.userdatasource;

import org.cesecore.util.SecureXMLDecoder;
import org.ejbca.core.model.ra.UserDataVO;
import org.junit.Test;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import static org.junit.Assert.assertEquals;

public class UserDataVOTest {
    @Test
    public void testEncodeDecodeXml() throws Exception {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)) {
            final UserDataVO userDataVO = new UserDataVO();
            userDataVO.setDN("CN=test");
            encoder.writeObject(userDataVO);
        }
        final SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(baos.toByteArray()));
        final UserDataVO userDataVO = (UserDataVO) decoder.readObject();
        assertEquals("CN=test", userDataVO.getDN());
    }
}
