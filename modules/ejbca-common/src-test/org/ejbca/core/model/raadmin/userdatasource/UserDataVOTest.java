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

import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.PSD2RoleOfPSPStatement;
import org.cesecore.util.SecureXMLDecoder;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataVO;
import org.junit.Test;

import com.keyfactor.util.Base64;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

public class UserDataVOTest {
    private final static Logger log = Logger.getLogger(UserDataVOTest.class);

    @Test
    public void testBasicEncodeDecodeXml() throws Exception {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)) {
            final UserDataVO userDataVO = new UserDataVO();
            encoder.writeObject(userDataVO);
        }
        log.info(new String(baos.toByteArray()));
        final SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(baos.toByteArray()));
        decoder.readObject();
    }

    @Test
    public void testEncodeDecodeXmlWithEndEntityInformation() throws Exception {
        final Date date = new Date();
        final EndEntityType endEntityType = new EndEntityType();
        endEntityType.addType(EndEntityTypes.ENDUSER);
        endEntityType.addType(EndEntityTypes.KEYRECOVERABLE);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)) {
            final UserDataVO userDataVO = new UserDataVO();
            userDataVO.setType(endEntityType);
            final ExtendedInformation extendedInformation = new ExtendedInformation();
            extendedInformation.setCertificateSerialNumber(new BigInteger("123"));
            userDataVO.setExtendedinformation(extendedInformation);
            userDataVO.setTimeCreated(date);
            userDataVO.setKeyRecoverable(true);
            encoder.writeObject(userDataVO);
        }
        log.info(new String(baos.toByteArray()));
        final SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(baos.toByteArray()));
        final UserDataVO userDataVO = (UserDataVO) decoder.readObject();
        assertEquals(new BigInteger("123"), new BigInteger(Base64.decode(userDataVO.getExtendedinformation().
                getMapData("CERTIFICATESERIALNUMBER").getBytes(StandardCharsets.US_ASCII))));
        assertEquals(date, userDataVO.getTimeCreated());
        assertTrue(userDataVO.getKeyRecoverable());
    }

    @Test
    public void testUserDataVOWithPSD2RoleOfPSPStatement() throws Exception {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)) {
            final UserDataVO userDataVO = new UserDataVO();
            final PSD2RoleOfPSPStatement psd2RoleOfPSPStatement = new PSD2RoleOfPSPStatement();
            psd2RoleOfPSPStatement.setName("foo");
            psd2RoleOfPSPStatement.setOid("1.2.3.4");
            final ExtendedInformation extendedInformation = new ExtendedInformation();
            extendedInformation.getRawData().put("psd", psd2RoleOfPSPStatement);
            userDataVO.setExtendedinformation(extendedInformation);
            encoder.writeObject(userDataVO);
        }
        log.info(new String(baos.toByteArray()));
        final SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(baos.toByteArray()));
        final UserDataVO userDataVO = (UserDataVO) decoder.readObject();
        final PSD2RoleOfPSPStatement psd2RoleOfPSPStatement = (PSD2RoleOfPSPStatement) userDataVO.getExtendedinformation().getRawData().get("psd");
        assertEquals("foo", psd2RoleOfPSPStatement.getName());
        assertEquals("1.2.3.4", psd2RoleOfPSPStatement.getOid());
    }
}
