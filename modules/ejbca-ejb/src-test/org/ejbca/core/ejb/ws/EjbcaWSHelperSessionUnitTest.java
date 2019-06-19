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
package org.ejbca.core.ejb.ws;

import static org.junit.Assert.assertEquals;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit test of {@link EjbcaWSHelperSession}.
 * @version $Id$
 */
public class EjbcaWSHelperSessionUnitTest {

    private static final Logger log = Logger.getLogger(EjbcaWSHelperSessionUnitTest.class);

    private static final String TEST_CANAME = "EjbcaWSHelperSessionUnitTestCA";
    private static final String TEST_CADN = "CN=" + TEST_CANAME + ",O=Test";
    private static final int TEST_CAID = TEST_CADN.hashCode();
    private static final String TEST_EEPNAME = "TestEndEntityProfile";
    private static final int TEST_EEPID = 234;
    private static final String TEST_CPNAME = "TestCertificateProfile";
    private static final int TEST_CPID = 567;
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_SUBJECTDN = "CN=testuser";

    private static final String ISO_FORMAT = "yyyy-MM-dd HH:mm:ss";
    private SimpleDateFormat localIsoFormat = new SimpleDateFormat(ISO_FORMAT);
    private FastDateFormat utcIsoFormat = FastDateFormat.getInstance(ISO_FORMAT, TimeZone.getTimeZone("UTC"));

    private EjbcaWSHelperSession ejbcaWsHelper;
    private UserDataVOWS givenUserData;

    @Before
    public void setUp() {
        log.trace(">setUp");
        ejbcaWsHelper = new EjbcaWSHelperSessionBean(); // This works because convertUserDataVOWSInternal does not use any EJBs
        givenUserData = new UserDataVOWS(TEST_USERNAME, "foo123", false, TEST_SUBJECTDN, TEST_CANAME, null, null, EndEntityConstants.STATUS_NEW, UserDataVOWS.TOKEN_TYPE_USERGENERATED, TEST_EEPNAME, TEST_CPNAME);
        log.trace("<setUp");
    }

    /** Tests converting an incoming UserDataVOWS object with dates in the absolute date format */
    @Test
    public void explicitAbsoluteDateInConvertUserDataVOWSInternal() throws EjbcaException {
        log.trace(">explicitAbsoluteDateInConvertUserDataVOWSInternal");
        // Given
        givenUserData.setStartTime("2019-06-30 17:53:59+02:00");
        givenUserData.setEndTime("2019-07-31 23:15:34+02:00");
        // When
        final EndEntityInformation endEntityInfo = ejbcaWsHelper.convertUserDataVOWSInternal(givenUserData, TEST_CAID, TEST_EEPID, TEST_CPID, EndEntityConstants.TOKEN_USERGEN, false);
        // Then
        final ExtendedInformation extInfo = endEntityInfo.getExtendedInformation();
        assertEquals("2019-06-30 15:53:59", extInfo.getCertificateStartTime()); // Note: This is in UTC timezone
        assertEquals("2019-07-31 21:15:34", extInfo.getCertificateEndTime());
        log.trace("<explicitAbsoluteDateInConvertUserDataVOWSInternal");
    }

    /** Tests converting an incoming UserDataVOWS object with dates in x:y:z relative date format */
    @Test
    public void explicitRelativeDateInConvertUserDataVOWSInternal() throws EjbcaException {
        log.trace(">explicitRelativeDateInConvertUserDataVOWSInternal");
        // Given
        givenUserData.setStartTime("1:2:3");
        givenUserData.setEndTime("3:4:5");
        // When
        final EndEntityInformation endEntityInfo = ejbcaWsHelper.convertUserDataVOWSInternal(givenUserData, TEST_CAID, TEST_EEPID, TEST_CPID, EndEntityConstants.TOKEN_USERGEN, false);
        // Then
        final ExtendedInformation extInfo = endEntityInfo.getExtendedInformation();
        assertEquals("1:2:3", extInfo.getCertificateStartTime());
        assertEquals("3:4:5", extInfo.getCertificateEndTime());
        log.trace("<explicitRelativeDateInConvertUserDataVOWSInternal");
    }

    /** Tests converting an incoming UserDataVOWS object with dates in the old legacy WS date format */
    @Test
    public void explicitOldFormatDateInConvertUserDataVOWSInternal() throws EjbcaException {
        log.trace(">explicitOldFormatDateInConvertUserDataVOWSInternal");
        // Given
        givenUserData.setStartTime("May 31, 2019, 12:07 PM"); // system timezone
        givenUserData.setEndTime("Jun 19, 2019, 12:59 AM");
        // When
        final EndEntityInformation endEntityInfo = ejbcaWsHelper.convertUserDataVOWSInternal(givenUserData, TEST_CAID, TEST_EEPID, TEST_CPID, EndEntityConstants.TOKEN_USERGEN, false);
        // Then
        final ExtendedInformation extInfo = endEntityInfo.getExtendedInformation();
        assertEquals(localTimeToUtc("2019-05-31 12:07:00"), extInfo.getCertificateStartTime());
        assertEquals(localTimeToUtc("2019-06-19 00:59:00"), extInfo.getCertificateEndTime());
        log.trace("<explicitOldFormatDateInConvertUserDataVOWSInternal");
    }

    /** Tests conversion of an EndEntityInformation object with the legacy date format without seconds */
    @Test
    public void convertToUserDataWithoutSeconds() {
        log.trace(">convertToUserDataWithoutSeconds");
        // Given
        final ExtendedInformation extInfo = new ExtendedInformation();
        extInfo.setCertificateStartTime("2019-06-30 17:53");
        extInfo.setCertificateEndTime("2019-07-31 21:15");
        EndEntityInformation endEntityInfo = new EndEntityInformation(TEST_USERNAME, TEST_SUBJECTDN, TEST_CAID, null, null, EndEntityTypes.ENDUSER.toEndEntityType(), TEST_EEPID, TEST_CPID, EndEntityConstants.TOKEN_USERGEN, extInfo);
        // When
        final UserDataVOWS userdata = ejbcaWsHelper.convertEndEntityInformation(endEntityInfo,
                TEST_CANAME, TEST_EEPNAME, TEST_CPNAME, UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        // Then
        assertEquals("2019-06-30 17:53:00+00:00", userdata.getStartTime());
        assertEquals("2019-07-31 21:15:00+00:00", userdata.getEndTime());
        log.trace("<convertToUserDataWithoutSeconds");
    }

    /** Tests conversion of an EndEntityInformation object with the new date format with seconds since 7.2.0 */
    @Test
    public void convertToUserDataWithSeconds() {
        log.trace(">convertToUserDataWithSeconds");
        // Given
        final ExtendedInformation extInfo = new ExtendedInformation();
        extInfo.setCertificateStartTime("2019-06-30 17:53:59");
        extInfo.setCertificateEndTime("2019-07-31 21:15:34");
        EndEntityInformation endEntityInfo = new EndEntityInformation(TEST_USERNAME, TEST_SUBJECTDN, TEST_CAID, null, null, EndEntityTypes.ENDUSER.toEndEntityType(), TEST_EEPID, TEST_CPID, EndEntityConstants.TOKEN_USERGEN, extInfo);
        // When
        final UserDataVOWS userdata = ejbcaWsHelper.convertEndEntityInformation(endEntityInfo,
                TEST_CANAME, TEST_EEPNAME, TEST_CPNAME, UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        // Then
        assertEquals("2019-06-30 17:53:59+00:00", userdata.getStartTime());
        assertEquals("2019-07-31 21:15:34+00:00", userdata.getEndTime());
        log.trace("<convertToUserDataWithSeconds");
    }

    private String localTimeToUtc(final String localTime) {
        try {
            final Date date = localIsoFormat.parse(localTime);
            return utcIsoFormat.format(date);
        } catch (ParseException e) {
            throw new IllegalStateException(e);
        }
    }
}
