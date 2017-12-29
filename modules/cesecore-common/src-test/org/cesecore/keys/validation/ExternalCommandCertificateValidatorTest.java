/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import java.util.LinkedHashMap;

import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.ExternalProcessException;
import org.junit.Test;

/**
 * This class contains whitebox integrations tests for External Command Validators. To determine whether
 * an external command was executed as specified we need to place a file on the fileystem in the location
 * given by the value mapped to the key <code>EXTERNAL_COMMAND</code>, or if we only care about whether
 * the command was invoked, it suffices to ensure the executable does not exist and then check for an
 * <code>ExternalProcessException</code>.
 * @version $Id$
 */
public class ExternalCommandCertificateValidatorTest {

    @Test(expected = ExternalProcessException.class)
    public void testDisabledWhitelist() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, "/foo/allowed");
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        validator.validate(null, null, ExternalScriptsWhitelist.permitAll());
    }

    @Test(expected = ExternalProcessException.class)
    public void testAllowedCommand() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, "/foo/allowed");
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        validator.validate(null, null, new ExternalScriptsWhitelist("/foo/allowed"));
    }

    @Test(expected = ExternalProcessException.class)
    public void testAllowedCommandWithParameters() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, "/foo/allowed %cert%");
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        validator.validate(null, null, new ExternalScriptsWhitelist("/foo/allowed"));
    }

    @Test(expected = ValidatorNotApplicableException.class)
    public void testForbiddenCommand() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, "/foo/forbidden");
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        validator.validate(null, null, new ExternalScriptsWhitelist("/foo/allowed"));
    }

    @Test(expected = ValidatorNotApplicableException.class)
    public void testForbiddenCommandWithParameters() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, "/foo/forbidden %cert%");
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        validator.validate(null, null, new ExternalScriptsWhitelist("/foo/allowed"));
    }
}
