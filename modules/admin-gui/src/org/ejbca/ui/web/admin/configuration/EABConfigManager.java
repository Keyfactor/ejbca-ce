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
package org.ejbca.ui.web.admin.configuration;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.util.StringTools;
import org.ejbca.core.EjbcaException;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * This class is used to manage EAB configs in EJBCA's system configuration.
 */
public class EABConfigManager {
    private static final Logger log = Logger.getLogger(EABConfigManager.class);

    private final SystemConfigurationHelper systemConfigurationHelper;
    private UploadedFile eabCSVFile = null;

    public EABConfigManager(SystemConfigurationHelper systemConfigurationHelper) {
        this.systemConfigurationHelper = systemConfigurationHelper;
    }

    public UploadedFile getEabCSVFile() {
        return eabCSVFile;
    }

    public void setEabCSVFile(UploadedFile eabCSVFile) {
        this.eabCSVFile = eabCSVFile;
    }

    public String saveEabConfig() {
        if (eabCSVFile == null) {
            systemConfigurationHelper.addErrorMessage("EABTAB_FILEUPLOAD_FAILED");
        } else {
            try {
                final Map<String, Set<String>> eabConfigMap = parseCsvToMap(eabCSVFile.getBytes(), ",");
                systemConfigurationHelper.saveEabConfig(eabConfigMap);
                systemConfigurationHelper.addInfoMessage("EABTAB_UPLOADED");
            } catch (EjbcaException | IOException e) {
                log.error("Can not parse EAB configurations", e);
                systemConfigurationHelper.addErrorMessage("EABTAB_BADEABFILE");
            }
        }
        return "EAB saved";
    }
    public interface SystemConfigurationHelper {
        /**
         * Displays an error message to the user.
         * @param languageKey the language key of the message to show
         */
        public void addErrorMessage(String languageKey);

        /**
         * Displays an error message to the user with a formatted message.
         * @param languageKey the language key of the message to show
         * @param params additional parameters to include in the error message
         */
        public void addErrorMessage(String languageKey, Object... params);

        /**
         * Displays an information message to the user.
         * @param languageKey the language key of the message to show
         */
        public void addInfoMessage(String languageKey);

        /**
         * Saves a list of EAB config to persistent storage.
         * @param eabConfigMap the EAB configuration Map to save
         */
        public void saveEabConfig(Map<String, Set<String>> eabConfigMap);
    }

    public static Map<String, Set<String>> parseCsvToMap(final byte[] bytes, String delimeter) throws EjbcaException {
        delimeter = delimeter == null ? "," : delimeter;
        if (bytes == null) {
            return null;
        }
        Map<String, Set<String>> result = new LinkedHashMap<>();
        try {
            final ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
            BufferedReader reader = new BufferedReader(new InputStreamReader(stream));
            String row;
            int line = 0;
            while ((row = reader.readLine()) != null) {
                line++;
                if (StringUtils.isNotBlank(row)) {
                    String[] data = row.split(delimeter);
                    if (data.length != 2) {
                        throw new EjbcaException("Wrong file format error in line " + line);
                    }
                    final String namespace = data[0].trim();
                    final String accountId = data[1].trim();
                    if (!StringTools.checkValueIsAlfaNumericWithSpecialChars(namespace)
                            || !StringTools.checkValueIsAlfaNumericWithSpecialChars(accountId)) {
                        throw new EjbcaException("Namespace or accountId contains characters that are not allowed in line " + line);
                    }
                    result.computeIfAbsent(namespace, k -> new LinkedHashSet<>());
                    result.get(namespace).add(accountId);
                }
            }
            reader.close();
        } catch (IOException e) {
            throw new EjbcaException("Failed to read file content", e);
        }
        return result;
    }
}
