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

package org.ejbca.repository.generator;

import org.ejbca.repository.generator.model.Entity;
import freemarker.template.Configuration;
import freemarker.template.TemplateExceptionHandler;
import org.ejbca.repository.generator.model.Field;
import org.ejbca.repository.generator.util.JsonUtil;
import org.ejbca.repository.generator.util.StringUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.util.TimeZone;
import java.util.stream.Stream;

public class Main {

    private static void delete(File file) {
        if (file.exists()) {
            if (file.isDirectory()) {
                for (File child : file.listFiles()) {
                    delete(child);
                }
            }
            file.delete();
        }
    }

    private static File getDir(File outputDir, String packageName) {
        return new File(outputDir, packageName.replaceAll("\\.", File.separator));
    }

    private static void doGenerateFile(Configuration configuration, File dir, String templateName, Entity entity) throws Exception {
        String filename = templateName
                .replace("dto", StringUtil.firstUpperCase(entity.getName()))
                .replace("ftl", "java");
        File file = new File(dir, filename);
        if (!file.exists()) {
            file.getParentFile().mkdirs();
            Writer out = new FileWriter(file);
            configuration.getTemplate(templateName).process(entity, out);
        }
    }

    private static String getSrcDirName(final boolean test, final String templateName) {
        if (test) {
            return "modules/ejbca-repository/src-test";
        }
        else {
            if (templateName.toLowerCase().contains("bean")) {
                return "modules/ejbca-entity/src";
            }
            else {
                return "modules/ejbca-ejb-interface/src";
            }
        }
    }

    private static void generateFiles(Configuration configuration, File rootDir, boolean test, String[] templateNames, Entity entity) throws Exception {
        for (String templateName : templateNames) {
            File srcDir = new File(rootDir, getSrcDirName(test, templateName));
            File dir = getDir(srcDir, entity.getPackageName()+".dto");
            doGenerateFile(configuration, dir, templateName, entity);
        }
    }

    private static Configuration getTemplateConfiguration(File templateDir) throws Exception {
        Configuration configuration = new Configuration(Configuration.VERSION_2_3_34);
        configuration.setDirectoryForTemplateLoading(templateDir);
        // Recommended settings for new projects:
        configuration.setDefaultEncoding("UTF-8");
        configuration.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        configuration.setLogTemplateExceptions(false);
        configuration.setWrapUncheckedExceptions(true);
        configuration.setFallbackOnNullLoopVariable(false);
        configuration.setSQLDateAndTimeTimeZone(TimeZone.getDefault());
        configuration.setAPIBuiltinEnabled(true);
        return configuration;
    }

    public static File deleteAndCreateEmptyDir(String dirName) {
        File dir = new File(dirName);
        delete(dir);
        dir.mkdirs();
        return dir;
    }

    public static FileInputStream getFileInputStream(File file) throws Exception {
        if (!file.isFile()) {
            throw new IllegalArgumentException("Argument " + file.getCanonicalPath() + " is not a file");
        }
        return new FileInputStream(file);
    }

    private static boolean isRootDir(File dir) {
        return Stream.of(dir.listFiles())
                .map(File::getName)
                .anyMatch(name->"settings.gradle.kts".equals(name));
    }

    private static File getRootDir(File outputDir) {
        if (outputDir == null) {
            throw new IllegalArgumentException("Argument " + outputDir + " is null");
        }
        return isRootDir(outputDir) ?
                outputDir :
                getRootDir(outputDir.getParentFile());
    }

    private static File getRootDir() throws IOException {
        return getRootDir(new File(".").getCanonicalFile());
    }

    private static Field getField(final String javaName, final String javaType) {
        final var field = new Field();
        field.setJavaName(javaName);
        field.setJavaType(javaType);
        return field;
    }

    private static Entity parseJson(final String dtoName, final InputStream inputStream) {
        Entity entity = JsonUtil.parseJson(inputStream, Entity.class);
        entity.setPackageName("org.ejbca");
        entity.setName(dtoName);
        return entity;
    }

    private static void doMain(File rootDir, boolean test) throws Exception {
        final String nameSuffix = test ? "-test" : "";
        final File templatesDir = new File(rootDir, "modules/ejbca-repository/templates");
        final String[] templateNames = templatesDir.list();
        File resourcesDir = new File(rootDir, "modules/ejbca-repository/resources" + nameSuffix);
        File[] jsonFiles = resourcesDir.listFiles((dir, name) -> name.endsWith(".json"));
        Configuration configuration = getTemplateConfiguration(templatesDir);
        for (File jsonFile : jsonFiles) {
            try (FileInputStream fileInputStream = getFileInputStream(jsonFile)) {
                final var name = jsonFile.getName().replace(".json", "");
                final var entity = parseJson(name, fileInputStream);
                generateFiles(configuration, rootDir, test, templateNames, entity);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        final var rootDir = getRootDir();
        doMain(rootDir, false);
        doMain(rootDir, true);
    }

}
