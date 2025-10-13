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
package org.ejbca.core;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.nodes.Tag;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

/**
 * Wrapper for SnakeYAML.
 */
public final class YamlWriter {

    private YamlWriter() {
        throw new AssertionError("Must never been instantiated!");
    }

    public static byte[] exportToYamlBytes(final Object data) {
        final DumperOptions options = new DumperOptions();
        options.setAllowReadOnlyProperties(true);

        final Yaml yaml = new Yaml(options);
        final String yamlExport = yaml.dumpAs(data, Tag.MAP, DumperOptions.FlowStyle.BLOCK);

        return yamlExport.getBytes(StandardCharsets.UTF_8);
    }

    public static <T> T importFromYamlBytes(final byte[] bytes, final Class<T> clazz) {
        final Yaml yaml = new Yaml();
        return yaml.loadAs(new ByteArrayInputStream(bytes), clazz);
    }

}
