package org.ejbca.ui.web.rest.api.io.response;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class ExtendedInformationRestResponseComponentUnitTest {

    private final String name;
    private final boolean expected;

    public ExtendedInformationRestResponseComponentUnitTest(final String name, final boolean expected) {
        this.name = name;
        this.expected = expected;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> getTestParameters() {
        return Arrays.asList(
                new Object[]{null, false},
                new Object[]{"", false},
                new Object[]{"something", false},
                new Object[]{ExtendedInformation.INTERNAL_KEY_PREFIX, true},
                new Object[]{"before"+ExtendedInformation.INTERNAL_KEY_PREFIX, true},
                new Object[]{ExtendedInformation.INTERNAL_KEY_PREFIX+"after", true},
                new Object[]{"before"+ExtendedInformation.INTERNAL_KEY_PREFIX+"after", true});
    }

    @Test
    public void testIsInternalName() {
        // Given
        final var component = new ExtendedInformationRestResponseComponent
                .ExtendedInformationRestResponseComponentBuilder()
                .setName(name)
                .build();

        // When
        final var actual = component.isInternalName();

        // Then
        assertEquals(expected, actual);
    }

}
