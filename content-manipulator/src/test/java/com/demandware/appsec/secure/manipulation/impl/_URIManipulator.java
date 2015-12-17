package com.demandware.appsec.secure.manipulation.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import com.demandware.appsec.secure.manipulation.impl.DefaultManipulationType;
import com.demandware.appsec.secure.manipulation.impl.ManipulatorFactory;
import com.demandware.appsec.secure.manipulation.impl.URIManipulator;
import com.demandware.appsec.secure.manipulation.impl.URIManipulator.URIManipulatorOption;

public class _URIManipulator
{

    private final URIManipulator uri = (URIManipulator) ManipulatorFactory
        .getManipulator( DefaultManipulationType.URI_COMPONENT_MANIPULATOR );

    private final URIManipulator strict = (URIManipulator) ManipulatorFactory
        .getManipulator( DefaultManipulationType.URI_STRICT_COMPONENT_MANIPULATOR );

    /**
     * Tests that immunity characters are honored
     */
    @Test
    public void testImmunity()
    {
        List<SimpleEntry<Character[], URIManipulator>> list =
            Arrays.asList(
                new SimpleEntry<Character[], URIManipulator>( URIManipulatorOption.COMPONENT
                    .getImmuneCharacters(), this.uri ), new SimpleEntry<Character[], URIManipulator>(
                    URIManipulatorOption.COMPONENT_STRICT.getImmuneCharacters(), this.strict ) );

        for ( SimpleEntry<Character[], URIManipulator> entry : list )
        {
            for ( Character c : entry.getKey() )
            {
                assertEquals( String.valueOf( c ), entry.getValue().getCorrectCharacter( c ) );
            }
        }
    }

    /**
     * Test entities work for a few entities
     */
    @Test
    public void testPercentEncoding()
    {

        List<SimpleEntry<Character, String>> list =
            Arrays.asList( new SimpleEntry<Character, String>( (char) 33, "!" ), new SimpleEntry<Character, String>(
                (char) 45, "-" ), new SimpleEntry<Character, String>( (char) 95, "_" ),
                new SimpleEntry<Character, String>( (char) 46, "." ), new SimpleEntry<Character, String>( (char) 126,
                    "~" ), new SimpleEntry<Character, String>( (char) 42, "*" ), new SimpleEntry<Character, String>(
                    (char) 39, "\'" ), new SimpleEntry<Character, String>( (char) 40, "(" ),
                new SimpleEntry<Character, String>( (char) 41, ")" ), new SimpleEntry<Character, String>( (char) 64,
                    "%40" ), /* @ */
                new SimpleEntry<Character, String>( (char) 125, "%7d" ) /* } */
            );

        for ( SimpleEntry<Character, String> entry : list )
        {
            assertEquals( entry.getValue(), this.uri.getCorrectCharacter( entry.getKey() ) );
        }
    }

    /**
     * Test entities work for a few entities
     */
    @Test
    public void testStrictPercentEncoding()
    {

        List<SimpleEntry<Character, String>> list =
            Arrays.asList( new SimpleEntry<Character, String>( (char) 33, "%21" ), new SimpleEntry<Character, String>(
                (char) 45, "-" ), new SimpleEntry<Character, String>( (char) 95, "_" ),
                new SimpleEntry<Character, String>( (char) 46, "." ), new SimpleEntry<Character, String>( (char) 126,
                    "~" ), new SimpleEntry<Character, String>( (char) 42, "%2a" ), new SimpleEntry<Character, String>(
                    (char) 39, "%27" ), new SimpleEntry<Character, String>( (char) 40, "%28" ),
                new SimpleEntry<Character, String>( (char) 41, "%29" ), new SimpleEntry<Character, String>( (char) 64,
                    "%40" ), /* @ */
                new SimpleEntry<Character, String>( (char) 125, "%7d" ) /* } */
            );

        for ( SimpleEntry<Character, String> entry : list )
        {
            assertEquals( entry.getValue(), this.strict.getCorrectCharacter( entry.getKey() ) );
        }
    }

    /**
     * Total Sanity Test to make sure test code doesn't explode
     */
    @Test
    public void testNoExceptions()
    {
        try
        {
            for ( int i = 0; i < Character.MAX_CODE_POINT; i++ )
            {
                this.uri.getCorrectCharacter( (char) i );
                this.strict.getCorrectCharacter( (char) i );
            }
        }
        catch ( Throwable e )
        {
            fail( "Exception throw in testNoExceptions - " + e.getMessage() );
        }

    }

}
