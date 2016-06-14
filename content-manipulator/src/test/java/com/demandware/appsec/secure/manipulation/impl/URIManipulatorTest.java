/*
 * Copyright 2015 Demandware Inc. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
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

public class URIManipulatorTest
{

    private final URIManipulator uri =
        (URIManipulator) ManipulatorFactory.getManipulator( DefaultManipulationType.URI_COMPONENT_MANIPULATOR );

    private final URIManipulator strict =
        (URIManipulator) ManipulatorFactory.getManipulator( DefaultManipulationType.URI_STRICT_COMPONENT_MANIPULATOR );

    /**
     * Tests that immunity characters are honored
     */
    @Test
    public void testImmunity()
    {
        @SuppressWarnings( "unchecked" )
        List<SimpleEntry<Character[], URIManipulator>> list = Arrays.asList(
            new SimpleEntry<Character[], URIManipulator>( URIManipulatorOption.COMPONENT.getImmuneCharacters(),
                this.uri ),
            new SimpleEntry<Character[], URIManipulator>( URIManipulatorOption.COMPONENT_STRICT.getImmuneCharacters(),
                this.strict ) );

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

        @SuppressWarnings( "unchecked" )
        List<SimpleEntry<Character, String>> list = Arrays.asList( new SimpleEntry<Character, String>( (char) 33, "!" ),
            new SimpleEntry<Character, String>( (char) 45, "-" ), new SimpleEntry<Character, String>( (char) 95, "_" ),
            new SimpleEntry<Character, String>( (char) 46, "." ), new SimpleEntry<Character, String>( (char) 126, "~" ),
            new SimpleEntry<Character, String>( (char) 42, "*" ), new SimpleEntry<Character, String>( (char) 39, "\'" ),
            new SimpleEntry<Character, String>( (char) 40, "(" ), new SimpleEntry<Character, String>( (char) 41, ")" ),
            new SimpleEntry<Character, String>( (char) 64, "%40" ), /* @ */
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

        @SuppressWarnings( "unchecked" )
        List<SimpleEntry<Character, String>> list = Arrays.asList(
            new SimpleEntry<Character, String>( (char) 33, "%21" ),
            new SimpleEntry<Character, String>( (char) 45, "-" ), new SimpleEntry<Character, String>( (char) 95, "_" ),
            new SimpleEntry<Character, String>( (char) 46, "." ), new SimpleEntry<Character, String>( (char) 126, "~" ),
            new SimpleEntry<Character, String>( (char) 42, "%2a" ),
            new SimpleEntry<Character, String>( (char) 39, "%27" ),
            new SimpleEntry<Character, String>( (char) 40, "%28" ),
            new SimpleEntry<Character, String>( (char) 41, "%29" ),
            new SimpleEntry<Character, String>( (char) 64, "%40" ), /* @ */
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
