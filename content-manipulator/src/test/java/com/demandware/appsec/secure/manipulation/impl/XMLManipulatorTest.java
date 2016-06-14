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
import com.demandware.appsec.secure.manipulation.impl.XMLManipulator;
import com.demandware.appsec.secure.manipulation.impl.XMLManipulator.XMLManipulatorOption;

public class XMLManipulatorTest
{
    private final XMLManipulator comMan =
        (XMLManipulator) ManipulatorFactory.getManipulator( DefaultManipulationType.XML_COMMENT_MANIPULATOR );

    private final XMLManipulator conMan =
        (XMLManipulator) ManipulatorFactory.getManipulator( DefaultManipulationType.XML_CONTENT_MANIPULATOR );

    private final XMLManipulator dblMan = (XMLManipulator) ManipulatorFactory
        .getManipulator( DefaultManipulationType.XML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR );

    private final XMLManipulator sglMan = (XMLManipulator) ManipulatorFactory
        .getManipulator( DefaultManipulationType.XML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR );

    /**
     * Tests that immunity characters are honored
     */
    @Test
    public void testImmunity()
    {
        @SuppressWarnings( "unchecked" )
        List<SimpleEntry<Character[], XMLManipulator>> list = Arrays.asList(
            new SimpleEntry<Character[], XMLManipulator>( XMLManipulatorOption.COMMENT_CONTENT.getImmuneCharacters(),
                this.comMan ),
            new SimpleEntry<Character[], XMLManipulator>( XMLManipulatorOption.CONTENT.getImmuneCharacters(),
                this.conMan ),
            new SimpleEntry<Character[], XMLManipulator>(
                XMLManipulatorOption.DOUBLE_QUOTE_ATTRIBUTE.getImmuneCharacters(), this.dblMan ),
            new SimpleEntry<Character[], XMLManipulator>(
                XMLManipulatorOption.SINGLE_QUOTE_ATTRIBUTE.getImmuneCharacters(), this.sglMan ) );

        for ( SimpleEntry<Character[], XMLManipulator> entry : list )
        {
            for ( Character c : entry.getKey() )
            {
                assertEquals( entry.getValue().getCorrectCharacter( c ), String.valueOf( c ) );
            }

        }
    }

    /**
     * Test entities work for a few entities
     */
    @Test
    public void testEntityEncoding()
    {

        @SuppressWarnings( "unchecked" )
        List<SimpleEntry<Character, String>> list =
            Arrays.asList( new SimpleEntry<Character, String>( (char) 34, "&quot;" ), /* quotation mark */
                new SimpleEntry<Character, String>( (char) 38, "&amp;" ), /* ampersand */
                new SimpleEntry<Character, String>( (char) 60, "&lt;" ), /* less-than sign */
                new SimpleEntry<Character, String>( (char) 62, "&gt;" ) /* greater-than sign */
            );

        for ( SimpleEntry<Character, String> entry : list )
        {
            assertEquals( entry.getValue(), this.conMan.getCorrectCharacter( entry.getKey() ) );
        }
    }

    /**
     * Test replacement character is used for odd control characters
     */
    @Test
    public void testReplacementCharacters()
    {
        String replaceHex = XMLManipulator.getReplacementHex();
        for ( int i = 0x80; i <= 0x9f; i++ )
        {
            if ( i == 0x85 )
            {
                continue;
            }
            assertEquals( replaceHex, this.conMan.getCorrectCharacter( (char) i ) );
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
                this.comMan.getCorrectCharacter( (char) i );
                this.conMan.getCorrectCharacter( (char) i );
                this.dblMan.getCorrectCharacter( (char) i );
                this.sglMan.getCorrectCharacter( (char) i );
            }
        }
        catch ( Throwable e )
        {
            fail( "Exception throw in testNoExceptions - " + e.getMessage() );
        }

    }

}
