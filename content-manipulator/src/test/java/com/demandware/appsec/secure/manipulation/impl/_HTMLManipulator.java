package com.demandware.appsec.secure.manipulation.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import com.demandware.appsec.secure.manipulation.impl.DefaultManipulationType;
import com.demandware.appsec.secure.manipulation.impl.HTMLManipulator;
import com.demandware.appsec.secure.manipulation.impl.ManipulatorFactory;
import com.demandware.appsec.secure.manipulation.impl.HTMLManipulator.HTMLManipulatorOption;

public class _HTMLManipulator
{
    private final HTMLManipulator conMan = (HTMLManipulator) ManipulatorFactory
        .getManipulator( DefaultManipulationType.HTML_CONTENT_MANIPULATOR );

    private final HTMLManipulator dblMan = (HTMLManipulator) ManipulatorFactory
        .getManipulator( DefaultManipulationType.HTML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR );

    private final HTMLManipulator sglMan = (HTMLManipulator) ManipulatorFactory
        .getManipulator( DefaultManipulationType.HTML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR );

    private final HTMLManipulator noqMan = (HTMLManipulator) ManipulatorFactory
        .getManipulator( DefaultManipulationType.HTML_UNQUOTED_ATTRIBUTE_MANIPULATOR );

    /**
     * Tests that immunity characters are honored
     */
    @Test
    public void testImmunity()
    {
        List<SimpleEntry<Character[], HTMLManipulator>> list =
            Arrays.asList(
                new SimpleEntry<Character[], HTMLManipulator>( HTMLManipulatorOption.CONTENT
                    .getImmuneCharacters(), this.conMan ),
                new SimpleEntry<Character[], HTMLManipulator>( HTMLManipulatorOption.DOUBLE_QUOTE_ATTRIBUTE
                    .getImmuneCharacters(), this.dblMan ),
                new SimpleEntry<Character[], HTMLManipulator>( HTMLManipulatorOption.SINGLE_QUOTE_ATTRIBUTE
                    .getImmuneCharacters(), this.sglMan ), new SimpleEntry<Character[], HTMLManipulator>(
                    HTMLManipulatorOption.UNQUOTED_ATTRIBUTE.getImmuneCharacters(), this.noqMan ) );

        for ( SimpleEntry<Character[], HTMLManipulator> entry : list )
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

        List<SimpleEntry<Character, String>> list =
            Arrays.asList( new SimpleEntry<Character, String>( (char) 34, "&quot;" ), /* quotation mark */
                new SimpleEntry<Character, String>( (char) 38, "&amp;" ), /* ampersand */
                new SimpleEntry<Character, String>( (char) 60, "&lt;" ), /* less-than sign */
                new SimpleEntry<Character, String>( (char) 62, "&gt;" ), /* greater-than sign */
                new SimpleEntry<Character, String>( (char) 160, "&nbsp;" ) /* no-break space */
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
        String replaceHex = HTMLManipulator.getReplacementHex();
        for ( int i = 0x80; i <= 0x9f; i++ )
        {
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
                this.conMan.getCorrectCharacter( (char) i );
                this.dblMan.getCorrectCharacter( (char) i );
                this.sglMan.getCorrectCharacter( (char) i );
                this.noqMan.getCorrectCharacter( (char) i );
            }
        }
        catch ( Exception e )
        {
            fail( "Exception throw in testNoExceptions - " + e.getMessage() );
        }

    }

}
