package com.demandware.appsec.secure.manipulation.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import com.demandware.appsec.secure.manipulation.impl.DefaultManipulationType;
import com.demandware.appsec.secure.manipulation.impl.JavaScriptManipulator;
import com.demandware.appsec.secure.manipulation.impl.ManipulatorFactory;

public class _JavaScriptManipulator
{
    private final JavaScriptManipulator html = (JavaScriptManipulator) ManipulatorFactory
        .getManipulator( DefaultManipulationType.JAVASCRIPT_HTML_MANIPULATOR );

    private final JavaScriptManipulator attr = (JavaScriptManipulator) ManipulatorFactory
        .getManipulator( DefaultManipulationType.JAVASCRIPT_ATTRIBUTE_MANIPULATOR );

    private final JavaScriptManipulator blck = (JavaScriptManipulator) ManipulatorFactory
        .getManipulator( DefaultManipulationType.JAVASCRIPT_BLOCK_MANIPULATOR );

    private final JavaScriptManipulator src = (JavaScriptManipulator) ManipulatorFactory
        .getManipulator( DefaultManipulationType.JAVASCRIPT_SOURCE_MANIPULATOR );

    private final List<JavaScriptManipulator> jslist = Arrays.asList( html, attr, blck, src );

    /**
     * Test that large Unicode characters are encoded properly
     */
    @Test
    public void testUnicode()
    {
        Character c = '\u2222';
        assertEquals( "\\u2222", this.html.getCorrectCharacter( c ) );
    }

    /**
     * Test that string escaping works correctly
     */
    @Test
    public void testEscape()
    {
        List<SimpleEntry<Character, String>> escapes =
            Arrays.asList( new SimpleEntry<Character, String>( '\b', "\\b" ), new SimpleEntry<Character, String>( '\t',
                "\\t" ), new SimpleEntry<Character, String>( '\n', "\\n" ), new SimpleEntry<Character, String>( '\f',
                "\\f" ), new SimpleEntry<Character, String>( '\r', "\\r" ), new SimpleEntry<Character, String>( '\\',
                "\\\\" ) );

        for ( JavaScriptManipulator manip : this.jslist )
        {
            for ( SimpleEntry<Character, String> escape : escapes )
            {
                Character orig = escape.getKey();
                String expect = escape.getValue();
                String actual = manip.getCorrectCharacter( orig );
                assertEquals( expect, actual );
            }
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
                for ( JavaScriptManipulator manip : this.jslist )
                {
                    manip.getCorrectCharacter( (char) i );
                }
            }
        }
        catch ( Exception e )
        {
            fail( "Exception throw in testNoExceptions - " + e.getMessage() );
        }
    }
}
