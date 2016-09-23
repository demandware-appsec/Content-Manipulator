package com.demandware.appsec.secure.manipulation.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.demandware.appsec.secure.manipulation.SecureFilter;

public class CDATAManipulatorTest
{

    private final CDATAManipulator cdata =
        (CDATAManipulator) ManipulatorFactory.getManipulator( DefaultManipulationType.CDATA_CONTENT_MANIPULATOR );

    /**
     * Total Sanity Test to make sure test code doesn't explode
     */
    @Test
    public void testNoExceptions()
    {
        StringWriter sw = new StringWriter();
        try
        {
            for ( int i = 0; i < Character.MAX_CODE_POINT; i++ )
            {
                this.cdata.filterInternal( String.valueOf( (char) i ), sw );
            }
        }
        catch ( Exception e )
        {
            fail( "Exception throw in testNoExceptions - " + e.getMessage() );
        }

    }

    static class Pair
    {
        String input;

        String expect;

        Pair( String f, String s )
        {
            input = f;
            expect = s;
        }
    }

    @Test
    public void testEdgeCases()
    {
        List<Pair> cases = new ArrayList<Pair>();
        cases.add( new Pair( "]", "]" ) );
        cases.add( new Pair( "]]", "]]" ) );
        cases.add( new Pair( "]]>", "" ) );
        cases.add( new Pair( "]]]>", "]" ) );
        cases.add( new Pair( "]]]>]", "]]" ) );
        cases.add( new Pair( "]]>]]", "]]" ) );
        cases.add( new Pair( "]]]]]]]]]]", "]]]]]]]]]]" ) );
        cases.add( new Pair( "] ]>", "] ]>" ) );
        cases.add( new Pair( "<\"&\'>", "<\"&\'>" ) );
        cases.add( new Pair( "\u2022", "\u2022" ) );
        cases.add( new Pair( "\u0001", "" ) );
        cases.add( new Pair(
            "Invalid expand parameter 'pri<>'c]]><x:script xmlns:x=\"http://www.w3.org/1999/xhtml\">alert('xss')</x:script>es' found.",
            "Invalid expand parameter 'pri<>'c<x:script xmlns:x=\"http://www.w3.org/1999/xhtml\">alert('xss')</x:script>es' found." ) );
        
        for ( Pair p : cases )
        {
            assertEquals( p.expect, SecureFilter.filterCDATAContent( p.input ) );
        }
    }

}
