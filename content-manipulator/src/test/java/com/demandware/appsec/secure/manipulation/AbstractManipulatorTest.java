package com.demandware.appsec.secure.manipulation;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import com.demandware.appsec.secure.manipulation.impl.DefaultManipulationType;
import com.demandware.appsec.secure.manipulation.impl.IManipulationType;
import com.demandware.appsec.secure.manipulation.impl.ManipulatorFactory;

@RunWith( Parameterized.class )
public class AbstractManipulatorTest
{
    @Parameters( name = "{0}" )
    public static List<Object[]> manipulators()
    {
        List<Object[]> params = new ArrayList<Object[]>();

        for ( IManipulationType t : DefaultManipulationType.values() )
        {
            params.add( new Object[] { t } );
        }

        return params;
    }

    @Parameter( 0 )
    public IManipulationType type;

    @Test
    public void testNullEncode()
    {
        AbstractManipulator manip = ManipulatorFactory.getManipulator( type );

        String result = manip.encode( null );
        assertNull( result );
    }

    @Test
    public void testNullEncodeWriter()
        throws IOException
    {
        AbstractManipulator manip = ManipulatorFactory.getManipulator( type );

        StringWriter writer = new StringWriter();

        manip.encode( null, writer );
        assertTrue( writer.toString().equals( "" ) );
    }

    @Test
    public void testNullFilter()
    {
        AbstractManipulator manip = ManipulatorFactory.getManipulator( type );

        String result = manip.filter( null );
        assertNull( result );
    }

    @Test
    public void testNullFilterWriter()
        throws IOException
    {
        AbstractManipulator manip = ManipulatorFactory.getManipulator( type );

        StringWriter writer = new StringWriter();

        manip.filter( null, writer );
        assertTrue( writer.toString().equals( "" ) );
    }
}
