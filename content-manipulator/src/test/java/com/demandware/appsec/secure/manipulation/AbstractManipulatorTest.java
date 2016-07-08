package com.demandware.appsec.secure.manipulation;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
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
        params.add( new Object[]{ null} );
        return params;
    }

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Parameter( 0 )
    public IManipulationType type;

    @Test
    public void testNullEncode()
    {
        if(type == null)
        {
            this.exception.expect( IllegalArgumentException.class );
        }
        AbstractManipulator manip = ManipulatorFactory.getManipulator( type );

        String result = manip.encode( null );
        assertNull( result );
    }

    @Test
    public void testNullEncodeWriter()
        throws IOException
    {
        if(type == null)
        {
            this.exception.expect( IllegalArgumentException.class );
        }
        AbstractManipulator manip = ManipulatorFactory.getManipulator( type );

        StringWriter writer = new StringWriter();

        manip.encode( null, writer );
        assertTrue( writer.toString().equals( "" ) );
    }

    @Test
    public void testNullWriterEncode()
        throws IllegalArgumentException, IOException
    {
        this.exception.expect( IllegalArgumentException.class );
        AbstractManipulator manip = ManipulatorFactory.getManipulator( type );

        manip.encode( "", null );
    }

    @Test
    public void testNullFilter()
    {
        if(type == null)
        {
            this.exception.expect( IllegalArgumentException.class );
        }
        AbstractManipulator manip = ManipulatorFactory.getManipulator( type );

        String result = manip.filter( null );
        assertNull( result );
    }

    @Test
    public void testNullFilterWriter()
        throws IOException
    {
        if(type == null)
        {
            this.exception.expect( IllegalArgumentException.class );
        }
        AbstractManipulator manip = ManipulatorFactory.getManipulator( type );

        StringWriter writer = new StringWriter();

        manip.filter( null, writer );
        assertTrue( writer.toString().equals( "" ) );
    }

    @Test
    public void testNullWriterFilter()
        throws IllegalArgumentException, IOException
    {
        this.exception.expect( IllegalArgumentException.class );
        AbstractManipulator manip = ManipulatorFactory.getManipulator( type );

        manip.filter( "", null );
    }
}
