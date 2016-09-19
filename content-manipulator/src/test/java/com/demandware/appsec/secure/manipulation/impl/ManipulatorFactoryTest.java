package com.demandware.appsec.secure.manipulation.impl;

import static org.junit.Assert.*;

import org.junit.Test;

import com.demandware.appsec.secure.manipulation.AbstractCharacterManipulator;
import com.demandware.appsec.secure.manipulation.AbstractManipulator;
import com.demandware.appsec.secure.manipulation.IManipulateOption;
import com.demandware.appsec.secure.manipulation.SecureEncoder;
import com.demandware.appsec.secure.manipulation.impl.ManipulatorFactoryTest.CaesarCipherManipulator.CaesarOption;

public class ManipulatorFactoryTest
{
    enum TestManipulationType
        implements IManipulationType
    {
        CAESAR;

        public AbstractManipulator getManipulator()
        {
            return new CaesarCipherManipulator( CaesarOption.ROT_13 );
        }
    }

    static class CaesarCipherManipulator
        extends AbstractCharacterManipulator
    {
        enum CaesarOption
            implements IManipulateOption
        {
            ROT_13;
        }

        protected CaesarCipherManipulator( IManipulateOption manipulatorOption )
        {
            super( manipulatorOption );
        }

        @Override
        protected String getCorrectCharacter( Character c )
        {
            char shift = (char) ( c + 13 );
            if ( shift > 'z' )
            {
                shift = (char) ( shift - 26 );
            }
            else if ( shift < 'a' )
            {
                shift = (char) ( shift + 26 );
            }

            return String.valueOf( shift );
        }
    }

    static class TestSecureEncoder
        extends SecureEncoder
    {
        public static String encodeCaesar( String input )
        {
            return encode( TestManipulationType.CAESAR, input );
        }
    }

    @Test
    public void testRegistration()
    {
        TestManipulationType[] types1 = null;
        ManipulatorFactory.registerManipulationTypes( types1 );
        AbstractManipulator mainp1 = ManipulatorFactory.getManipulator( TestManipulationType.CAESAR );
        assertNull( mainp1 );

        TestManipulationType[] types2 = { null };
        ManipulatorFactory.registerManipulationTypes( types2 );
        AbstractManipulator mainp2 = ManipulatorFactory.getManipulator( TestManipulationType.CAESAR );
        assertNull( mainp2 );

        ManipulatorFactory.registerManipulationTypes( TestManipulationType.CAESAR );
        AbstractManipulator mainp3 = ManipulatorFactory.getManipulator( TestManipulationType.CAESAR );
        assertNotNull( mainp3 );
    }

    @Test
    public void testSubclassing()
    {
        ManipulatorFactory.registerManipulationTypes( TestManipulationType.CAESAR );

        String testString = "foobar";
        String expected = "sbbone";

        String result = TestSecureEncoder.encodeCaesar( testString );

        assertEquals( expected, result );

        assertEquals( testString, TestSecureEncoder.encodeCaesar( result ) );
    }
}
