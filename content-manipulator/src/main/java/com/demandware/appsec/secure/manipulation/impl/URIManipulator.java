package com.demandware.appsec.secure.manipulation.impl;

import com.demandware.appsec.secure.manipulation.AbstractManipulator;
import com.demandware.appsec.secure.manipulation.IManipulateOption;

/**
 * URIManipulator handles all content related to URIs
 *
 * @author Chris Smith
 */
public class URIManipulator
    extends AbstractManipulator
{

    static enum URIManipulatorOption
        implements IManipulateOption
    {
        //This list contains characters that are immune from modification
        //COMPONENT is a lenient list, modeled after javascript's encodeURIComponent
        COMPONENT       ( '-', '_', '.', '~', '!', '*', '\'', '(', ')' ),
        //COMPONENT_STRICT is based on the RFC
        COMPONENT_STRICT( '-', '_', '.', '~' ),
        ;

        private final Character[] immune;

        private URIManipulatorOption( Character... immune )
        {
            this.immune = immune;
        }

        public Character[] getImmuneCharacters()
        {
            return this.immune;
        }
    }

    URIManipulator( URIManipulatorOption manipulatorOption )
    {
        super( manipulatorOption );
    }

    @Override
    protected String getCorrectCharacter( Character c )
    {
        String correctedCharacter = "";
        URIManipulatorOption opt = (URIManipulatorOption) this.manipulatorOption;

        //If the character is alphanumeric, or immune, it is OK
        if ( ManipulationUtils.isAlphaNum( c ) || ManipulationUtils.isInList( c, opt.getImmuneCharacters() ) )
        {
            correctedCharacter = String.valueOf( c );
        }
        //Otherwise, Percent encode the hex representation
        else
        {
            correctedCharacter = "%" + ManipulationUtils.getHexForCharacter( c );
        }

        return correctedCharacter;
    }
}
