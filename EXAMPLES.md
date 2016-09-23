# Examples
## Standard Use Case Example
```jsp
<script>
	$("button").click(function(){
		$.ajax({
			url: "http://external.host.com/ajax_endpoint", 
			data: {"trusted_content": "<%=SecureEncoder.encodeJSONValue( getAjaxData() ) %>"}
			success: function(result){
				$(".ajax_result").html(result);
			}
		})
	})
</script>
<h2>Welcome to the application <%=SecureEncoder.encodeHtmlContent( getUserName() ) %></h2>
```

## Extending functionality of Encoder/Filter
```java
/**
 * Adds ability to call manipulators using a String designation
 * 
 */
public class CustomSecureEncoder extends SecureEncoder{

	private static DefaultManipulationType getManipulationType( String type )
	{
		DefaultManipulationType manip = null;

		switch( type.toLowerCase() )
		{
		case "htmlcontent":
			manip = DefaultManipulationType.HTML_CONTENT_MANIPULATOR;
			break;
		case "htmlsinglequote":
			manip = DefaultManipulationType.HTML_UNQUOTED_ATTRIBUTE_MANIPULATOR;
			break;
		default:
			break;
		}
		
		return manip;
	}

    public static String encodeByStringType( String type, String input )
    {
        DefaultManipulationType manip = getManipulationType( type );
        if( manip == null )
        {
            throw new IllegalArgumentException( "SecureEncoder was given an illegal type: " + type );
        }
        return encode( manip, input );
    }

    public static void main( String... s )
    {
    	String testString = "<script></script>";
	    System.out.println( CustomSecureEncoder.encodeHtmlContent( testString ) ); 
	    System.out.println( CustomSecureEncoder.encodeByStringType( "htmlcontent", testString ) );
    }
    /*
     * Output:
     * &lt;script&gt;&lt;/script&gt;
     * &lt;script&gt;&lt;/script&gt;
     */
}
```

## Adding a new Manipulator
First you must create the Manipulator
```java
/**
 * This Manipulator Base64 encodes specific symbols, leaving all other
 * values untouched
 */
public class Base64SymbolManipulator extends AbstractCharacterManipulator
{

	static enum Base64SymbolManipulatorOption implements IManipulateOption
	{
		STANDARD( '~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', 
				  '_', '+', '`', '-', '=', '{', '}', '|', '[', ']', '\\', 
				  ':', '"', ';', '\'', '<', '>', '?', ',', '.', '/' ),
		;
		
		private final Character[] targets;
		
		Base64SymbolManipulatorOption( Character... targets )
		{
			this.targets = targets;
		}
		
		public Character[] getTargets()
		{
			return this.targets;
		}
	}
	

	protected Base64SymbolManipulator( Base64SymbolManipulatorOption manipulatorOption ) 
	{
		super( manipulatorOption );
	}
	
	@Override
	protected String getCorrectCharacter( Character c ) 
	{
        String correctedCharacter = "";
        
        Base64SymbolManipulatorOption opt = (Base64SymbolManipulatorOption) this.manipulatorOption;
		
		if( ManipulationUtils.isInList( c, opt.getTargets() ) )
		{
			try 
			{
				correctedCharacter = Base64.getEncoder().encodeToString( String.valueOf( c ).getBytes( "UTF-8" ) );
			} 
			catch ( UnsupportedEncodingException e ) 
			{
				e.printStackTrace();
			}
		}
		else
		{
			correctedCharacter = String.valueOf( c );
		}
		
		return correctedCharacter;
	}
}
```

Next, create a ManipulationType enum
```java
public enum CustomManipulationType implements IManipulationType
{
	BASE64_SYMBOLS_STANDARD( new Base64SymbolManipulator( Base64SymbolManipulatorOption.STANDARD ) ),
	;

	private final AbstractManipulator manipulator;

    private DefaultManipulationType( AbstractManipulator manipulator )
    {
        this.manipulator = manipulator;
    }

    public AbstractManipulator getManipulator()
    {
        return this.manipulator;
    }
}
```

Finally, register the manipulator in the Factory. This method should be called once e.g. in an application init sequence
```java
public void applicationInit()
{
	...

	ManipulationFactory.registerManipulationTypes( CustomManipluationType.values() );
	...	
}
```

Now you can subclass SecureEncoder and SecureFilter
```java
public class CustomSecureEncoder extends SecureEncoder
{
	public static encodeBase64Symbols( String input )
	{
		return encode( CustomManipulationType.BASE64_SYMBOLS_STANDARD, input );
	}

	public static encodeBase64Symbols( String input, Writer out )
	{
		encode( CustomManipulationType.BASE64_SYMBOLS_STANDARD, input, out );
	}
}

public class CustomSecureFilter extends SecureFilter
{
	public static filterBase64Symbols( String input )
	{
		return filter( CustomManipulationType.BASE64_SYMBOLS_STANDARD, input );
	}

	public static filterBase64Symbols( String input, Writer out )
	{
		filter( CustomManipulationType.BASE64_SYMBOLS_STANDARD, input, out );
	}
}

```

Which can be called via
```java
	CustomSecureFilter.encodeBase64Symbols( "foobar!" );
	CustomSecureFilter.encodeHtmlContent( "foobar!" );
```
