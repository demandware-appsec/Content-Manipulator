# Context Based Content Manipulation
#### Demandware Inc, 2015

## Code Status
[![Build Status](https://travis-ci.org/demandware-appsec/Content-Manipulator.svg?branch=master)](https://travis-ci.org/demandware-appsec/Content-Manipulator)

## Documentation
[Context Based Content Manipulation Documentation](http://demandware-appsec.github.io/Content-Manipulator/javadoc/)

## Goal
Provide a set of Context-Based Encoders and Filterers in Java that allow application developers to sanitize application data for safe output or processing. The library is designed to be easy to extend for other use-cases and requires no dependencies. This work is built off the excellent [ESAPI library](https://github.com/ESAPI/esapi-java), with a stronger emphasis on ease of expansion, an architecture with no setup requirements, and a focus on performance balanced with readability.

## Installation

### Standalone
JDK7: [content-manipulator-jdk7.jar](https://demandware-appsec.github.io/Content-Manipulator/jar/content-manipulator-jdk7.jar)

JDK8: [content-manipulator-jdk8.jar](https://demandware-appsec.github.io/Content-Manipulator/jar/content-manipulator-jdk8.jar)

### Maven
Use the following coordinates:
``` xml
<dependency>
  <groupId>TBD</groupId>
  <artifactId>TBD</artifactId>
</dependency>
```

## Design
### Supported Contexts     

Context                         | Description
------------------------------- | -------------------------- 
HTML Content   				 	| Encodes/Filters a given input for use in a general HTML context.
HTML Unquoted Attribute 	 	| Encodes/Filters a given input for use in an HTML Attribute left unguarded.
HTML Single Quoted Attribute	| Encodes/Filters a given input for use in an HTML Attribute guarded by a single quote.
HTML Double Quoted Attribute 	| Encodes/Filters a given input for use in an HTML Attribute guarded by a double quote.
Javascript in HTML 			 	| Encodes/Filters a given input for use in JavaScript inside an HTML context.
Javascript in Attribute 		| Encodes/Filters a given input for use in JavaScript inside an HTML attribute.
Javascript in Block 		 	| Encodes/Filters a given input for use in JavaScript inside an HTML block.
Javascript in Source Files 	 	| Encodes/Filters a given input for use in JavaScript inside a JavaScript source file.
JSON Values 				 	| Encodes/Filters a given input for use in a JSON Object Value.
URI Components 					| Encodes/Filters a given input for use as a component of a URI. This is equivalent to javascript's encodeURIComponent and does a realistic job of encoding.
URI Components (RFC-Compliant) 	| Encodes/Filters a given input for use as a component of a URI. This is a strict encoder and fully complies with [RFC3986](https://www.ietf.org/rfc/rfc3986.txt).
XML Content 					| Encodes/Filters a given input for use in a general XML context
XML Single Quoted Attribute 	| Encodes/Filters a given input for use in an XML attribute guarded by a single quote
XML Double Quoted Attribute 	| Encodes/Filters a given input for use in an XML attribute guarded by a double quote
XML Comment 					| Encodes/Filters a given input for use in an XML comments


### Architectural Decisions
<p>
The general flow of this library is to make calls against SecureEncoder or SecureFilter. These classes hold static methods to encode and filter, respectively. The methods all dispatch to an implementation of AbstractManipulator which is retreived by the ManipulatorFactory by ManipulationType. This ManipulationType is an enumeration of each AbstractManipulator flavor, which allows the Factory to only maintain one AbstractManipulator implementation per ManipulationType. This has significant performance gains, but requires all AbstractManipulator implementations to be entirely self-contained - no instance data should be saved in the object unless it is required for <u>all</u> executions of the implementaion. 
</p><p>
Control flow has now moved from static methods in SecureEncoder and SecureFilter to an instance of an AbstractManipulator implementation. AbstractManipulator implements an encode(String) and a filter(String) method which both utilize the abstract method getCorrectCharacter(Character). This method is the only required method to implement to add a new AbstractManipulator. Its contract is that is accepts a single Character object, does any necessary transformations on the Character and returns a safe, String version of the input Character. "Safe" in this context is variable per implementation, but in general should be a modification to the Character that makes it harmless to be output in the given context. When the getCorrectCharacter(Character) method is called in encode(String), each Character in the input String is collated returned. When the getCorrectCharacter(Character) method is called in filter(String), the returned value is checked against the input value to the original Character; if they differ, the returned string is dropped, otherwise it is collated and returned.
</p><p>
As an additional configuration, AbstractManipulators accept an implementation of IManipulateOption. This allows an AbstractManipulation implementation to support multiple similar contexts with the same class. E.g. HTMLManipulator has several ManipulateOptions that allow it to support content manipulation in plain HTML, or HTML attributes with different quotations.
</p>
### Example Usage
For examples on using the library, extending the library, or adding to the library, please see [Examples](./EXAMPLES.md)

## Tests
Included is a test suite ManipulatorTestSuite which executes sets of JUnit tests that cover over 95%+ of instructions in the library (some instructions are missed in defensive code branches).

## License
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.txt)