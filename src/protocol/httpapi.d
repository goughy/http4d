/**

HTTP4D provides an easy entry point for providing embedded HTTP support
into any D application.  The library provides endpoints for the following

Supported Protocols:
$(OL
    $(LI HTTP internal implementation)
    $(LI AJP internal implementation (incomplete))
    $(LI Mongrel2 - Relies on the ZMQ library))
It provides a very simple interface using request/response style making it very
easy to dispatch, route and handle a variety of web requests.

Example:
---
import std.stdio;
import protocol.http;

int main( string[] args )
{
    httpServe( "127.0.0.1", 8888,
                (req) => req.getResponse().
                            status( 200 ).
                            header( "Content-Type", "text/html" ).
                            content( "<html><head></head><body>Processed ok</body></html>" ) );
    return 0;
}
---
In general no attempt is made to ensure compliance to the HTTP protocol as part of the response
as that is deemed the responsibility of the developer using the library.  That is, this library
does not aim to be an HTTP/1.1 RFC 2616 compliant server, but rather an embeddable library
that can expose an endpoint that may be interacted with via an HTTP client
(such as a browser or programmatically eg. cURL).

This provides maximum flexibility to the developer, rather than implementing full server
constraints.  It is expected that an application would $(B $(I not)) expose itself to the
internet, but access would be moderated via a process with better security credentials, such
as $(LINK2 http://httpd.apache.org/, Apache), $(LINK2 http://www.nginx.org/, Nginx),
or $(LINK2 http://mongrel2.org/, Mongrel2).  The exception to this rule is with
respect to the "Connection" header, as that is used to determine the "keep-alive"
nature of the underlying socket connection - ie. set the "Connection" header to
"close" and the library will close the socket after transmitting the response.

However, by exposing an HTTP interface directly, those systems may proxy requests through
to a D application using this library incredibly easily.

License: $(LINK2 http://boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: $(LINK2 https://github.com/goughy, Andrew Gough)

Source: $(LINK2 https://github.com/goughy/d/tree/master/http4d, github.com)
*/

module protocol.httpapi;

import std.stdio, std.array, std.regex, std.typecons, std.ascii, std.string, 
		std.concurrency, std.conv, std.file, std.base64, std.string : splitter;
import core.sys.posix.signal, core.sys.posix.stdlib;

// ------------------------------------------------------------------------- //

enum MAX_REQUEST_LEN = 1024 * 1024 * 20; // 20MB
enum DIVERT_REQUEST_LEN = 1024 * 30; // 50kB

enum TIMEOUT_MSEC   = 0;
enum CHUNK_SIZE     = 8096; //try to get at least Content-Length header in first chunk
bool running        = false;

enum SERVER_HEADER  = "Server";
enum SERVER_DESC    = "http4d/1.0";
enum NEWLINE        = "\r\n";
enum HTTP_10        = "HTTP/1.0";
enum HTTP_11        = "HTTP/1.1";
enum SERVER_ADMIN   = "root";
enum SERVER_HOST    = "localhost.localdomain";
enum SERVER_PORT    = 8080;
enum USER_AGENT     = SERVER_DESC ~ " (" ~ __VENDOR__ ~ " " ~ to!string( __VERSION__ ) ~ ")";

// ------------------------------------------------------------------------- //
// ------------------------------------------------------------------------- //

enum Method
{
    UNKNOWN,
    OPTIONS,
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    TRACE,
    CONNECT,
	PATCH
};

// ------------------------------------------------------------------------- //

/**
 * The list of HTTP status codes from $(LINK2 http://en.wikipedia.org/wiki/List_of_HTTP_status_codes, Wikipedia)
 */

immutable string[int] StatusCodes;

static this()
{
    StatusCodes = [
                  100: "Continue",
                  101: "Switching Protocols",
                  102: "Processing",

                  200: "OK",
                  201: "Created",
                  202: "Accepted",
                  203: "Non-Authoritative Information",
                  204: "No Content",
                  205: "Reset Content",
                  206: "Partial Content",
                  207: "Multi-Status (RFC 4918)",
                  208: "Already Reported (RFC 5842)",
                  226: "IM Used (RFC 3229)",

                  300: "Mulitple Choices",
                  301: "Moved Permanently",
                  302: "Found",
                  303: "See Other",
                  304: "Not Modified",
                  305: "Use Proxy",
                  306: "Switch Proxy",
                  307: "Temporary Redirect",
                  308: "Permanent Redirect",

                  400: "Bad Request",
                  401: "Unauthorized",
                  402: "Payment Required",
                  403: "Forbidden",
                  404: "Not Found",
                  405: "Method Not Allowed",
                  406: "Not Acceptable",
                  407: "Proxy Authentication Required",
                  408: "Request Timeout",
                  409: "Conflict",
                  410: "Gone",
                  411: "Length Required",
                  412: "Precondition Failed",
                  413: "Request Entity Too Large",
                  414: "Request-URI Too Long",
                  415: "Unsupported Media Type",
                  416: "Requested Range Not Satisfiable",
                  417: "Expectation Failed",
                  418: "I'm a teapot (RFC 2324)", //wtf!
                  420: "Enhance Your Calm (Twitter)",
                  422: "Unprocessable Entity (RFC 4918)",
                  423: "Locked (RFC 4918)",
                  424: "Failed Dependency (RFC 4918)",
                  425: "Unordered Collection (RFC 3648)",
                  426: "Upgrade Required (RFC 2817)",
                  428: "Precondition Required",
                  429: "Too Many Requests",
                  431: "Request Header Fields Too Large",
                  444: "No Response (Nginx)",
                  449: "Retry With (Microsoft)", //M$ extension
                  450: "Blocked By Windows Parental Controls (Microsoft)",
                  499: "Client Closed Request (Nginx)",

                  500: "Internal Server Error",
                  501: "Not Implemented",
                  502: "Bad Gateway",
                  503: "Service Unavailable",
                  504: "Gateway Timeout",
                  505: "HTTP Version Not Supported",
                  506: "variant Also Negotiates (RFC 2295)",
                  507: "Insufficient Storage (RFC 4918)",
                  508: "Loop Detected (RFC 5842)",
                  509: "Bandwidth Limit Exceeded (Apache)",
                  510: "Not Extended (RFC 2774)",
                  511: "Network Authenticated Required",
                  598: "Network read timeout error",
                  599: "Network connect timeout error"
                  ];
}

// ------------------------------------------------------------------------- //

struct Uri
{
    string scheme;
    string userName; //TODO
    string password; //TODO
    string host;
    ushort port;
    string path;

    this( string uri )
    {
        port = 80u;

        int state = 0;
        string scratch;

        foreach( i, c; uri )
        {
            switch( state )
            {
                case 0: // scheme
                    if( c == ':' )
                        state = 1;
                    else
                        scheme ~= c;
                    break;

                case 1: //process '://'
                    if( c != ':' && c != '/' )
                    {
                        state = 2;
                        host ~= c;
                    }
                    break;

                case 2: //process host
                    if( c == ':' )
                        state = 3;
                    else if( c == '/' )
                    {
                        state = 4;
                        path ~= c;
                    }
                    else
                        host ~= c;
                    break;

                case 3: //process port
                    if( !isDigit( c ) )
                    {
                        if( c == '/' )
                            path ~= c;

                        if( scratch.length )
                            port = to!ushort( scratch );

                        state = 4;
                    }
                    else
                        scratch ~= c;
                    break;
                
                case 4: //process path
                    path ~= c;
                    break;

                default:
                    break;
            }
        }
    }

    debug void dump()
    {
        writeln( "\tscheme  : " ~ scheme );
        writeln( "\tuserName: " ~ userName );
        writeln( "\tpassword: " ~ password );
        writeln( "\thost    : " ~ host );
        writeln( "\tport    : " ~ to!string( port ) );
        writeln( "\tpath    : " ~ path );
    }

    string toString()
    {
        return scheme ~ "://" ~ host ~ ":" ~ to!string( port ) ~ path;
    }
}

unittest 
{
    Uri u = Uri( "" );
    assert( u.scheme.length == 0 );

    u = Uri( "http://example.com" );
    u.dump();
    assert( u.scheme.length == 4 );
    assert( u.host == "example.com" );
    assert( u.port == 80u );

    u = Uri( "http://example.com:8080/abc" );
    u.dump();
    assert( u.scheme.length == 4 );
    assert( u.host == "example.com" );
    assert( u.port == 8080u );
    assert( u.path == "/abc" );

    u = Uri( "http://example.com:8080/" );
    u.dump();
    assert( u.scheme.length == 4 );
    assert( u.host == "example.com" );
    assert( u.port == 8080u );
    assert( u.path == "/" );
}

/**
 * The $(D Request) class encapsulates all captured data from the inbound client
 * request.  It is the core class the library provides to model an HTTP request
 * from any source.
 *
 * Note that this class is defined as shared to support the asynchronous dispatch
 * model using std.concurrency.
 */

shared class Request
{
public:

    this( void* id = null )
    {
        connection = cast(shared(void*))id;
    }
    
    Tid              tid;
    void*            connection;
    Method           method;
    string           protocol;
    string           uri;
    string[][string] headers;
    string[string]   attrs;
    ubyte[]          data;

    string[] getHeader( string k )
    {
		static string[] empty;
		auto key = capHeaderInPlace( k.dup );
		if( auto res = key in headers )
			return cast(string[]) *res;
		
		return empty;
    }

    string getAttr( string k )
    {
        return attrs[ k.toLower ];
    }

    shared( Response ) getResponse()
    {
        //bind the response to the request connection
        shared Response resp = cast( shared ) new Response( cast(void*)connection, protocol );

        if( "Connection" in headers )
            resp.addHeader( "Connection", getHeader( "Connection" )[ 0 ] );

        return resp;
    }

    
}

// ------------------------------------------------------------------------- //

/**
 * The $(D_PSYMBOL Response) class is delivered back to the library to be serialized and
 * transmitted to the underlying socket as defined by the $(D_PARAM connection)
 * parameter.  In general, the $(D_PARAM getResponse()) function on the
 * $(D_PSYMBOL Request) should be used to create the $(D_PSYMBOL Response) as this ensures the
 * $(D_PARAM connection) attribute is copied from the request.  However, this is
 * not strictly necessary, and a Response may be created manually so long as the
 * $(D_PARAM Request.connection) is copied to the $(D_PARAM Response.connection).
 *
 * Note that this class is defined as shared to support the asynchronous dispatch
 * model using std.concurrency.
 */

shared class Response
{
public:

    this( void* id = null, string proto  = "" )
    {
        connection = cast(shared(void*))id;
        protocol = proto;
    }

    void*            connection;
    string           protocol;
    int              statusCode;
    string         	 statusMesg;
    string[][string] headers;
    ubyte[]          data;

    shared( Response ) addHeader( string k, string v )
    {
        headers[ capHeaderInPlace( k.dup ) ] ~= v;
        return this;
    }
}

// ------------------------------------------------------------------------- //
/**
 * The function protoype for the predefined dispatchers.  Any defined handler function
 * must implement this signature.
 *
 * Example:
 * ---
 *
 * import std.stdio;
 * import protocol.http;
 *
 * int main( string[] args )
 * {
 *     httpServe( "127.0.0.1", 8888, (req) => handleReq( req ) );
 *     return 0;
 * }
 *
 * shared(Response) handleReq( shared(Request) req )
 * {
 *      return req.getResponse().
 *              status( 200 ).
 *              header( "Content-Type", "text/html" ).
 *              content( "<html><head></head><body>Processed ok</body></html>" );
 * }
 * ---
 */
alias shared( Response ) function( shared( Request ) ) RequestHandler;

alias shared( Request ) HttpRequest;
alias shared( Response ) HttpResponse;

/**
 * Delegate signature required to be implemented by any handler
 */

alias shared(Response) delegate(shared(Request)) RequestDelegate;


// ------------------------------------------------------------------------- //

class HttpException : Exception
{
public:

    this( int c = 400, string m = "" )
    {
        super( m.empty ? StatusCodes[ c ] : m );
        code = c;
    }

    int code;
}

// ------------------------------------------------------------------------- //

interface HttpProcessor
{
    void onInit();
    void onLog( string s );
    void onRequest( shared( Request ) req );
    bool onIdle();  //return true if we processed something
    void onExit();
	
	HttpResponse lastResponse();
}

// ------------------------------------------------------------------------- //

/**
 * Router base class for setting the default handler and providing
 * $(D_PSYMBOL opCall()).  DO NOT USE! Use one of the subclasses instead (or
 * subclass your own)
 */

class Router
{
public:

    this()
    {
        defHandler = ( req ) => error( req.getResponse(), 404 );
    }

    RequestHandler defaultHandler( RequestHandler func )
    {
        auto old = defHandler;
        defHandler = func;
        return old;
    }

    HttpResponse opCall( HttpRequest r )
    {
        return dispatch( r );
    }

    HttpResponse dispatch( HttpRequest req )
    {
        return defHandler( req );
    }

    abstract void dumpRoutes();

protected:

    RequestHandler defHandler;
}

// ------------------------------------------------------------------------- //

/**
 * A convenience class that provides a dispatch mechanism based on the
 * HTTP Method in a $(D_PSYMBOL Request).
 *
 * Example:
 * ---
 * import std.stdio;
 * import protocol.http;
 *
 * int main( string[] args )
 * {
 *     MethodRouter dispatcher = new MethodRouter;
 *     dispatcher.mount( Method.GET, &onGet );
 *     dispatcher.mount( Method.POST, &onPost );
 *
 *     httpServe( "127.0.0.1", 8888, (req) => dispatcher( req ) );
 *     return 0;
 * }
 *
 * shared(Response) onGet( shared(Request) req )
 * {
 *      return req.getResponse().
 *              status( 200 ).
 *              header( "Content-Type", "text/html" ).
 *              content( "<html><head></head><body>Processed ok</body></html>" );
 * }
 *
 * shared(Response) onPost( shared(Request) req )
 * {
 *     return req.getResponse().error( 405 );
 * }
 * ---
 */

class MethodRouter : Router
{
public:

    MethodRouter mount( Method m, RequestHandler func )
    {
        return mount( m, std.functional.toDelegate( func ) );
    }

    MethodRouter mount( Method m, Router d )
    {
        return mount( m, &d.dispatch );
    }

    MethodRouter mount( Method m, RequestDelegate dg )
    {
        HandlerType ht;
        ht.m = m;
        ht.f = dg;
        handlerMap ~= ht;

        return this;
    }

    // Map all methods to their respective functions
    // so you can do for all HTTP methods defined in Method:
    //      
    //      MethodRouter r = new MethodRouter;
    //      r.get( & getHandler );
    //      r.post( & postHandler );
    //      r.head( & headHandler );
    //
    //  ...etc...
    //
    MethodRouter opDispatch(string op, T)( T func ) if( is(T : RequestHandler) )
    {
        mixin( "return mount( Method."  ~ op.toUpper ~ ", func );" );
    }

    override HttpResponse dispatch( HttpRequest req )
    {
        foreach( handler; handlerMap )
        {
            if( req.method == handler.m )
                return handler.f( req );
        }
        return defHandler( req );
    }

    override void dumpRoutes()
    {
        writefln( "MethodRouter::dumpRoutes()" );
        foreach( handler; handlerMap )
        {
            writefln( "\t%s (method)", to!string( handler.m ) );
        }
    }

private:

    alias HttpResponse delegate(HttpRequest) RequestDelegate;
    alias Tuple!( Method, "m", RequestDelegate, "f" ) HandlerType;
    HandlerType[]  handlerMap;
}

// ------------------------------------------------------------------------- //
/**
 * A convenience class that provides a dispatch mechanism based on the
 * URI in a $(D_PSYMBOL Request) using regular expressions.
 *
 * Example:
 * ---
 * import std.stdio, std.regex;
 * import protocol.http;
 *
 * int main( string[] args )
 * {
 *     UriRouter dispatcher = new UriRouter;
 *     dispatcher.mount( regex( "/abc$" ), &onABC );
 *     dispatcher.mount( regex( "/def$" ), &onDEF );
 *
 *     httpServe( "127.0.0.1", 8888, (req) => dispatcher( req ) );
 *     return 0;
 * }
 *
 * shared(Response) onABC( shared(Request) req )
 * {
 *      return req.getResponse().
 *              status( 200 ).
 *              header( "Content-Type", "text/plain" ).
 *              content( "Processed an ABC request" );
 * }
 *
 * shared(Response) onDEF( shared(Request) req )
 * {
 *      return req.getResponse().
 *              status( 200 ).
 *              header( "Content-Type", "text/plain" ).
 *              content( "Processed a DEF request" );
 * }
 * ---
 */

class UriRouter : Router
{
public:

    UriRouter mount( string r, RequestHandler func )
    {
        return mountImpl( r, std.functional.toDelegate( func ) );
    }

    UriRouter mount( string r, Router d )
    {
        return mountImpl( r, &d.dispatch );
    }

    UriRouter mount( string r, RequestDelegate dg )
    {
        return mountImpl( r, dg );
    }

    override HttpResponse dispatch( HttpRequest req )
    {
        foreach( handler; handlerMap )
        {
//            debug writefln( "Checking regex %s matches uri %s", handler.u, req.uri );
            if( match( req.uri, handler.r ) )
                return handler.f( req );
        }
        return defHandler( req );
    }

    override void dumpRoutes()
    {
        writefln( "UriRouter::dumpRoutes()" );
        foreach( handler; handlerMap )
        {
            writefln( "\t%s (regex)", handler.u );
        }
    }

private:

    UriRouter mountImpl( string r, RequestDelegate dg )
    {
        HandlerType ht;
        ht.u = r;
        ht.r = regex( r );
        ht.f  = dg;
        handlerMap ~= ht;

        return this;
    }

    alias HttpResponse delegate(HttpRequest) RequestDelegate;
    alias Tuple!( string, "u", Regex!char, "r", RequestDelegate, "f" ) HandlerType;
    HandlerType[] handlerMap;
}

// ------------------------------------------------------------------------- //

class AutoRouter(T) : Router
{
public:

    this( string base = "/" )
    {
        instance     = new T;
        methodRouter = new MethodRouter;

        init( base );
    }


    override HttpResponse dispatch( HttpRequest req )
    {
        return methodRouter( req );
    }

    override void dumpRoutes()
    {
        writefln( "AutoRouter!" ~ T.stringof ~ "::dumpRoutes()" );
        methodRouter.dumpRoutes();
        foreach( s,r; uriRouters )
            r.dumpRoutes();
    }

private:

    void init( string base )
    {
        //CTFE
        static string ctfeMemberFuncs(T)()
        {
            string s = "";
            foreach( mbr; __traits(derivedMembers, T) )
            {
                std.traits.ParameterTypeTuple!(__traits(getMember, T, mbr)) args;

                static if( args.length == 1 && typeof( args[ 0 ] ).stringof == HttpRequest.stringof && 
                            std.traits.ReturnType!(__traits(getMember, T, mbr)).stringof == HttpResponse.stringof )
                {
                    pragma( msg, "Processing member " ~ T.stringof ~ "." ~ mbr );
                    foreach( meth; __traits(allMembers,Method) )
                    {
                        static if( meth == to!string( Method.UNKNOWN ) )
                            continue;

                        auto r = std.algorithm.findSplit( mbr.toLower, to!string( meth ).toLower );
                        if( !r[1].empty )
                            s = s ~ "makeMount( \"" ~ mbr ~ "\", Method." ~ meth ~ ", \"" ~ r[ 2 ] ~ "\", &instance." ~ mbr ~ ");";
                    }
                }
                else
                    pragma( msg, "Unrecognised signature on member " ~ T.stringof ~ "." ~ mbr ~ " - ignoring" );
            }
            return s;
        }

        //runtime
        void makeMount( string funcName, Method method, string mountPoint, HttpResponse delegate(HttpRequest) handler )
        {
            UriRouter uriRouter;
            if( method in uriRouters )
                uriRouter = uriRouters[ method ];
            else
            {
                uriRouter = new UriRouter;
                uriRouters[ method ] = uriRouter;
            }
            if( base[ $ - 1 ] == '/' )
                base = base[ 0 .. $ - 1 ];

            debug writeln( "Mapping " ~ T.stringof ~ "." ~ funcName ~"() -> [" ~ to!string( method ) ~ ", " ~ base ~ "/" ~ mountPoint ~ "]" );
            uriRouter.mount( "^" ~ base ~ "/" ~ mountPoint, handler );
            methodRouter.mount( method, uriRouter );
        }

        mixin( ctfeMemberFuncs!(T) );

        if( uriRouters.length == 0 )
            stderr.writeln( "WARN: failed to extract any routes from specified type: " ~ T.stringof );
    }

    T                 instance;
    MethodRouter      methodRouter;
    UriRouter[Method] uriRouters;
}


// ------------------------------------------------------------------------- //

Method toMethod( string m )
{
    //enum Method { UNKNOWN, OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT };
    switch( m.toLower )
    {
        case "get":
            return Method.GET;

        case "post":
            return Method.POST;

        case "head":
            return Method.HEAD;

        case "options":
            return Method.OPTIONS;

        case "put":
            return Method.PUT;

        case "delete":
            return Method.DELETE;

        case "trace":
            return Method.TRACE;

        case "connect":
            return Method.CONNECT;

        default:
            break;
    }

    return Method.UNKNOWN;
}

// ------------------------------------------------------------------------- //

ubyte[] toBuffer( HttpResponse r, bool includeHeaders = true )
{
    auto buf = appender!( ubyte[] )();
    buf.reserve( 512 );

    if( includeHeaders )
    {
        buf.put( cast( ubyte[] ) HTTP_11 );
        buf.put( ' ' );

        buf.put( cast( ubyte[] ) to!string( r.statusCode ) );
        buf.put( ' ' );
        buf.put( cast( ubyte[] ) r.statusMesg );
        buf.put( '\r' );
        buf.put( '\n' );

        r.addHeader( SERVER_HEADER, SERVER_DESC );

        if( !( "Date" in r.headers ) )
        {
            long now = time( null );
            r.addHeader( "Date", to!string( asctime( gmtime( & now ) ) )[0..$ -1] );
        }

		if( !( "Content-Length" in r.headers ) )
			r.addHeader( "Content-Length", to!string( r.data.length ) );

        foreach( k, v1; r.headers )
        {
            foreach( v; v1 )
            {
                buf.put( cast( ubyte[] ) k );
                buf.put( ':' );
                buf.put( ' ' );
                buf.put( cast( ubyte[] ) v );
                buf.put( '\r' );
                buf.put( '\n' );
            }
        }

		buf.put( '\r' );
		buf.put( '\n' );
    }

    if( r.data.length > 0 )
        buf.put( cast( ubyte[] ) r.data );

    debug dump( r, "HTTP RESPONSE" );
    return buf.data;
}

// ------------------------------------------------------------------------- //

ubyte[] toBuffer( HttpRequest req )
{
    ubyte[] buf;

    buf ~= format( "%s %s %s\r\n", to!string( req.method ), req.uri.dup, req.protocol.dup );
    buf ~= format( "Host: %s\r\n", req.getHeader( "Host" ) );
    foreach( k,v1; req.headers )
    {
        if( k != "Host" )
        {
            foreach( v; v1 )
                buf ~= format( "%s: %s\r\n", k.dup, v.dup );
        }
    }

    buf ~= format( "Connection: %s\r\n\r\n", req.protocol == HTTP_10 ? "close" : "Keep-Alive" );
    return buf;
}

// ------------------------------------------------------------------------- //

string[string] loadMimeTypes( string mimeFile = "/etc/mime.types" )
{
	string[string] mt;
	version(Posix) 
	{
		if( exists( mimeFile ) )
		{
			auto f = File( mimeFile );

			auto r = regex( r"\s*#.*" );
			foreach( line; f.byLine )
			{
				if( match( line, r ) )
					continue; //filter comments
				
				auto s = std.string.split( line );
				for( auto i = 1; i < s.length; ++i )
					mt[ s[ i ].idup ] = s[ 0 ].idup;
			}
		}
	}
	return mt;
}

/**
 * Parse an address of the form "x.x.x.x:yyyy" into a string address and 
 * corresponding ushort port
 */
Tuple!(string,ushort) parseAddr( string addr, ushort def )
{
    auto res = std.algorithm.findSplit( addr, ":" );
    ushort port = (res.length == 3) ? to!ushort( res[ 2 ] ) : def; //default
    return tuple( res[ 0 ], port );
}

// ------------------------------------------------------------------------- //

string capHeaderInPlace( char[] hdr )
{
    bool up = true; //uppercase first letter
    foreach( i, char c; hdr )
    {
        if( isAlpha( c ) )
        {
            hdr[ i ] = cast( char )( up ? toUpper( c ) : toLower( c ) );
            up = false;
        }
        else
            up = true;
    }
    return hdr.idup;
}

// ------------------------------------------------------------------------- //

/**
 * Parse a header of the form:
 *  
 *  key1=val1, key2=val2, key3=val3
 *
 * and return an associative array of the pairs
 */

string[string] parseHeader( string c, string delim = "," )
{
    string[string] result;
    foreach( ref val; std.algorithm.splitter( c, delim ) )
    {
        auto r1 = std.algorithm.findSplit( val, "=" );
        if( r1.length == 3 )
            result[ r1[ 0 ] ] = r1[ 2 ];
    }
    return result;
}

alias parseHeader parseQueryString;

// ------------------------------------------------------------------------- //

/** Convenience function to set the HTTP response status code and message */
HttpResponse status( HttpResponse r, int c, string m = null )
{
    r.statusCode = c;
    r.statusMesg = m;

    if( m is null )
        r.statusMesg = c in StatusCodes ? StatusCodes[ c ] : "";

    return r;
}

/** Convenience function to set the HTTP response status code and message to '200 OK'*/
shared( Response ) ok( shared( Response ) r )                           { return status( r, 200 ); }
/** Convenience function to set the HTTP response status code */
shared( Response ) error( shared( Response ) r, int c )                 { return status( r, c ); }
/** Convenience function to set the HTTP response status code */
shared( Response ) notfound( shared( Response ) r )                     { return status( r, 404 ); }

/** Convenience function to set the HTTP response status message */
shared( Response ) msg( shared( Response ) r, string m )                { r.statusMesg = m; return r; }
/** Convenience function to set a $(D_PSYMBOL Response) header */
shared( Response ) header( shared( Response ) r, string h, string v )   { r.headers[ h ] ~= v; return r; }
/** Convenience function to set a $(D_PSYMBOL Response) content */
shared( Response ) content( shared( Response ) r, string v )            { r.data = cast( shared ubyte[] ) v.dup; return r; }
/** Convenience function to set a $(D_PSYMBOL Response) content */
shared( Response ) content( shared( Response ) r, char[] v )            { r.data = cast( shared ubyte[] ) v; return r; }
/** Convenience function to set a $(D_PSYMBOL Response) content */
shared( Response ) content( shared( Response ) r, ubyte[] v )           { r.data = cast( shared ubyte[] ) v; return r; }

// ------------------------------------------------------------------------- //

debug void dump( shared( Request ) r, string title = "" )
{
    if( title.length > 0 )
        writeln( title );

//    writeln( "Connection: ", r.connection );
    writeln( "Method    : ", r.method );
    writeln( "Protocol  : ", r.protocol );
    writeln( "URI       : ", r.uri.idup );

    writeln( "Headers   : " );
    foreach( k, v; r.headers )
		writeln( "\t", k.idup, ": ", v.idup );

    writeln( "Attributes: " );
    foreach( k, v; r.attrs )
		writeln( "\t", k.idup, ": ", v.idup );
}

// ------------------------------------------------------------------------- //

debug void dump( shared( Response ) r, string title = "" )
{
    if( title.length > 0 )
        writeln( title );

//    writeln( "Connection: ", to!string( r.connection ) );
    writeln( "Status    : ", r.statusCode, " - ", r.statusMesg.idup );

    foreach( k, v; r.headers )
		writeln( "\t", k.idup, ": ", v.idup );

    dumpHex( cast( char[] ) r.data );
}

// ------------------------------------------------------------------------- //


debug void dumpHex( char[] buf, string title = "", int cols = 16 )
{
    if( buf.length <= 0 )
        return;

    assert( cols < 256 );
    assert( buf.length > 0 );

    if( title.length > 0 )
        writeln( title );

    char[ 256 ] b1;
    int x = 0, i = 0;

    for( ; i < buf.length; ++i )
    {
        if( x > 0 && i > 0 && i % cols == 0 )
        {
            writefln( "   %s", b1[ 0 .. x ] );
            x = 0;
        }

        b1[ x++ ] = .isPrintable( buf[ i ] ) ? buf[ i ] : '.';
        writef( "%02x ", buf[ i ] );
    }

//      writefln( "\n(D) x = %d, i = %d", x, i );
    if( x > 0 )
        writefln( "%s   %s", ( cols > x ) ? replicate( "   ", cols - x ) : "", b1[ 0 .. x ] );
}

// ------------------------------------------------------------------------- //


