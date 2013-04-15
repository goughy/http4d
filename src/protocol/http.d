/**

HTTP4D provides an easy entry point for providing embedded HTTP support
into any D application.

This module provides a simple HTTP implementation

License: $(LINK2 http://boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: $(LINK2 https://github.com/goughy, Andrew Gough)

Source: $(LINK2 https://github.com/goughy/d/tree/master/http4d, github.com)
*/


module protocol.http;

import std.string, std.concurrency, std.uri, std.conv, std.stdio, std.ascii;
import std.socket, std.algorithm, std.typecons, std.array, std.c.time, std.datetime;

import core.sys.posix.signal, core.sys.posix.stdlib;
import deimos.event2.keyvalq_struct, deimos.event2.http;

public import protocol.httpapi;

enum MAX_REQUEST_LEN = 1024 * 1024 * 20; // 20MB
enum DIVERT_REQUEST_LEN = 1024 * 30; // 50kB

enum TIMEOUT_MSEC   = 0;
enum CHUNK_SIZE     = 8096; //try to get at least Content-Length header in first chunk
bool running        = false;

enum SERVER_HEADER  = "Server";
enum SERVER_DESC    = "HTTP4D/1.0";
enum NEWLINE        = "\r\n";
enum HTTP_10        = "HTTP/1.0";
enum HTTP_11        = "HTTP/1.1";
enum SERVER_ADMIN   = "root";
enum SERVER_HOST    = "localhost.localdomain";
enum SERVER_PORT    = 8080;
enum USER_AGENT     = SERVER_DESC ~ " (" ~ __VENDOR__ ~ " " ~ to!string( __VERSION__ ) ~ ")";

/**
 * Delegate signature required to be implemented by any handler
 */

alias shared(Response) delegate(shared(Request)) RequestDelegate;

// ------------------------------------------------------------------------- //

class HttpException : Exception
{
public:

    this( int c = 400 )
    {
        super( StatusCodes[ c ] );
        code = c;
    }

    int code;
}

// ------------------------------------------------------------------------- //

/**
 * Synchronous HTTP request handler entry point.  Once executed, control
 * of the event loop stays in the library and control only returns to 
 * user code via the execution of the provided delegate.  This interface
 * provides the lowest execution overhead (as opposed to the asynchronous
 * interface below).
 * Example:
 * ---
 * import std.stdio;
 * import protocol.http;
*
* int main( string[] args )
*
{
    *     httpServe( "127.0.0.1:8888",
    * ( req ) => req.getResponse().
    *                             status( 200 ).
    *                             header( "Content-Type", "text/html" ).
    *                             content( "<html><head></head><body>Processed ok</body></html>" ) );
    *     return 0;
    *
}
* ---
*/

void httpServe( string bindAddr, RequestDelegate dg )
{
    auto res = parseAddr( bindAddr, SERVER_PORT );
    HttpProcessor proc = new DelegateProcessor( dg, "[HTTP-D] " );
    proc.onLog( "Executing in SYNC mode" );
    httpServeLibevent2( res[ 0 ], res[ 1 ], proc );
}

// ------------------------------------------------------------------------- //

/**
 * Asynchronous thread entry point for HTTP processing.  This interface requires
 * a $(D_PSYMBOL Tid) with a $(D_PSYMBOL Request) delegate clause.
 *
 * Example:
 * ---
 * import std.stdio, std.concurrency;
 * import protocol.http;
 *
 * int main( string[] args )
 * {
 *     Tid tid = spawnLinked( httpServe, "127.0.0.1:8888", thisTid() );
 *
 *     bool shutdown = false;
 *     while( !shutdown )
 *     {
 *         try
 *         {
 *             receive(
 *                 ( shared(Request) req )
 *                 {
 *                     send( tid, handleReq( req ) );
 *                 },
 *                 ( LinkTerminated e ) { shutdown = true; }
 *            );
 *        }
 *        catch( Throwable t )
 *        {
 *            writefln( "Caught exception waiting for msg: " ~ t.toString );
 *        }
 *    }
 * }
 *
 * shared(Response) handleReq( shared(Request) req )
 * {
 *      return req.getResponse().
 *              status( 200 ).
 *              header( "Content-Type", "text/html" ).
 *              content( "<html><head></head><body>Processed ok</body></html>" );
 * }
 *
 * ---
 */

void httpServe( string bindAddr, Tid tid )
{
    auto res = parseAddr( bindAddr, SERVER_PORT );
    HttpProcessor proc = new TidProcessor( tid, "[HTTP-D] " );
    proc.onLog( "Executing in ASYNC mode" );
    httpServeLibevent2( res[ 0 ], res[ 1 ], proc );
}

// ------------------------------------------------------------------------- //

HttpResponse httpClient( string url )
{
   Uri u = Uri( url );
   if( u.scheme != "http" )
       throw new Exception( "Unsupported URI scheme: " ~ u.scheme );

   HttpRequest req = new HttpRequest( null );
   req.method   = Method.GET;
   req.protocol = HTTP_11; //auto-close
   req.uri      = u.path;

   req.headers[ "Host" ]       ~= u.host ~ ":" ~ to!string( u.port );
   req.headers[ "User-Agent" ] ~= USER_AGENT;
   return httpClient( req );
}

// ------------------------------------------------------------------------- //

HttpResponse httpClient( HttpRequest req )
{
/* TODO: reimplement in terms of evhttp!! */
    return null;
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

ulong[string] httpStats;

private void addStat( string s, ulong num )
{
    if( auto p = s in httpStats )
        (*p) += num;
    else
        httpStats[ s ] = num;
}

private void incStat( string s )
{
    addStat( s, 1 );
}

private void setStat( string s, ulong num )
{
    httpStats[ s ] = num;
}

void showStats()
{
    foreach( k,v; httpStats )
        writefln( "\t%s = %u", k, v );
}

// ------------------------------------------------------------------------- //
// ------------------------------------------------------------------------- //

void httpServeLibevent2( string address, ushort port, HttpProcessor proc )
{
	auto base = event_base_new();
	enforce( base !is null, "Failed to create a libevent2 base event" );
	
	auto http = evhttp_new( base );
	enforce( http !is null, "Failed to create a libevent2 HTTP server" );
	
	proc.onLog( format( "libevent: Binding to %s:%d", address, port ) );
	auto fd = evhttp_bind_socket( http, address.toStringz, port );
//	enforce( fd > 0, "Failed to bind libevent2 HTTP server address" );
	
	auto accept = evhttp_accept_socket_with_handle( http, fd );
	enforce( accept !is null, "Failed to set libevent2 accept socket" );
	
	static extern(C) void evcb( evhttp_request * req, void * arg )
	{
		auto p = cast(HttpProcessor *) arg;
			
		auto uri = evhttp_request_get_uri( req );
		p.onRequest( toHttpRequest( req ) );
		if( p.lastResponse !is null )
		{
			evbuffer * databuf = toEvbuffer( req, p.lastResponse );
			scope(exit) { if( databuf !is null ) evbuffer_free( databuf ); }
			evhttp_send_reply( req, p.lastResponse.statusCode, p.lastResponse.statusMesg.toStringz, databuf );
		}
		else
			evhttp_send_error( req, 500, "No response!" );
	}
	
	evhttp_set_gencb( http, & evcb, cast(void *) & proc );
	event_base_dispatch( base );
}

// ------------------------------------------------------------------------- //

HttpRequest toHttpRequest( evhttp_request * req )
{
	HttpRequest hr = new HttpRequest( cast(void*)evhttp_request_get_connection( req ) );
	final switch( req.type )
	{
		case evhttp_cmd_type.EVHTTP_REQ_GET:
			hr.method = Method.GET;
			break;
		case evhttp_cmd_type.EVHTTP_REQ_POST:
			hr.method = Method.POST;
			break;
		case evhttp_cmd_type.EVHTTP_REQ_HEAD:
			hr.method = Method.HEAD;
			break;
		case evhttp_cmd_type.EVHTTP_REQ_PUT:
			hr.method = Method.PUT;
			break;
		case evhttp_cmd_type.EVHTTP_REQ_DELETE:
			hr.method = Method.DELETE;
			break;
		case evhttp_cmd_type.EVHTTP_REQ_OPTIONS:
			hr.method = Method.OPTIONS;
			break;
		case evhttp_cmd_type.EVHTTP_REQ_TRACE:
			hr.method = Method.TRACE;
			break;
		case evhttp_cmd_type.EVHTTP_REQ_CONNECT:
			hr.method = Method.CONNECT;
			break;
		case evhttp_cmd_type.EVHTTP_REQ_PATCH:
			hr.method = Method.PATCH;
			break;
	}
	hr.protocol = (req.minor == 0 ? HTTP_10 : HTTP_11);
	hr.uri      = "" ~ to!string( req.uri );
	
	auto headers = req.input_headers;
	for( auto cur = headers.tqh_first; cur.next.tqe_next != null; cur = cur.next.tqe_next )
		hr.headers[ to!string( cur.key ) ] ~= to!string( cur.value );
	
	auto len = evbuffer_get_length( req.input_buffer );
	if( len > 0 )
	{
		hr.data.length = len;
		evbuffer_remove( req.input_buffer, cast(void*) hr.data.ptr, len );
	}
	return hr;
}

// ------------------------------------------------------------------------- //

evbuffer* toEvbuffer( evhttp_request * req, HttpResponse resp )
{
	ubyte[] d = toBuffer( resp, false );
	foreach( k, arr; resp.headers )
	{
		foreach( v; arr )
			evhttp_add_header( req.output_headers, k.toStringz, v.toStringz );
	}
	
	evbuffer* buf = evbuffer_new();
	evbuffer_add( buf, cast(const(void)*) d.ptr, d.length );
	return buf;
}

// ------------------------------------------------------------------------- //

class TidProcessor : HttpProcessor
{
public:

    this( Tid t, string logPrefix = "[HTTP] " )
    {
        tid = t;
        prefix = logPrefix;
    }

    void onInit()
    {
        onLog( "Protocol initialising (ASYNC mode)" );
    }

    void onLog( string s )
    {
        if( tid != Tid.init )
            send( tid, prefix ~ s );
    }

    void onExit()
    {
        onLog( "Protocol exiting (ASYNC mode)" );
    }

    void onRequest( shared( Request ) req )
    {
        req.tid = cast(shared) thisTid();
        send( tid, req );
    }

    bool onIdle()
    {
        bool found = false;

        receiveTimeout( dur!"usecs"( 0 ),
        ( int i )
        {
            running = ( i != 1 );
        },
        ( HttpResponse resp )
        {
/*		
            foreach( conn; httpConns )
            {
                if( conn.id == resp.connection )
                {
                    conn.add( resp );
                    found = true;
                    break;
                }
            }
*/			
        } );

        return found;
    }

	HttpResponse lastResponse() { return null; }

private:

    Tid tid;
    string prefix;
}

// ------------------------------------------------------------------------- //

class DelegateProcessor : HttpProcessor
{
public:

    this( HttpResponse delegate(HttpRequest) d, string logPrefix = "[HTTP] " )
    {
        dg = d;
        prefix = logPrefix;
    }

    void onInit()
    {
        onLog( "Protocol initialising (SYNC mode)" );
    }

    void onLog( string s )
    {
        writeln( prefix ~ s );
    }

    void onExit()
    {
        onLog( "Protocol exiting (SYNC mode)" );
    }

    void onRequest( HttpRequest req )
    {
        lastResp = dg( req );
    }

    bool onIdle()
    {
        //noop for sync
        return false;
    }

	HttpResponse lastResponse() { return lastResp; }

protected:

	HttpResponse delegate(HttpRequest) dg;
    string prefix;
    HttpResponse lastResp;
}

// ------------------------------------------------------------------------- //
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

//    debug dumpHex( cast( char[] ) buf.data, "HTTP RESPONSE" );
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

ulong hexToULong( ubyte[] d )
{
    ulong val = 0;
    int pow = 1;
    foreach( u; std.range.retro( d ) )
    {
        val += ( isDigit( u ) ? u - '0' : u - ( 'A' - 10 ) ) * pow;
        pow *= 16;
    }
    return val;
}

unittest
{
    assert( hexToULong( ['3', '1', 'C'] ) == 796 );
}
