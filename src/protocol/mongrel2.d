
module protocol.mongrel2;

public import protocol.httpapi;

import std.ascii, std.c.stdlib;
import std.stdio, std.string, std.conv, std.stdint, std.array, std.range, std.json,
       std.datetime, std.algorithm, std.concurrency, std.typecons, std.random, std.utf;
import deimos.zmq.zmq;

string zmqIdentity;
bool running = true;

extern (C) int errno;

// ------------------------------------------------------------------------- //

// Create a TLS context...
void * zmqCtx;
string zmqIdent;

// ------------------------------------------------------------------------- //
// ------------------------------------------------------------------------- //

class ZSocket
{
    static string verStr()
    {
        int major, minor, patch;
        zmq_version( &major, &minor, &patch );
        return format( "%d.%d.%d", major, minor, patch );
    }

    void * zmqSock;

    this( int type )
    {
		if( zmqCtx is null )
			zmqCtx = zmq_ctx_new();

		zmqSock = zmq_socket( zmqCtx, type );
    }

    this( string addr, int type )
    {
		if( zmqCtx is null )
			zmqCtx = zmq_ctx_new();
			
        zmqSock = zmq_socket( zmqCtx, type );
        connect( addr );
    }

    ~this()
    {
        close();
    }

    void bind( string addr )
    {
        if( zmq_bind( zmqSock, addr.toStringz ) != 0 )
			throw new Exception( "Failed to bind ZMQ socket to '" ~ addr );
    }

    void connect( string addr )
    {
        if( zmq_connect( zmqSock, addr.toStringz ) != 0 )
			throw new Exception( "Failed to connect ZMQ socket to '" ~ addr );
    }

    char[] receive( int flags = 0 )
    {
        zmq_msg_t msg;
        if( zmq_msg_init( &msg ) != 0 )
			throw new Exception( "Failed to init ZMQ message" );
			
        auto len = zmq_msg_recv( & msg, zmqSock, flags );

        char[] data;
        if( len >= 0 )
        {
            data = cast(char[]) zmq_msg_data( & msg )[ 0 .. len ].dup;
            zmq_msg_close( & msg );
        }
        return data;
    }

    void send( char[] buf )
    {
        zmq_msg_t msg;
        if( zmq_msg_init_size( & msg, buf.length ) != 0 )
			throw new Exception( "Failed to init ZMQ message" );
			
        std.c.string.memcpy( zmq_msg_data( & msg ), buf.ptr, buf.length );
        if( zmq_msg_send( & msg, zmqSock, 0 ) == -1 ) //send it off
			throw new Exception( "Failed to send ZMQ message" );

        zmq_msg_close( & msg );
    }

    int setSockOpt( int optName, char[] val )
    {
        return zmq_setsockopt( zmqSock, optName, cast(void *) val.ptr, val.length );
    }

    int setSockOpt( int optName, void * val, size_t vlen )
    {
        return zmq_setsockopt( zmqSock, optName, val, vlen );
    }

    void close()
    {
        if( zmqSock !is null )
            zmq_close( zmqSock );
    }
}

// ------------------------------------------------------------------------- //
// ------------------------------------------------------------------------- //

void mongrel2ServeImpl( ZSocket zmqReceive, HttpProcessor proc )
{
    char[ 20 ] ident;
    for( auto i = 0; i < 20; ++i )
        ident[ i ] = uniform( 'a', 'z' );

    zmqIdentity = ident.idup;
    writeln( "Identity: ", ident );
    zmqReceive.setSockOpt( ZMQ_IDENTITY, ident );

    bool done = false;
    while( !done )
    {
        char[] msg = zmqReceive.receive();
        debug dumpHex( msg );

        HttpRequest req = parseMongrelRequest( msg );
        if( req !is null && !isDisconnect( req ) )
            proc.onRequest( req );

        proc.onIdle();
    }
    proc.onExit();
}

// ------------------------------------------------------------------------- //

void mongrel2Serve( string addrPull, string addrPub, RequestDelegate dg )
{
    int major, minor, patch;
    zmq_version( &major, &minor, &patch );

    auto resPull = parseAddr( addrPull, SERVER_PORT );
    auto resPub  = parseAddr( addrPub, SERVER_PORT );

    string pull = format( "tcp://%s:%d", resPull[ 0 ], resPull[ 1 ] );
    string pub  = format( "tcp://%s:%d", resPub[ 0 ], resPub[ 1 ] );

    auto zmqReceive = new ZSocket( pull, ZMQ_PULL );
    auto zmqPublish = new ZSocket( pub, ZMQ_PUB );

    HttpProcessor proc = new DelegateProcessor( dg, zmqPublish );
    proc.onLog( format( "[0MQ %d.%d.%d] Connecting PULL socket to %s", major, minor, patch, pull ) );
    proc.onLog( format( "[0MQ %d.%d.%d] Connecting PUB socket to %s", major, minor, patch, pub ) );
    proc.onLog( "Executing in SYNC mode" );

    mongrel2ServeImpl( zmqReceive, proc );
}

// ------------------------------------------------------------------------- //

void mongrel2Serve( string addrPull, string addrPub, Tid tid )
{
    int major, minor, patch;
    zmq_version( &major, &minor, &patch );

    auto resPull = parseAddr( addrPull, SERVER_PORT );
    auto resPub  = parseAddr( addrPub, SERVER_PORT );

    string pull = format( "tcp://%s:%d", resPull[ 0 ], resPull[ 1 ] );
    string pub  = format( "tcp://%s:%d", resPub[ 0 ], resPub[ 1 ] );

    auto zmqReceive = new ZSocket( pull, ZMQ_PULL );
    auto zmqPublish = new ZSocket( pub, ZMQ_PUB );

    HttpProcessor proc = new TidProcessor( tid, zmqPublish );
    proc.onLog( format( "[0MQ %d.%d.%d] Connecting PULL socket to %s", major, minor, patch, pull ) );
    proc.onLog( format( "[0MQ %d.%d.%d] Connecting PUB socket to %s", major, minor, patch, pub ) );

    mongrel2ServeImpl( zmqReceive, proc );
}

// ------------------------------------------------------------------------- //

HttpRequest parseMongrelRequest( char[] data )
{
	if( data.length <= 0 )
		return null;
		
	debug writeln( "parsing mongrel2 request" );
    auto tmp   = findSplitBefore( data, " " );
    auto mconn = tmp[ 0 ].idup;
    tmp[ 1 ].popFront(); //skip found space

    tmp    = findSplitBefore( tmp[ 1 ], " " );
    mconn ~= ":" ~ tmp[ 0 ]; //add connection ID to the end of the sender UUID
    tmp[ 1 ].popFront(); //skip space

	HttpRequest req = new HttpRequest( cast(void*) mconn.ptr );
	debug writefln( "mongrel2 request %s", mconn );
    tmp            = findSplitBefore( tmp[ 1 ], " " );
    req.uri        = tmp[ 0 ].idup;
    tmp[ 1 ].popFront(); //skip space

    auto netstr     = parseNetString( tmp[ 1 ] ); //len in netstr[ 0 ], data in netstr[ 1 ]
    auto headerStr  = netstr[ 0 ];
    netstr          = parseNetString( netstr[ 1 ] );
    auto bodyStr    = netstr[ 0 ];

    JSONValue headerJSON = parseJSON( headerStr ); 
    assert( headerJSON != JSONValue.init );
    assert( headerJSON.type == JSON_TYPE.OBJECT );
    foreach( string k, JSONValue v; headerJSON.object )
    {
        string key = capHeaderInPlace( k.dup );

        assert( v.type == JSON_TYPE.STRING );
        req.headers[ key ] ~= v.str;

        if( key == "Method" ) //TODO: Handle JSON method from Mongrel
            req.method = toMethod( req.headers[ key ][ 0 ] );
        else if( key == "Version" )
            req.protocol = req.headers[ key ][ 0 ];
        else if( key == "Query" )
            req.attrs[ "uri_query" ] = req.headers[ key ][ 0 ];
    }

    if( req.method == Method.UNKNOWN && req.headers[ "Method" ][ 0 ] == "JSON" )
    {
        parseJSONBody( bodyStr, req );
        if( isDisconnect( req ) )
        {
            debug writeln( "Disconnect found" );
            return null;
        }
    }
	else
	{
		req.data = cast(shared(ubyte[])) bodyStr;
	}
//    debug dump( req );
    return req;
}

// ------------------------------------------------------------------------- //

char[] toMongrelResponse( HttpResponse resp )
{
    //serialise the response as appropriate
    auto buf = appender!( ubyte[] )();
    buf.reserve( 512 + resp.data.length );

    //retrieve the mongrel connection id from the connection identifier
	const(char)* mc = cast(const(char)*) resp.connection;
    char[] conn = to!(char[])( mc );
	debug writefln( "mongrel2 response %s", conn );
	
    auto tmp = findSplitAfter( conn, ":" );

    if( tmp[ 0 ].empty )
    {
        debug writeln( "Found no mongrel connection id in response connection string " ~ conn );
        return null; //no connection id,
    }

    buf.put( cast( ubyte[] ) zmqIdentity );
    buf.put( ' ' );
    buf.put( cast( ubyte[] ) to!string( tmp[ 1 ].length ) ); //length of following connection id
    buf.put( ':' );
    buf.put( cast( ubyte[] ) tmp[ 1 ] ); //connection id
    buf.put( ',' );
    buf.put( ' ' );

    //now add the HTTP payload
    buf.put( toBuffer( resp ) );

//    debug dumpHex( cast(char[]) buf.data );
    return cast(char[]) buf.data.dup;
}

// ------------------------------------------------------------------------- //

void parseJSONBody( char[] bodyStr, ref HttpRequest req )
{
    auto jsonBody = parseJSON( bodyStr );
    if( jsonBody == JSONValue.init )
        return;

    foreach( string k, JSONValue v; jsonBody.object )
    {
        req.attrs[ k ] = v.str;
    }
}

// ------------------------------------------------------------------------- //

Tuple!( char[], char[] ) parseNetString( char[] data )
{
    auto tmp = findSplitBefore( data, ":" );
    int len  = to!int( tmp[ 0 ] );
    tmp[ 1 ].popFront(); //skip colon
    assert( tmp[ 1 ][ len ] == ',' );

    return tuple( tmp[ 1 ][ 0 .. len ], tmp[ 1 ][ len + 1 .. $ ] );
}

// ------------------------------------------------------------------------- //

bool isDisconnect( HttpRequest req )
{
    if( req is null )
        return true;

    if( "Method" in req.headers && "type" in req.attrs )
        return req.headers[ "Method" ][ 0 ] == "JSON" &&
                            req.attrs[ "type" ] == "disconnect";
    return false;
}

// ------------------------------------------------------------------------- //
// ------------------------------------------------------------------------- //

class TidProcessor : HttpProcessor
{
public:

    this( Tid t, ZSocket conn )
    {
		tid = t;
        prefix = "[MONGREL2] ";
        zmqConn = conn;
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

    bool onIdle()  //return true if we processed something
    {
        receiveTimeout( dur!"usecs"( 0 ),
            ( int i )
            {
                running = ( i != 1 );
            },
            ( HttpResponse resp )
            {
                debug writefln( "protocol.mongrel2.TidProcessor::onIdle() received response" );
                if( resp !is null )
                    zmqConn.send( toMongrelResponse( resp ) );
            } );

        return true;
    }

	HttpResponse lastResponse() { return null; }

private:

    Tid tid;
    string prefix;
    ZSocket zmqConn;
}

// ------------------------------------------------------------------------- //

class DelegateProcessor : HttpProcessor
{
public:

    this( HttpResponse delegate(HttpRequest) d, ZSocket conn )
    {
        dg = d;
        prefix = "[MONGREL2] ";
        zmqConn = conn;
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
        if( lastResp !is null )
            zmqConn.send( toMongrelResponse( lastResp ) );
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
    ZSocket zmqConn;
}

// ------------------------------------------------------------------------- //
// ------------------------------------------------------------------------- //

