
module protocol.http;

import std.string, std.concurrency, std.uri, std.conv, std.stdio, std.ascii;
import std.socket, std.algorithm, std.typecons, std.array, std.c.time;
import util.util;

import core.sys.posix.signal;

enum Method { UNKNOWN, OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT };
string[] Headers = [ "", //dummy entry
                        "accept",
                        "accept-charset",
                        "accept-encoding",
                        "accept-language",
                        "authorization",
                        "connection",
                        "content-type",
                        "content-length",
                        "cookie",
                        "cookie2",
                        "host",
                        "pragma",
                        "referer",
                        "user-agent" ];

enum TIMEOUT_USEC = 500;
enum CHUNK_SIZE   = 1024; //try to get at least Content-Length header in first chunk
bool running = false;

enum SERVER_HEADER = "HTTP-D/1.0";

// --------------------------------------------------------------------------------

shared class Request
{
public:

    this( string id = "" )
    {
        connection = id;
    }

    string          connection;
    Method          method;
    string          protocol;
    string          uri;
    string[string]  headers;
    string[string]  attrs;
    ubyte[]         data;

    string getHeader( string k )
    {
        return headers[ capHeader( k.dup ) ];
    }

    string getAttr( string k )
    {
        return attrs[ k.toLower ];
    }

    shared(Response) getResponse()
    {
        Response resp = new Response( connection, protocol ); //bind the response to the reqest connection
        if( "Connection" in headers )
            resp.addHeader( "Connection", getHeader( "Connection" ) );

        return resp;
    }
}

// ------------------------------------------------------------------------- //

shared class Response
{
public:
    
    this( string id = "", string proto  = "" )
    {
        connection = id;
        protocol = proto;
    }

    string          connection;
    string          protocol;
    int             statusCode;
    string          statusMesg;
    string[string]  headers;
    ubyte[]         data;

    Response addHeader( string k, string v )
    {
        headers[ capHeader( k.dup ) ] = v.idup;
        return this;
    }

}

// ------------------------------------------------------------------------- //

interface HttpProcessor
{
    void onInit();
    void onLog( string s );
    void onRequest( Request req );
    void onIdle();
    void onExit();
}

// ------------------------------------------------------------------------- //

ubyte[] readChunk( Socket s )
{
    ubyte[] buf;
    buf.length = CHUNK_SIZE;
    try
    {
        buf.length = s.receive( buf );
    }
    catch( Throwable t )
    {
        debug writefln( "(E) read failed: %s", t.toString() );
        buf.length = 0;
    }

    if( buf.length == 0 ) //eof
        throw new Exception( "client closed connection (0 bytes read)" );
    
//    writefln( "Received %d bytes", buf.length );
    debug dumpHex( cast(char[]) buf, "initial read" );
    return buf;
}

// ------------------------------------------------------------------------- //

Tuple!(Request,int) parseHttp( ubyte[] buf )
{
    Request req = new Request();
    int pos = 0, reqLen = 0;
    
    auto res = findSplit( buf, "\r\n" );
    //first line should be OP URL PROTO
    auto line  = splitter( res[ 0 ], ' ' );

    req.method = toMethod( (cast(char[]) line.front).idup );
    line.popFront;
    req.uri    = (cast(char[]) line.front).idup;
    line.popFront;
    req.protocol = (cast(char[]) line.front).idup;

//    writefln( "Length of remaining buffer is %d", res[ 2 ].length );
    for( res = findSplit( res[ 2 ], "\r\n" ); res[ 0 ].length > 0; )
    {
        auto hdr = findSplit( res[ 0 ], ":" );
//        writefln( "Header split = %s: %s", to!string( hdr[ 0 ] ), to!string( hdr[ 2 ] ) );
        if( hdr.length > 0 )
        {
            string key = capHeader( (cast(char[]) hdr[ 0 ]) ).idup; 
            string val = (cast(char[]) hdr[ 2 ]).idup;

            req.headers[ key ] = val;
            if( key == "Content-Length" )
                reqLen = to!int( val );
        }
        res = findSplit( res[ 2 ], "\r\n" );
    }

    debug dumpHex( cast(char[]) req.data, "HTTP REQUEST" );
    return tuple( req, reqLen );
}

// ------------------------------------------------------------------------- //

ubyte[] convertResponse( Response r )
{
    auto buf = appender!(ubyte[])();
    buf.reserve( 512 );

    buf.put( cast(ubyte[]) "HTTP/1.1 " );

    buf.put( cast(ubyte[]) to!string( r.statusCode ) );
    buf.put( ' ' );
    buf.put( cast(ubyte[]) r.statusMesg );
    buf.put( '\r' );
    buf.put( '\n' );

    r.addHeader( "Server", SERVER_HEADER );
    if( ("Date" in r.headers) is null )
    {
        long now = time( null );
        r.addHeader( "Date", to!string( asctime( gmtime( & now ) ) )[0..$-1] );
    }

    if( ("Connection" in r.headers) !is null )
    {
        if( r.protocol.toLower == "http/1.0" )
            r.addHeader( "Connection", "Keep-Alive" );
    }

    if( ("Content-Length" in r.headers) is null )
        r.addHeader( "Content-Length", to!string( r.data.length ) );

    foreach( k,v; r.headers )
    {
        buf.put( cast(ubyte[]) k );
        buf.put( ':' );
        buf.put( ' ' );
        buf.put( cast(ubyte[]) v );
        buf.put( '\r' );
        buf.put( '\n' );
    }

    buf.put( '\r' );
    buf.put( '\n' );
    if( r.data.length > 0 )
        buf.put( r.data );

    debug dumpHex( cast(char[]) buf.data, "HTTP RESPONSE" );
    return buf.data;
}

// ------------------------------------------------------------------------- //

interface Connection
{
public:

    enum Flags { CONNECTED = 0x0, READING = 0x01, WRITING = 0x02, CLOSING = 0x04 };

    @property string id();
    @property uint flags();
    @property Socket socket();

    void close();
    Request read();
    ulong write();
    void add( Response r );
}

// ------------------------------------------------------------------------- //

class HttpConnection : Connection
{
public:

    this( Socket _c )
    {
        _socket = _c;
        _state  = Flags.CONNECTED;
        _id     = _c.remoteAddress().toString();
    }

    @property string id()           { return _id; }
    @property Socket socket()       { return _socket; }
    @property uint flags()          { return _state; }

    void close()
    {
        debug writefln( "Closing connection 1 %s (%s)", id, to!string( _socket.handle() ) );
        try
        {
            if( _socket.isAlive )
                _socket.shutdown( SocketShutdown.BOTH );

            _socket.close();
        }
        catch( Throwable t ) 
        {
            writefln( "(E) socket close failed on connection %s: %s", _id, t.toString() );
        }

        _state = Flags.CLOSING;
    }

    Request read()
    {
        ubyte [] httpChunk = readChunk( _socket );
        switch( _state )
        {
            case Flags.CONNECTED: //first chunk read from socket - parse headers
                auto r = parseHttp( httpChunk );
                _lastReq = r[ 0 ];
                _lastReq.connection = id;
                _state   = r[ 1 ] == 0 ? _state & ~Flags.READING : _state | Flags.READING;
                _lastReadPos = 0; //reset if needed
                break;

            case Flags.READING:
                _lastReq.data ~= httpChunk;
                _lastReadPos  += httpChunk.length;
                break;

            default:
                break;
        }
        return (_state & Flags.READING) == 0 ? _lastReq : null;
    }

    //write any pending data to the socket, and return number of bytes left to write
    ulong write()
    {
        if( _lastWritePos == _lastResp.length )
        {
            _state &= ~Flags.WRITING;
            return 0UL; //nothing to send
        }

        long num = _socket.send( _lastResp[ _lastWritePos .. $ ] );
        debug writefln( "Wrote %d bytes to connection %s", num, id );
        if( num < 0 )
        {
            _state &= ~Flags.WRITING;
            return 0UL;
        }

        _lastWritePos += num;
        if( _lastWritePos >= _lastResp.length )
        {
            _lastResp.length = _lastWritePos = 0;
            _state &= ~Flags.WRITING;
            return 0UL;
        }
        _state |= Flags.WRITING;
        return _lastResp.length - _lastWritePos;
    }

    void add( Response r )
    {
        if( _state & Flags.CLOSING )
        {
            debug writefln( "Connection %s is marked for closing - not accepting next response", id );
            return; //don't add more info if we're closing...
        }
//        dump( r );
        _lastResp ~= convertResponse( r );
        _state |= Flags.WRITING;
        if( ("Connection" in r.headers) !is null && r.headers[ "Connection" ].toLower == "close" )
            _state |= Flags.CLOSING;
//        _lastWritePos = 0;
    }

private:

    string  _id;
    Socket  _socket;
    uint    _state;
    Request _lastReq;
    ubyte[] _lastResp;
    ulong   _lastWritePos;
    ulong   _lastReadPos;
}

Connection[string] allConns;

// ------------------------------------------------------------------------- //

private void httpServeImpl( string address, ushort port, HttpProcessor proc )
{
//    sigset_t set;
//    sigemptyset( & set );
//    sigaddset( &set, SIGUSR1 );
//
//    pthread_sigmask( SIG_UNBLOCK, & set, null );
//

    proc.onInit();
    running = true;

    SocketSet readSet = new SocketSet();
    SocketSet writeSet = new SocketSet();
    SocketSet exceptSet = new SocketSet();

    InternetAddress bindAddr = new InternetAddress( address, port );

    //TODO: loop accepting all available connections...
    void doAccept( Socket s )
    {
        try
        {
            while( true )
            {
                Socket client = s.accept();
                client.blocking( false );

                client.setOption( SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, 1 );
                linger lin = { 1, 1 };
                client.setOption( SocketOptionLevel.SOCKET, SocketOption.LINGER, lin );

                Connection conn = new HttpConnection( client );// id is allocated in the constructor
                proc.onLog( "accepted new client connection from " ~ conn.id );
                allConns[ conn.id ] = conn;
            }
        }
        catch( SocketException se ) {}
    }

    void doRead( Connection c ) 
    {
        debug writeln( "(D) Reading from " ~ c.id );
         Request req = c.read();
         if( req !is null )
             proc.onRequest( req );
    }

    void doWrite( Connection c ) 
    {
        debug writeln( "(D) Writing from " ~ c.id );
        c.write();
    }

    void doExcept( Connection c ) 
    {
        debug writefln( "Error on connection %s", c.id );
        c.close();
    }

    //set up our listening socket...
    Socket listenSock;
    try
    {
        listenSock = new Socket( AddressFamily.INET, SocketType.STREAM );
        listenSock.bind( bindAddr );
        listenSock.listen( 100 );
        listenSock.blocking( false );
        proc.onLog( "listening on " ~ bindAddr.toString() ~ ", queue length 100" );
    }
    catch( SocketException se )
    {
        debug writefln( se.toString() );
        throw se;
    }

    string[] closedConns;
    while( running )
    {
        readSet.reset();
        readSet.add( listenSock );
        writeSet.reset();

        closedConns.clear();
        foreach( c; allConns )
        {
//            writefln( "Processing select state for connection: %s", c.id );
            //if we've finished writing, and we're marked for closing - go ahead and close
            if( c.flags & Connection.Flags.CLOSING )
            {
                if( (c.flags & Connection.Flags.WRITING) == 0 )
                {
                    debug writefln( "Connection %s is added to closing conns", c.id );
                    closedConns ~= c.id;
                    continue;
                }
            }

            if( (c.flags & Connection.Flags.CLOSING) == 0 ) //don't read any more data on a closing socket
                readSet.add( c.socket );
            if( c.flags & Connection.Flags.WRITING )
                writeSet.add( c.socket );

            //debug writefln( "(D) %s: %08x", c.id, c.flags );
        }

        //close connections found wanting
        //this can't be done as part of the iteration over the connections
        //above or below as it explodes the iterator (sorry, range) if
        //items are removed during iteration.  There is probably a way to do so, though...
        foreach( s; closedConns )
        {
            allConns.remove( s );
            proc.onLog( "removing closed connection " ~ s ~ " (" ~ to!string( allConns.length ) ~ ")" );
        }

        int num = Socket.select( readSet, writeSet, exceptSet, TIMEOUT_USEC );
        if( num > 0 )
        {
            debug writefln( "%d/%d", num, allConns.length );
            if( readSet.isSet( listenSock ) )
                doAccept( listenSock );

            foreach( c; allConns )
            {
                try
                {
                    if( readSet.isSet( c.socket ) )
                        doRead( c );
                    if( writeSet.isSet( c.socket ) )
                        doWrite( c );
                    if( exceptSet.isSet( c.socket ) )
                        doExcept( c );
                }
                catch( Exception e )
                {
                    proc.onLog( e.toString() );
                    c.close();
                }
            }
        }

        try
        {
            proc.onIdle();
        }
        catch( Throwable t )
        {
            writeln( "Exception processing idle: " ~ t.toString );
        }
    }

    proc.onLog( "shutting down " ~ to!string( allConns.length ) ~ " connection(s)" );

    //shutdown remaining sockets...
    foreach( c; allConns )
    {
        try
        {
            c.close();
        }
        catch( Throwable t ) {} //ignored
    }
 
    try
    {
        listenSock.close();
    }
    catch( Throwable t )
    {
        writeln( "Failed to close listen socket: " ~ t.toString() );
    }

    proc.onExit();

}

// ------------------------------------------------------------------------- //

/**
 * Thread entry point for HTTP processing
 */

void httpServe( string address, ushort port, Tid tid )
{
    httpServeImpl( address, port, new TidProcessor( tid, "[HTTP-D] " ) );
}

// ------------------------------------------------------------------------- //

void httpServe( string address, ushort port, Response delegate(Request) dg )
{
    httpServeImpl( address, port, new DelegateProcessor( dg, "[HTTP-D] " ) );
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

    void onRequest( Request req )
    {
        send( tid, req );
    }

    void onIdle()
    {
        receiveTimeout( 0, 
                ( int i )
                {
                    switch( i )
                    {
                        case 1:
                            running = false;
                            break;

                        default:
                            break;
                    }
                },
                ( Response resp ) 
                { 
 //                   writefln( "(D) processing received response" );
                    Connection conn = allConns[ resp.connection ];
                    if( conn is null )
                    {
                        writefln( "Failed to resolve connection %s", resp.connection );
                        return;
                    }
                    conn.add( resp );
//                    dump( resp );
                } );
    }

private:

    Tid tid;
    string prefix;
}

// ------------------------------------------------------------------------- //

class DelegateProcessor : HttpProcessor
{
public:

    this( Response delegate(Request) d, string logPrefix = "[HTTP] " )
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

    void onRequest( Request req )
    {
        Response resp = dg( req );
        if( resp !is null )
        {
            debug writefln( "(D) processing received response" );
            Connection conn = allConns[ resp.connection ];
            if( conn is null )
            {
                writefln( "Failed to resolve connection %s", resp.connection );
                return;
            }
            conn.add( resp );
        }
    }

    void onIdle()
    {
        //noop for sync
    }

private:

    Response delegate(Request) dg;
    string prefix;
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

void dump( Request r )
{
    writeln( "Connection: ", r.connection );
    writeln( "Method    : ", r.method );
    writeln( "Protocol  : ", r.protocol );
    writeln( "URI       : ", r.uri );

    foreach( k, v; r.headers )
        writeln( "\t", k, ": ", v );

    foreach( k, v; r.attrs )
        writeln( "\t", k, ": ", v );
}

// ------------------------------------------------------------------------- //

void dump( Response r, string title = "" )
{
    if( title.length > 0 )
        writeln( title );

    writeln( "Connection: ", r.connection );
    writeln( "Status    : ", r.statusCode, " ", r.statusMesg );

    foreach( k, v; r.headers )
        writeln( "\t", k, ": ", v );

    dumpHex( cast(char[]) r.data );
}

// ------------------------------------------------------------------------- //

string capHeader( char[] hdr )
{
    bool up = true; //uppercase first letter
    foreach( i, char c; hdr ) 
    {
        if( isAlpha( c ) )
        {
            hdr[ i ] = cast(char)(up ? toUpper( c ) : toLower( c ));
            up = false;
        }
        else
            up = true;
    }
    return hdr.idup;
}