
module luasp.http4d;

import std.stdio, std.array, std.conv, std.datetime;
import protocol.http;
import luasp.process;

enum COOKIE_NAME = "LSPSESSID";

// ------------------------------------------------------------------------- //

//void onPanic( LuaState L, in char[] msg )
//{
//    writefln( "PANIC: %s", msg );
//
//    LuaFunction trace = L.get!LuaFunction( "debug", "traceback" );
//
//    if( !trace.isNil )
//    {
//        LuaObject[] res = trace();
//        foreach( LuaObject o; res )
//        writefln( "STACK: %s", o.to!string() );
//    }
//}

// ------------------------------------------------------------------------- //

class GlueCallback : LspCallback
{
    void writer( in string content )
    {
        response.data ~= content;
    }

    void log( in string msg )
    {
        writefln( "LOG: %s", msg );
    }

    void error( in string msg )
    {
        response.statusCode = 500;
        response.headers[ "Content-Type" ] = "text/plain";
        response.data = cast( shared ubyte[] ) msg.dup;
    }

    string getHeader( in string name )
    {
        return request.headers[ name ];
    }

    void setHeader( in string name, in string value )
    {
        response.headers[ name ] = value;
    }

    void setRequest( HttpRequest req )
    {
        request = req;
        response = req.getResponse();
        response.statusCode = 200;
    }

    auto getResponse()
    {
        return response;
    }

private:

    HttpRequest  request;
    HttpResponse response;
}

// ------------------------------------------------------------------------- //

void luaspServe( string dir, string addr = "0.0.0.0", ushort port = 8080 )
{
    LuaState L = new LuaState;
    //L.setPanicHandler( &onPanic );
    L.openLibs();

    auto lsp = new LspState( L, new GlueCallback );
    lsp.cache = false;

    httpServe( addr, port, ( req ) => handleRequest( lsp, dir, req ) );
}

// ------------------------------------------------------------------------- //

private HttpResponse handleRequest( LspState lsp, string dir, HttpRequest req )
{
    GlueCallback callback = cast( GlueCallback ) lsp.callback;
    callback.setRequest( req );

    lsp.env[ "filename" ] = req.uri;

    if( "Query-String" in req.attrs )
        lsp.env[ "args" ] = req.attrs[ "Query-String" ];
    else
        lsp.env[ "args" ] = "";

    string sessionId = "";

    if( "Cookie" in req.headers )
        sessionId = findCookie( req.headers[ "Cookie" ], COOKIE_NAME );

    if( sessionId.length == 0 )
    {
        sessionId = lsp.lsp_uuid_gen();
        auto expires = Clock.currTime();
        expires.roll!"days"( 1 );
        callback.setHeader( "Set-Cookie", std.string.format( "%s=%s; expires=%s", COOKIE_NAME, sessionId, formatExpires( expires ) ) );
    }

    lsp.env[ "session" ]            = sessionId;
    lsp.env[ "hostname" ]           = req.headers[ "Host" ];
    lsp.env[ "remote_ip" ]          = req.attrs[ "Remote-Host" ];
    lsp.env[ "server_admin" ]       = req.attrs[ "Server-Admin" ];
    lsp.env[ "server_hostname" ]    = req.attrs[ "Server-Host" ];
    lsp.env[ "method" ]             = to!string( req.method );
    lsp.env[ "uri" ]                = req.uri;

//    callback.log( "locating URI " ~ req.uri );
    string file = locateLsp( dir, req.uri );

    if( file.length == 0 ) //not found
        return req.getResponse().status( 404 );

    callback.log( "executing LSP " ~ file );
    lsp.doLsp( file );

    return callback.getResponse();
}

// ------------------------------------------------------------------------- //

string locateLsp( string dir, string path )
{
    string f = dir ~( path[ 0 ] == '/' ? "" : "/" ) ~ path;

    if( std.file.exists( f ) && std.file.isFile( f ) ) return f;

    f = f ~ ".lsp";

    if( std.file.exists( f ) && std.file.isFile( f ) ) return f;

    f = f ~ ".lua";

    if( std.file.exists( f ) && std.file.isFile( f ) ) return f;

    return "";
}

// ------------------------------------------------------------------------- //

string findCookie( string cookie, string name )
{
    if( cookie is null || cookie.length == 0 )
        return "";

    auto r = std.algorithm.splitter( cookie, ';' );

    while( !r.empty )
    {
        auto r1 = std.algorithm.splitter( r.front, '=' );

        if( !r1.empty && std.string.strip( r1.front ) == name )
        {
            r1.popFront;
            return r1.front;
        }

        r.popFront;
    }

    return "";
}

// ------------------------------------------------------------------------- //

string formatExpires( SysTime t )
{
    immutable string[] days   = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    immutable string[] months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    return std.string.format( "%s, %d %s %.4d %.2d:%.2d:%.2d GMT",
                              days[ t.dayOfWeek ], t.day, months[ t.month - 1 ], t.year,
                              t.hour, t.minute, t.second );
}

// ------------------------------------------------------------------------- //
