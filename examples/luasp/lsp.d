
import std.stdio, std.datetime, std.regex;
import protocol.http, protocol.mongrel2, luasp.http4d;


import std.typetuple, std.traits;

int main( string [] args )
{
    if( args.length < 2 )
    {
        writefln( "Usage: %s [directory of LSP files]", args[ 0 ] );
        return 1;
    }
    
//    MethodRouter mr = new MethodRouter;
//    mr.get( & onApi );
//    mr.post( & onApi );
//
//    mr.dumpRoutes();

    LspRouter lspRouter = new LspRouter( args[ 1 ], true );
    lspRouter.dumpRoutes();

    UriRouter uriRouter = new UriRouter();
//    uriRouter.mount( "/api/*", & onApi );
    uriRouter.mount( "/luasp/*", lspRouter );
    uriRouter.dumpRoutes();

    httpServe( "127.0.0.1:8082", (req) => uriRouter( req ) );
//    mongrel2Serve( "127.0.0.1", 8081, (req) => dispatcher( req ) );
//    luaspServe( args[ 1 ], "0.0.0.0", 8081 );
    return 0;
}

HttpResponse onApi( HttpRequest req )
{
    return req.getResponse().status( 403 ); // ie not authorised
}
