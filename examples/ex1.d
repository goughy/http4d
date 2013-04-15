
/**
 * This example is the simplest of all and just processes any request
 * by returning the same response.
 *
 * This is utilising the synchronous interface with no dispatcher.
 */
import std.stdio, std.conv;
import protocol.http;

int main( string[] args )
{
    httpServe( "127.0.0.1:8888",
                (req) => process( req ) );
    return 0;
}

int num = 0;
HttpResponse process( HttpRequest req )
{ 
	return req.getResponse().status( 200 ).header( "Content-Type", "text/html" ).
				header( "Server", "http4d" ).
				content( "<html><head></head><body>Processed " ~ to!string(num++) ~ "</body></html>" ); 
}