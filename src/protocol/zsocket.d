
module protocol.zsocket;

import std.stdio, std.conv, std.string, core.thread;
public import deimos.zmq.zmq;

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

