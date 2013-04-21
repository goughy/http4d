
module protocol.httpauth;

import std.stdio, std.array, std.algorithm, std.string, 
		std.conv, std.base64, std.digest.md, std.ascii, std.string : splitter;
public import protocol.httpapi;

// ------------------------------------------------------------------------- //
// ------------------------------------------------------------------------- //

class Authorization
{
	enum Type { None, Basic, Digest, ApiKey };

	struct Principal
	{
		string id;
		string username;
		string fullName;
	}

	this( string authorizationHeader, string httpMethod = "GET" )
	{
		type = Type.None;
		params[ "auth_method" ] = httpMethod;
		
		auto pos = countUntil( authorizationHeader, " " );
		if( pos != -1 )
		{
			type = toType( authorizationHeader[ 0..pos ] );
			key  = authorizationHeader[ pos + 1 .. $ ];
		
			parseAuth();
		}
	}
	
	this( Type t, string k )
	{
		type = t;
		key  = k;
		
		parseAuth();
	}
	
	bool verify( string password )
	{
		switch( type )
		{
			case Type.Basic:
				return verifyBasicPassword( this, password );
			case Type.Digest:
				return verifyDigestPassword( this, password );
			default:
				break;
		}
		return false;
	}
	
	Type   			type;
	string 			key;
	string[string] 	params;
	bool 			success;
	Principal 		principal;

	override string toString()
	{
		auto buf = appender!string();
		buf.put( "Authorization{type=" );
		buf.put( to!string( type ) );
		buf.put( ",key=" );
		buf.put( key );
		buf.put( ", Params {" );
		foreach( k,v; params )
		{
			buf.put( k );
			buf.put( "=" );
			buf.put( v );
			buf.put( "," );
		}
		buf.put( "}}" );
		
		return buf.data;
	}

private: 

	void parseAuth()
	{
		switch( type )
		{
			case Type.Basic:  parseBasicAuth( key );  break;
			case Type.Digest: parseDigestAuth( key );	break;
			default: break;
		}
	}
	
	void parseBasicAuth( string data )
	{
		auto d = cast(char[]) Base64.decode( data );
		if( d.length > 0 )
		{
			auto res = std.string.split( d, ":" );
			params[ "username" ] = res[ 0 ].idup;
			params[ "password" ] = res[ 1 ].idup;
		}
	}

	void parseDigestAuth( string data )
	{
		foreach( tok; splitter( data, "," ) )
		{
			auto pos = countUntil( tok, "=" );
			if( pos != -1 )
			{
				string s1 = tok[ 0 .. pos ].strip.toLower;
				string s2 = tok[ pos+1 .. $ ].strip;
				if( s2[ 0 ] == '\"' )
					s2 = s2[ 1 .. $ ];
				if( s2[ $ - 1 ] == '\"' )
					s2 = s2[ 0 .. $ - 1 ];
				
				params[ s1 ] = s2.strip;
			}
		}
	}
	
	Type toType( string t )
	{
		if( t.toLower.strip == "basic" )
			return Type.Basic;
		if( t.toLower.strip == "digest" )
			return Type.Digest;
		
		return Type.None;
	}

    bool has( string k )
    {
        return !!(k in params);
    }
}

// ------------------------------------------------------------------------- //

string genDigestPassword( string username, string password, string realm )
{
	return toHexString( md5Of( username ~ ":" ~ realm ~ ":" ~ password ) ).idup.toLower;
}

// ------------------------------------------------------------------------- //

private bool verifyBasicPassword( Authorization auth, string password )
{
	auth.success = ("password" in auth.params && password == auth.params[ "password" ]);
	return auth.success;
}

// ------------------------------------------------------------------------- //

private bool verifyDigestPassword( Authorization auth, string password )
{
    if( auth is null || !auth.has( "auth_method") || !auth.has( "uri" ) ||
            !auth.has( "nonce" ) || !auth.has( "nc" ) || !auth.has( "cnonce" ) ||
            !auth.has( "qop" ) || !auth.has( "response" ) )
        return false;

	string ha2 = auth.params[ "auth_method" ] ~ ":" ~ auth.params[ "uri" ];
	ha2 = md5Of( ha2 ).toHexString.idup.toLower;
	auth.params[ "_pwd_ha2" ] = ha2;

	auto response = appender!string();
	response.put( password );
	response.put( ":" );
	response.put( auth.params[ "nonce" ] );
	response.put( ":" );
	response.put( auth.params[ "nc" ] );
	response.put( ":" );
	response.put( auth.params[ "cnonce" ] );
	response.put( ":" );
	response.put( auth.params[ "qop" ] );
	response.put( ":" );
	response.put( ha2 );

	string resp = md5Of( response.data ).toHexString.idup.toLower;
	auth.params[ "_pwd_response" ] = resp;
	
	auth.success = (resp == auth.params[ "response" ]);

	return auth.success;
}

// ------------------------------------------------------------------------- //
// ------------------------------------------------------------------------- //

private string digestResp( string pwdHash, string nonce, string nc, string cnonce, string qop, string method, string uri )
{
	MD5 md5;
	md5.start();
	md5.put( representation( method ) );
	md5.put( [':'] );
	md5.put( representation( uri ) );
	auto ha2 = toHexString( md5.finish() ).idup.toLower;
	
	auto response = appender!string();
	response.put( pwdHash.toLower );
	response.put( ":" );
	response.put( representation( nonce ) );
	response.put( ":" );
	response.put( representation( nc ) );
	response.put( ":" );
	response.put( representation( cnonce ) );
	response.put( ":" );
	response.put( representation( qop ) );
	response.put( ":" );
	response.put( ha2 );
	
	md5.start();
	md5.put( representation( response.data ) );
	auto respStr = toHexString( md5.finish() ).idup.toLower;
	
	debug writefln( "HA1: %s", pwdHash );
	debug writefln( "HA2: %s", ha2 );
	debug writefln( "Response: %s", respStr );
	
	return respStr;
}

// ------------------------------------------------------------------------- //

ubyte[] fromHexString( string s )
{
	ubyte[] u;
	assert( s.length %2 == 0 );
	
	for( auto i = 0; i < s.length; i += 2 )
	{
		u ~= cast(ubyte) (std.string.indexOf( hexDigits, s[ i ].toUpper ) * 16 + 
							std.string.indexOf( hexDigits, s[ i + 1 ].toUpper ) );
	}
	return u;
}

unittest 
{
	writefln( "Checking fromHexString()..." );
	writefln( to!string( fromHexString( "000102" ) ) );
	assert( fromHexString( "000102" ) == [ 0x00, 0x01, 0x02 ] );
	writefln( to!string( fromHexString( "7fab3c08" ) ) );
	assert( fromHexString( "7fab3c08" ) == [ 0x7f, 0xab, 0x3c, 0x08 ] );
	
	assert( digestResp( "939e7578ed9e3c518a452acee763bce9", "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		"00000001", "0a4f113b", "auth", "GET", "/dir/index.html" ) == "6629fae49393a05397450978507c4ef1" );
	
}

// ------------------------------------------------------------------------- //

unittest
{
	Authorization auth = new Authorization( "" );
	assert( auth.type == Authorization.Type.None );

	auth = new Authorization( "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" );
	assert( auth.type == Authorization.Type.Basic );
	assert( verifyBasicPassword( auth, "open sesame" ) );
	
	auth = new Authorization( "Digest username=\"Mufasa\","
                     "realm=\"testrealm@host.com\","
                     "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\","
                     "uri=\"/dir/index.html\","
                     "qop=auth,"
                     "nc=00000001,"
                     "cnonce=\"0a4f113b\","
                     "response=\"6629fae49393a05397450978507c4ef1\","
                     "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"" );
					 
//	assert( verifyDigestPassword( auth, "Circle Of Life" ) );
}
