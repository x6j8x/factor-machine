USING: accessors destructors http.machine.data http.machine.states io.encodings.utf8
http.machine.flow io.servers.connection kernel urls namespaces http.parsers io.crlf sequences ;
FROM: http => read-header parse-cookie ;

IN: http.machine

TUPLE: machine-server < threaded-server ;

SYMBOL: machine-dispatcher



<PRIVATE

: handle-request ( request resource -- response )
    [  
        [ machine-request set ] dip
        <machine-response> machine-response set
        v3b13 decide 
        response 
    ] with-scope ;

: handle-response ( request resource -- ) 2drop ;

: (read-header) ( -- alist )
    [ read-crlf dup f like ] [ parse-header-line ] produce nip  ;

: check-absolute ( url -- url )
    dup path>> "/" head? [ "Bad request: URL" throw ] unless ; inline

: read-request-line ( request -- request )
    read-crlf parse-request-line first3
    [ >>method ] [ >url check-absolute >>url ] [ >>version ] tri* ;

: extract-host ( request -- request )
    [ dup ] [ "host" header parse-host ] bi
    [ >>host ] [ >>port ] bi* drop ;

: extract-cookies ( request -- request )
    dup "cookie" header [ parse-cookie >>cookies ] when* ;

PRIVATE>

: read-http-request ( -- request )
    <machine-request>
    read-request-line
    read-header >>headers
    extract-host
    extract-cookies ;

: dispatch-request ( request -- ) drop ;

M: machine-server handle-client*
    [
        read-http-request
        [ dispatch-request ]
        [ handle-response ] bi
    ] with-destructors ;

: <machine> ( -- server )
    utf8 machine-server new-threaded-server
        "factor machine" >>name
        "http" protocol-port >>insecure
        "https" protocol-port >>secure ;