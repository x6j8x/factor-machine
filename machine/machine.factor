USING: accessors destructors http.machine.data
http.machine.flow io.servers.connection kernel ;
FROM: http => read-header ;
FROM: http.server => read-request-line extract-host extract-cookies ;

IN: http.machine

TUPLE: machine-server < threaded-server ;

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