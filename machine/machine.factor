USING: accessors arrays assocs byte-arrays calendar
calendar.format combinators.short-circuit continuations
http.parsers io io.crlf io.encodings io.encodings.utf8
io.servers.connection kernel math namespaces parser present
sequences strings urls vectors vocabs.refresh words.symbol
xml.data xml.writer destructors fry html.streams
http.machine.data
http.machine.dispatch
http.machine.flow
http.machine.mime
http.machine.resource
http.machine.request
http.machine.response 
http.machine.states
http.machine.stream ;
FROM: http => read-header parse-cookie unparse-set-cookie write-header ;
FROM: debugger => print-error :c ;
FROM: html => simple-page ;
IN: http.machine

SYMBOL: machine-development?

TUPLE: machine-server < threaded-server dispatcher ;

<PRIVATE

: make-http-error ( error -- xml )
    [ "Internal server error" f ] dip
    [ print-error nl :c ] with-html-writer simple-page ;

: error-response ( response error -- response )
    make-http-error >>body
    "text/html" >>content-type
    utf8 >>content-encoding ; inline

: <500> ( error -- response )
    <machine-response> 500 >>code 
    f "server-keep-alive" set-tx-metadata
    swap machine-development? get
    [ error-response ] [ drop ] if ;

: <404> ( -- response )
    <machine-response> 404 >>code
    f "server-keep-alive" set-tx-metadata ;

: process-request ( request resource -- )
    [
        [ handle-request write-response ]
        [ <500> nip write-response ] recover
    ] with-destructors ;

: ?refresh-all ( -- )
    machine-development? get-global
    [ global [ refresh-all ] bind ] when ;

: with-tx ( ..a quot -- ..b )
    [ <machine-transaction> machine-transaction ] dip
    with-variable ; inline

PRIVATE>

M: machine-server handle-client*
    [ 
        ?refresh-all read-request over
        dispatcher>> lookup-resource
        [ process-request ] 
        [ <404> write-response ] if*
        "server-keep-alive" tx-metadata
    ] with-tx
    [ handle-client* ] [ drop ] if ;

: <machine> ( dispatcher -- server )
    [ utf8 machine-server new-threaded-server ] dip >>dispatcher
        "factor machine" >>name
        "http" protocol-port >>insecure
        "https" protocol-port >>secure ;
