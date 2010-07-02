USING: accessors arrays assocs byte-arrays calendar
calendar.format combinators combinators.short-circuit
io.encodings.utf8 kernel linked-assocs math namespaces
quotations uuid ;
IN: http.machine.data

TUPLE: stream-body chunk next ;

: <stream-body> ( chunk next -- stream-body )
    [ stream-body new ] 2dip
    [ >>chunk ] [ >>next ] bi* ; inline

: >stream-body< ( stream-body -- chunk next )
    [ chunk>> ] [ next>> ] bi ; inline

SYMBOL: =undefined=

TUPLE: machine-transaction
    id metadata ;

: <machine-transaction> ( -- tx )
    machine-transaction new
    uuid4 >>id
    H{ } clone >>metadata ;

TUPLE: machine-request 
    method url version headers cookies host port 
    display-path path raw-path path-info path-tokens 
    body ;

: <machine-request> ( -- request )
    machine-request new ;

TUPLE: machine-response
    version code reason headers cookies
    content-type
    content-charset
    content-encoding
    body
    size ;

: <machine-response> ( -- response )
    machine-response new
    "1.1" >>version
    H{ } clone >>headers
    V{ } clone >>cookies
    utf8 >>content-encoding ;

: response-ok? ( response -- ? )
    code>> 400 < ; inline

: ?response-ok ( ..a response quot -- ..b )
    over response-ok?
    [ call ] [ 2drop ] if ; inline

: request ( -- request ) machine-request get ; inline

: response ( -- response ) machine-response get ; inline

: tx ( -- tx )
    machine-transaction get ; inline

: set-tx-metadata ( value key -- )
    tx metadata>> set-at ; inline

: tx-metadata ( key -- value )
    tx metadata>> at ; inline

: set-request-header ( value key -- )
    request headers>> set-at ; inline

: get-request-header ( header -- value )
    request headers>> at ; inline

: set-response-header ( value key -- )
    response headers>> set-at ; inline

: append-response-header ( value key -- )
    response headers>> push-at ; inline

: get-response-header ( header -- value )
    response headers>> at ; inline

: set-header ( request/response value key -- request/response )
    pick headers>> set-at ; inline

: header ( request/response key -- value ) swap headers>> at ;

: do-redirect? ( -- ? )
    f ;

CONSTANT: HTTP-STATUS-TABLE H{ 
        { 100 "Continue" }
        { 200 "OK" }
        { 201 "Created" }
        { 202 "Accepted" }
        { 203 "Non-Authoritative Information" }
        { 204 "No Content" }
        { 205 "Reset Content" }
        { 206 "Partial Content" }
        { 300 "Multiple Choices" }
        { 301 "Moved Permanently" }
        { 302 "Found" }
        { 303 "See Other" }
        { 304 "Not Modified" }
        { 305 "Use Proxy" }
        { 307 "Temporary Redirect" }
        { 400 "Bad Request" }
        { 401 "Unauthorized" }
        { 402 "Payment Required" }
        { 403 "Forbidden" }
        { 404 "Not Found" }
        { 405 "Method Not Allowed" }
        { 406 "Not Acceptable" }
        { 407 "Proxy Authentication Required" }
        { 408 "Request Timeout" }
        { 409 "Conflict" }
        { 410 "Gone" }
        { 411 "Length Required" }
        { 412 "Precondition Failed" }
        { 413 "Request Entity Too Large" }
        { 414 "Request-URI Too Long" }
        { 415 "Unsupported Media Type" }
        { 416 "Requested Range Not Satisfiable" }
        { 417 "Expectation Failed" }
        { 500 "Internal Server Error" }
        { 501 "Not Implemented" }
        { 502 "Bad Gateway" }
        { 503 "Service Unavailable" }
        { 504 "Gateway Timeout" }
        { 505 "HTTP Version Not Supported" }
    }

: lookup-status-code ( code -- reason )
    HTTP-STATUS-TABLE at ; inline