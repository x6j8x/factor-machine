USING: accessors arrays assocs byte-arrays calendar
calendar.format combinators combinators.short-circuit fry
http.machine.data http.machine.mime http.machine.stream io
io.crlf io.encodings kernel math namespaces present quotations
sequences sets sorting strings urls vectors xml.data xml.writer ;
FROM: http => parse-cookie unparse-set-cookie ;
IN: http.machine.response

<PRIVATE

: >http-status< ( response -- code reason )
    [ reason>> ] [ code>> ] bi ; inline

: write-status-code ( code reason -- )
    nip present write bl ; inline

: write-status-reason ( code reason -- )
    over [ drop ] [ nip lookup-status-code ] if
    write crlf ; inline

: write-http-version ( response -- )
    "HTTP/" write version>> write bl ; inline

PRIVATE>

: write-response-line ( response -- response )
    dup [ write-http-version ] [
        >http-status<
        [ write-status-code ] [ write-status-reason ] 2bi
    ] bi ;

<PRIVATE

: ensure-cookie-domain ( cookie -- cookie )
    [ url get host>> dup "localhost" = [ drop ] [ or ] if ]
    change-domain ;

: ?server-keep-alive ( response -- response )
    dup {
        [ drop client-keep-alive tx-metadata ]
        [ drop connection-request-count tx-metadata 1000 < ]
        [ response-ok? ]
    } 1&& server-keep-alive set-tx-metadata ;

GENERIC: body-length ( body -- length )

M: string body-length [ length>> ] [ aux>> length ] bi + ;

M: byte-array body-length length ;

M: object body-length drop response size>> ;

: set-transfer-mode ( response -- response )
    dup body>> [
        body-length
        [ "Content-Length" set-header ]
        [ "chunked" "Transfer-Encoding" set-header ] if*
        dup build-content-type "Content-Type" set-header    
    ] [ "0" "Content-Length" set-header ] if* ; inline

: set-date ( response -- response )
    now timestamp>rfc822 "Date" set-header ; inline

: set-connection ( response -- response )
    server-keep-alive tx-metadata [ "close" "Connection" set-header ] unless ; inline

: ensure-response-headers ( response -- response )
    set-date
    set-transfer-mode
    set-connection ; inline

: build-cookie-header ( seq cookie -- seq )
    ensure-cookie-domain unparse-set-cookie
    "Set-Cookie" swap 2array over push ; inline

: check-header-string ( str -- str )
    dup "\r\n" intersects?
    [ "Header injection attack" throw ] when ;

: header-value>string ( value -- string )
    {
        { [ dup timestamp? ] [ timestamp>http-string ] }
        {
            [ dup { [ array? ] [ vector? ] } 1|| ]
            [ [ header-value>string ] map "; " join ]
        }
        [ present ]
    } cond ;

: write-header ( assoc -- )
    >alist [
        [ check-header-string write ": " write ]
        [ header-value>string check-header-string write crlf ] bi*
    ] assoc-each crlf ;

: write-response-header ( response -- response )
    ensure-response-headers    
    dup headers>> >alist >vector
    over cookies>> [ build-cookie-header ] each
    write-header ; inline

GENERIC: write-response-body ( response -- )

M: f write-response-body drop ;

M: stream-body write-response-body
    >stream-body<
    [ [ write ] when* ]
    [ [ call( -- stream-body/f ) write-response-body ] when* ] bi* ;

M: string write-response-body write ;

M: xml write-response-body write-xml ;

M: callable write-response-body call( -- ) ;

: write-body ( response -- )
    [  ] [ body>> ] bi
    [
        swap headers>> "Content-Length" swap at
        [ write-response-body ]
        [ '[ _ write-response-body ] with-chunked-output ] if
    ] [ drop ] if* flush ; inline

PRIVATE>

: write-response ( request response -- )
    ?server-keep-alive
    write-response-line
    write-response-header
    swap method>> "HEAD" = [ drop ] [
        [ content-encoding>> encode-output ]
        [ write-body ] bi
    ] if ;
