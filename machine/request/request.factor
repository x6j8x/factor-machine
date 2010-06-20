USING: accessors combinators.short-circuit io.crlf kernel namespaces
sequences urls
http.machine.data
http.machine.flow
http.machine.states
http.parsers ;
FROM: http => read-header parse-cookie ;
IN: http.machine.request

<PRIVATE

: (read-header) ( -- alist )
    [ read-crlf dup f like ] [ parse-header-line ] produce nip  ;

: check-absolute ( url -- url )
    dup path>> "/" head? [ "Bad request: URL" throw ] unless ; inline

: read-request-line ( request -- request )
    read-crlf parse-request-line first3
    [ >>method ] [ >url check-absolute >>url ] [ >>version ] tri* ; inline

: extract-host ( request -- request )
    [ dup ] [ "host" header parse-host ] bi
    [ >>host ] [ >>port ] bi* drop ; inline

: extract-cookies ( request -- request )
    dup "cookie" header [ parse-cookie >>cookies ] when* ; inline

: ?client-keep-alive ( request -- request )
    dup {
        [ version>> "1.1" = ]
        [ "connection" header "close" = not ]
    } 1&& "client-keep-alive" set-tx-metadata ; inline

PRIVATE>

: read-request ( -- request )
    <machine-request>
    read-request-line
    read-header >>headers
    extract-host
    extract-cookies
    ?client-keep-alive ; inline

: handle-request ( request resource -- request response )
    [
        machine-request set
        <machine-response> machine-response set
    ] dip v3b13 decide request response ; inline

