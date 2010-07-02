USING: accessors arrays assocs checksums checksums.sha
combinators.short-circuit formatting fry http.machine.data
http.machine.resource http.machine.util io io.encodings.binary
io.files io.files.info io.files.types io.pathnames kernel
literals locals math mime.types namespaces sequences ;
FROM: ascii => >lower ;
IN: http.machine.resource.static

TUPLE: static-file-resource path entry index-page ;

TUPLE: entry path info directory? ;

: <static-file-resource> ( path -- static-file-resource )
    [ static-file-resource new ] dip >>path "index.html" >>index-page ; inline

<PRIVATE

: copy-range ( resource range -- )
    dup length 1 = [
        2drop
    ] [
        2drop
    ] if ;

: copy-file ( resource -- )
    entry>> path>> binary 
    [ [ write ] each-block ] with-file-reader ; inline

: range? ( -- ranges/f )
    "range" get-request-header [ byte-ranges ] [ f ] if* ;

PREDICATE: from-to-range < byte-range { [ >byte-range< and ] [ >byte-range< [ 0 >= ] bi@ and ] } 1&& ;
PREDICATE: suffix-range < byte-range { [ start>> ] [ start>> 0 < ] } 1&& ;

GENERIC: check-range ( size range -- t/f )

M: from-to-range check-range
    second <= ;

M: suffix-range check-range
    first neg <= ;

M: object check-range
    2drop f ;

: ranges-satified? ( ranges resource -- ranges/f )
    B entry>> info>> size>> '[ _ swap check-range ] dupd all? [  ] [ drop f ] if ;

: write-file ( resource -- )
    range? [ copy-range ] [ copy-file ] if* ;

: set-file-info ( entry path -- entry )
    dup exists? [
        file-info [ >>info ]
        [ type>> +directory+ = >>directory? ] bi
    ] [ drop ] if ;

: make-entry ( resource request -- entry )
    [ entry new ] 2dip
    [ path>> ] [ display-path>> ] bi* append-path
    [ >>path ] [ set-file-info ] bi ; inline

: content-type ( path -- ct )
    file-extension >lower mime-types at "application/octet-stream" or ;

:: handle-range-request ( ranges resource -- quot/f )
    ranges resource ranges-satified?
    [ [ [ resource ranges copy-range ] ] ]
    [ response 416 >>code drop f ] if ; inline

:: [content-writer] ( resource -- quot )
    range? :> ranges
    ranges [ ranges resource handle-range-request ]
    [ [ [ resource copy-file ] ] ] if ; inline

PRIVATE>

M: static-file-resource init-resource ( resource -- resource )
    clone [ ] [ request make-entry ] bi >>entry
    response binary >>content-encoding drop ;

M: static-file-resource resource-exists?
    entry>> path>> { [ exists? ] [ file-info type>> +directory+ = not ] } 1&& ;

M: static-file-resource previously-existed?
    entry>> path>> { [ exists? ] [ file-info type>> +directory+ = ] } 1&& ;

M: static-file-resource allowed-methods drop { "HEAD" "GET" } ;

M:: static-file-resource content-types-provided ( resource -- alist )
    V{ } clone resource entry>> :> entry
    entry path>> content-type
    resource [content-writer]
    2array over push ;

M: static-file-resource last-modified entry>> info>> modified>> ;

M: static-file-resource generate-etag
    entry>> info>> [ modified>> ] [ size>> ] bi
    "%s-%s" sprintf sha1 checksum-bytes hex-string ;

M: static-file-resource moved-permanently?
    entry>> directory?>> [ "http://127.0.0.1:8080/files/index.html" ] [ f ] if ;

M: static-file-resource finish-request
    "bytes" "Accept-Ranges" set-response-header
    "range-request" tx-metadata [
        response 206 >>code drop
    ] when drop ;