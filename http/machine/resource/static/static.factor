USING: accessors arrays assocs byte-arrays checksums
checksums.sha combinators.short-circuit formatting fry
http.machine.data http.machine.resource http.machine.util.byte-ranges io
io.encodings.binary io.files io.files.info
io.files.types io.pathnames io.streams.limited kernel literals
locals math math.parser mime.types namespaces sequences strings
uuid ;
FROM: ascii => >lower ;
IN: http.machine.resource.static

TUPLE: static-file-resource path entry index-page ;

TUPLE: entry path info directory? ;

: <static-file-resource> ( path -- static-file-resource )
    [ static-file-resource new ] dip >>path "index.html" >>index-page ; inline

<PRIVATE

: [partial-copy] ( start length -- quot )
    '[
        _ seek-absolute input-stream get
        [ stream-seek ] keep _ limit-stream
        [ write ] each-stream-block
        flush
    ] ; inline

M: static-file-resource copy-range ( byte-range resource -- )
    swap [ entry>> path>> binary ] dip
    >byte-range< over -
    [partial-copy] with-file-reader ;

: copy-file ( resource -- )
    entry>> path>> binary 
    [ [ write ] each-block ] with-file-reader ; inline

M: static-file-resource ranges-satified? ( ranges resource -- ranges/f )
    entry>> info>> size>> '[ _ swap end>> >= ] dupd all? [  ] [ drop f ] if ;

M: static-file-resource content-size ( resource -- size )
    entry>> info>> size>> ;

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

: [content-writer] ( resource -- quot/f )
    dup entry>> info>> size>> range-request?
    [ swap [range-request-handler] ]
    [ '[ [ _ copy-file ] ] ] if* ; inline

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
    dup entry>> directory?>> [ [ request url>> path>> ] dip index-page>> append-path  ] [ drop f ] if ;

M: static-file-resource finish-request
    "bytes" "Accept-Ranges" set-response-header
    "range-request" tx-metadata [
        drop response 206 >>code drop
    ] [ entry>> [ [ response ] dip info>> size>> >>size drop ] when* ] if ;