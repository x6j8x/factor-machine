USING: accessors ascii byte-arrays combinators
combinators.short-circuit continuations fry http.machine.data
io io.encodings.binary io.files kernel layouts locals make math math.order math.parser
peg peg.parsers prettyprint sequences sorting strings uuid ;
FROM: sequences.deep => flatten ;
IN: http.machine.util.byte-ranges

TUPLE: byte-range start end ;

: >byte-range< ( byte-range -- start end )
    [ start>> ] [ end>> ] bi ; inline

: <byte-range> ( start end -- byte-range )
    byte-range boa ;

<PRIVATE 

!      ranges-specifier = byte-ranges-specifier
!      byte-ranges-specifier = bytes-unit "=" byte-range-set
!      byte-range-set  = 1#( byte-range-spec | suffix-byte-range-spec )
!      byte-range-spec = first-byte-pos "-" [last-byte-pos]
!      first-byte-pos  = 1*DIGIT
!      last-byte-pos   = 1*DIGIT
!      suffix-byte-range-spec = "-" suffix-length
!      suffix-length = 1*DIGIT

: 'space' ( -- parser )
    [ " \t" member? ] satisfy repeat0 hide ;

: 'byte-ranges-specifier' ( -- parser )
    "bytes" token hide ;

: 'byte-pos' ( -- parser )
    [ digit? ] satisfy repeat1 [ string>number ] action ;

: 'comma' ( -- parser )
    "," token hide ;

: 'equals' ( -- parser )
    "=" token hide ;

: 'separator' ( -- parse )
    'equals' 'comma' 2choice ;

: 'suffix-byte-range-spec' ( -- parser )
    [
        'separator' ,
        "-" token hide ,
        'byte-pos' ,
        'space' ,
    ] seq* [ first neg f <byte-range> ] action ;

: 'byte-range-spec' ( -- parser )
    [
        'separator' ,
        'space' ,
        'byte-pos' ,
        'space' ,
        "-" token hide ,
        'byte-pos' optional ,
        'space' ,
    ] seq* [ first2 <byte-range> ] action ;

PEG: parse-range-spec ( str -- ranges )
    [
        'space' ,
        'byte-ranges-specifier' ,
        'byte-range-spec' 'suffix-byte-range-spec' 2choice repeat1 ,
    ] seq* [ flatten ] action ;

SINGLETONS: +overlap+ +included+ ;

GENERIC: combine ( range range type -- range range/f )

M: +overlap+ combine 
    drop [ start>> ] [ end>> ] bi* <byte-range> f ;

M: +included+ combine
    2drop f ;

M: f combine
    drop ;

: overlap? ( range range -- type/f )
    [ end>> ] [ start>> ] bi* >=
    [ +overlap+ ] [ f ] if ;

: included? ( range range -- type/f )
    {
        [ [ start>> ] [ start>> ] bi* <= ]
        [ [ end>> ] [ end>> ] bi* >= ]
    } 2&& [ +included+ ] [ f ] if ;

: ?combine ( byte-range byte-range -- byte-range byte-range/f )
    2dup { [ included? ] [ overlap? ] } 2|| combine ;

: convert-suffix ( range size -- range )
    [ over start>> + >>start ] [ >>end ] bi ; inline

: convert-prefix ( range size -- range )
    2dup [ start>> ] [ ] bi* <= 
    [ >>end ] [ drop most-positive-fixnum >>end ] if ; inline

: ?convert ( range size -- range )
    {
        { [ over { [ end>> not ] [ start>> 0 < ] } 1&& ] [ convert-suffix ] }
        { [ over { [ end>> not ] [ start>> 0 > ] } 1&& ] [ convert-prefix ] }
        [ drop ]
    } cond ; inline

: sort-ranges ( size seq -- seq' )
    swap 
    '[ _ ?convert ] map
    [ [ start>> ] bi@ <=> ] sort ;

: retain ( seq elt -- seq )
    over push ;

: consolidate ( seq -- seq' )
    unclip-slice V{  } clone [ push ] keep
    [
        [ [  ] [ pop ] bi ] dip
        ?combine [ [ retain ] bi@ ] [ retain ] if*
    ] reduce ;

PRIVATE>

: byte-ranges ( size str -- seq )
    [ parse-range-spec sort-ranges consolidate ]
    [ 3drop f ] recover ;

: range-request? ( size -- ranges/f )
    "range" request-header [ byte-ranges ] [ drop f ] if* ;

GENERIC: ranges-satified? ( ranges resource -- ranges/f )

GENERIC: copy-range ( byte-range object -- )

GENERIC: content-size ( object -- size )

<PRIVATE

: make-range ( byte-range object -- string )
    [ >byte-range< [ number>string ] bi@ "-" glue ] dip
    content-size number>string "/" glue
    [ "bytes" ] dip " " glue ;

: write-boundary ( -- )
    "--" "boundary" tx-metadata append >byte-array write CRLF write ;

: write-end-boundary ( -- )
    "--" "boundary" tx-metadata "--" 3append >byte-array write CRLF write ;

: write-part-headers ( object byte-range -- )
    "Content-Type: " "original-ct" tx-metadata append >byte-array write
    CRLF write
    [ "Content-Range: " ] 2dip make-range append >byte-array write
    CRLF dup [ write ] bi@ ; 

: write-range-part ( object byte-range -- )
    write-boundary
    [ write-part-headers ] [ swap copy-range ] 2bi
    CRLF write ;

: copy-ranges ( ranges object -- )
    over length 1 = [ [ first ] dip copy-range ] [
        swap '[ _ swap write-range-part ] each
        write-end-boundary
    ] if ;

: remember-ct ( -- )
    response content-type>> "original-ct" set-tx-metadata ; inline

: boundary ( -- string )
    uuid4 [ "boundary" set-tx-metadata ] keep ;

: make-multipart ( string -- )
    [ response ] dip
    [ "multipart/byteranges; boundary" ] dip "=" glue
    >>content-type drop ;

: ?multipart ( ranges resource -- )
    over length 1 > [
        2drop remember-ct boundary make-multipart
    ] [
        [ first ] dip make-range "Content-Range" set-response-header
    ] if ; inline

PRIVATE>

: [range-request-handler] ( ranges resource -- quot/f )
    2dup ranges-satified?
    [
        t "range-request" set-tx-metadata
        [ ?multipart ]
        [ '[ [ _ _ copy-ranges ] ] ] 2bi
    ] [ 2drop response 416 >>code drop f ] if ; inline
