USING: accessors ascii continuations kernel make math
math.parser peg peg.parsers quoting sequences strings ;
FROM: sequences.deep => flatten ;
IN: http.machine.util

: unquote-header ( value -- unquoted )
    unquote ; inline

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

TUPLE: byte-range start end ;

: >byte-range< ( byte-range -- start end )
    [ start>> ] [ end>> ] bi ; inline

: >byte-range ( ast -- byte-range )
    [ byte-range new ] dip
    first2 [ >>start ] [ >>end ] bi* ;

: 'suffix-byte-range-spec' ( -- parser )
    "-" token hide
    [ digit? ] satisfy repeat1 
    [ string>number neg [ byte-range new ] dip >>start ] action 2seq ;

: 'byte-range-spec' ( -- parser )
    [
        'space' ,
        'byte-pos' ,
        'space' ,
        "-" token hide ,
        'byte-pos' optional ,
        'space' ,
        "," token optional hide ,
        'space' ,
    ] seq* [ >byte-range ] action ;

PEG: parse-range-spec ( str -- ranges )
    [
        'space' ,
        'byte-ranges-specifier' ,
        "=" token hide ,
        'byte-range-spec' 'suffix-byte-range-spec' 2choice repeat1 ,
    ] seq* ;

: byte-ranges ( str -- seq )
    [ parse-range-spec flatten ]
    [ 2drop f ] recover ;
