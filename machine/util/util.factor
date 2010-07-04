USING: accessors ascii combinators.short-circuit continuations
kernel fry make math math.order math.parser peg peg.parsers
prettyprint quoting sequences sorting strings ;
FROM: sequences.deep => flatten ;
IN: http.machine.util

: unquote-header ( value -- unquoted )
    unquote ; inline
