USING: accessors assocs combinators
combinators.short-circuit fry kernel parser sequences splitting
strings words.symbol locals ;
IN: http.machine.dispatch

<PRIVATE

TUPLE: machine-dispatcher hosts ;

TUPLE: dispatch-rule host path-tokens bindings resource ;

PRIVATE>

: <dispatch-rule> ( seq -- dispatch-rule )
    [ dispatch-rule new ] dip
    {  
        [ first >>host ]
        [ second "/" split >>path-tokens ]
        [ third >>bindings ]
    } cleave ;

<PRIVATE

: ?dispatch-rule ( sequence -- dispatch-rule )
    [ { [ sequence? ]
        [ first string? ]
        [ second string? ]
        [ third { [ "*" = ] [ [ symbol? ] all? ] } 1|| ] } 1&&
        [ "matching rule must be a sequence in the form 
            #{ \"HOSTNAME\"|\"*\" \"PATH\" { BINDING ... }|\"*\" }
            Example: R# { \"www.myhost.net\" \"a\" \"*\" }" throw ] unless
    ] [ <dispatch-rule> ] bi ; inline
    
TUPLE: dispatch-tree value children ;

: <dispatch-tree> ( -- dispatch-tree )
    dispatch-tree new H{ } clone >>children ;

: ensure-tree ( f/tree -- tree )
    [ <dispatch-tree> ] unless* ; inline

: ensure-leaf ( key tree -- )
    children>> [ [ <dispatch-tree> ] unless* ] change-at ;

: leaf ( key tree -- tree )
    children>> at ; inline

: insert-rule ( resource path tree -- )
    over empty? [ nip swap >>value drop ] [
        [ unclip ] dip 
        [ ensure-leaf ] [ leaf ] 2bi 
        insert-rule
    ] if ; inline recursive

: leaf? ( key tree -- ? )
    children>> key? ; inline

: traverse-tree ( path tree -- rest entry )
    over empty? [ value>> ] [
        [ unclip ] dip 2dup leaf?
        [ leaf traverse-tree ] [ [ prepend ] [ value>> ] bi* ] if
    ] if ; inline recursive

: find-host-entry ( request dispatcher -- dispatch-tree )
    hosts>> { [ [ host>> ] [ ] bi* at ] [ [ drop "*" ] [ ] bi* at ] } 2|| ;

: annotate-paths ( request rest -- )
    2drop ;

: find-resource ( request tree -- rest resource )
    [ path-tokens>> ] [ ] bi* traverse-tree ;

PRIVATE>

<<

SYNTAX: #{
    \ } parse-until ?dispatch-rule suffix! ;

>>

: <machine-dispatcher> ( -- dispatcher )
    machine-dispatcher new H{ } clone >>hosts ;

: add-rule ( dispatcher dispatch-rule resource-exemplar -- dispatcher )
    >>resource [ host>> over hosts>> ] [
        '[
            [ _ [ ] [ path-tokens>> ] bi ] dip
            ensure-tree
            [ insert-rule ] [ ] bi
        ] change-at
    ] bi ;

: lookup-rule ( request dispatcher -- resource/f )
    [ drop dup ] [ find-host-entry ] 2bi
    find-resource [ annotate-paths ] dip ;

