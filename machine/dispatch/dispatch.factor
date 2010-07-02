USING: accessors assocs combinators arrays
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

: insert-rule ( rule path tree -- )
    over empty? [ nip swap >>value drop ] [
        [ unclip ] dip 
        [ ensure-leaf ] [ leaf ] 2bi 
        insert-rule
    ] if ; inline recursive

: leaf? ( key tree -- ? )
    children>> key? ; inline

: traverse-tree ( path tree -- rest entry )
    over empty? [ value>> ] [
        [ [ ] [ unclip-slice ] bi ] dip 2dup leaf?
            [ [ drop ] 3dip leaf traverse-tree ] 
            [ [ 2drop ] [ value>> ] bi* ] if
    ] if ; inline recursive

: find-host-entry ( request dispatcher -- dispatch-tree )
    hosts>> { [ [ host>> ] [ ] bi* at ] [ [ drop "*" ] [ ] bi* at ] } 2|| ;

: create-bindings ( rest bindings assoc -- rest' assoc )
    2over { [ nip { [ empty? not ] [ "*" = not ] } 1&& ] [ drop empty? not ] } 2&&
    [
        [ 2unclip-slice ] dip [ set-at ] keep create-bindings
    ] [ nip ] if ;

: annotate-paths ( request rest rule -- request )
    bindings>> H{ } clone create-bindings
    [ [ >array >>path-tokens ] [ "/" join >>display-path ] bi ] 
    [ >>path-info ] bi* ;

: locate-matching-rule ( request tree -- rest rule )
    [ url>> path>> "/" split rest-slice ] [ ] bi* traverse-tree ;

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
            ensure-tree [ insert-rule ] keep
        ] change-at
    ] bi ;

: lookup-resource ( request dispatcher -- request resource/f )
    [ drop dup ] [ find-host-entry ] 2bi
    locate-matching-rule
    [ [ annotate-paths ] [ resource>> ] bi ]
    [ drop f ] if* ;

