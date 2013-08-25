plantuml -o img/ -tpng token.uml
plantuml -o img/ -tpng auth.uml
plantuml -o img/ -tpng autz.uml

plantuml -o img/ -teps token.uml
plantuml -o img/ -teps auth.uml
plantuml -o img/ -teps autz.uml

doxygen dox
(
cd doc/latex
make
)
